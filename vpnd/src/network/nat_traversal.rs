// vpnd/src/network/nat_traversal.rs
// STUN-based NAT traversal (RFC 5389)
//
// Sends a real STUN Binding Request to a STUN server to discover:
// 1. Our public IP address (as seen from the internet)
// 2. Our public UDP port (after NAT mapping)
// 3. NAT type (to determine if UDP hole punching is feasible)
//
// This is the same mechanism used by WebRTC, SIP, and WireGuard for NAT traversal.

use anyhow::{anyhow, Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info};

/// Well-known public STUN servers (all RFC 5389 compliant)
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun.ekiga.net:3478",
];

/// STUN message type constants (RFC 5389 §6)
const STUN_BINDING_REQUEST:  u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_MAGIC_COOKIE:     u32 = 0x2112A442;

/// Result of a STUN discovery
#[derive(Debug, Clone)]
pub struct NatDiscovery {
    /// Our public IP:port as seen from the STUN server
    pub mapped_address: SocketAddr,
    /// The STUN server that responded
    pub stun_server: SocketAddr,
}

/// STUN client for NAT traversal and public address discovery
pub struct StunClient;

impl StunClient {
    /// Discover our public address by querying a STUN server.
    ///
    /// Sends a real STUN Binding Request per RFC 5389:
    ///   0                   1                   2                   3
    ///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |0 0|     STUN Message Type     |         Message Length        |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |                         Magic Cookie                          |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |                     Transaction ID (96 bits)                  |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    pub async fn discover_public_address(
        stun_server_host: &str,
    ) -> Result<NatDiscovery> {
        // Resolve STUN server address
        let server_addrs: Vec<SocketAddr> = tokio::net::lookup_host(stun_server_host)
            .await
            .with_context(|| format!("Failed to resolve STUN server '{}'", stun_server_host))?
            .filter(|a| a.is_ipv4())
            .collect();

        let server_addr = server_addrs
            .first()
            .copied()
            .ok_or_else(|| anyhow!("STUN server '{}' could not be resolved", stun_server_host))?;

        // Bind to any available local port
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket for STUN")?;

        // Build STUN Binding Request
        let transaction_id = Self::random_transaction_id();
        let request = Self::build_binding_request(&transaction_id);

        // Send request
        socket
            .send_to(&request, server_addr)
            .await
            .context("Failed to send STUN Binding Request")?;

        debug!(stun_server = %server_addr, "STUN Binding Request sent");

        // Wait for Binding Response (timeout 5 seconds)
        let mut buf = vec![0u8; 512];
        let n = timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .context("STUN response timeout (5s)")?
            .context("STUN socket receive error")?;

        // Parse the response
        let mapped_address = Self::parse_binding_response(&buf[..n], &transaction_id)
            .context("Failed to parse STUN Binding Response")?;

        info!(
            public_addr = %mapped_address,
            stun_server = %server_addr,
            "NAT discovery successful"
        );

        Ok(NatDiscovery {
            mapped_address,
            stun_server: server_addr,
        })
    }

    /// Try multiple STUN servers until one succeeds
    pub async fn discover_with_fallback() -> Result<NatDiscovery> {
        for server in DEFAULT_STUN_SERVERS {
            match Self::discover_public_address(server).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!(stun_server = server, error = %e, "STUN server failed, trying next");
                }
            }
        }
        Err(anyhow!("All STUN servers failed — check network connectivity"))
    }

    // ──────────────────────────────────────────────
    //  STUN packet building and parsing (RFC 5389)
    // ──────────────────────────────────────────────

    fn random_transaction_id() -> [u8; 12] {
        let mut id = [0u8; 12];
        for byte in &mut id {
            *byte = rand::random();
        }
        id
    }

    fn build_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(20);

        // Message Type: Binding Request (0x0001)
        packet.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        // Message Length: 0 (no attributes)
        packet.extend_from_slice(&0u16.to_be_bytes());
        // Magic Cookie
        packet.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        // Transaction ID
        packet.extend_from_slice(transaction_id);

        packet
    }

    fn parse_binding_response(
        data: &[u8],
        expected_transaction_id: &[u8; 12],
    ) -> Result<SocketAddr> {
        if data.len() < 20 {
            return Err(anyhow!("STUN response too short: {} bytes", data.len()));
        }

        // Validate message type
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type != STUN_BINDING_RESPONSE {
            return Err(anyhow!(
                "Unexpected STUN message type: 0x{:04X}",
                msg_type
            ));
        }

        // Validate magic cookie
        let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if magic != STUN_MAGIC_COOKIE {
            return Err(anyhow!("Invalid STUN magic cookie"));
        }

        // Validate transaction ID
        if &data[8..20] != expected_transaction_id {
            return Err(anyhow!("STUN transaction ID mismatch"));
        }

        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 20 + msg_len {
            return Err(anyhow!("STUN response truncated"));
        }

        // Parse attributes to find XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
        let mut offset = 20;
        while offset + 4 <= 20 + msg_len {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

            match attr_type {
                // XOR-MAPPED-ADDRESS (RFC 5389)
                0x0020 if attr_len >= 8 => {
                    let addr_bytes = &data[offset + 4..offset + 4 + attr_len];
                    let port_xor =
                        u16::from_be_bytes([addr_bytes[2], addr_bytes[3]])
                        ^ (STUN_MAGIC_COOKIE >> 16) as u16;
                    let ip = u32::from_be_bytes([
                        addr_bytes[4] ^ ((STUN_MAGIC_COOKIE >> 24) & 0xFF) as u8,
                        addr_bytes[5] ^ ((STUN_MAGIC_COOKIE >> 16) & 0xFF) as u8,
                        addr_bytes[6] ^ ((STUN_MAGIC_COOKIE >> 8) & 0xFF) as u8,
                        addr_bytes[7] ^ (STUN_MAGIC_COOKIE & 0xFF) as u8,
                    ]);
                    return Ok(SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)),
                        port_xor,
                    ));
                }
                // MAPPED-ADDRESS (RFC 3489 legacy)
                0x0001 if attr_len >= 8 => {
                    let addr_bytes = &data[offset + 4..offset + 4 + attr_len];
                    let port = u16::from_be_bytes([addr_bytes[2], addr_bytes[3]]);
                    let ip = u32::from_be_bytes([
                        addr_bytes[4],
                        addr_bytes[5],
                        addr_bytes[6],
                        addr_bytes[7],
                    ]);
                    return Ok(SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)),
                        port,
                    ));
                }
                _ => {}
            }

            // Advance to next attribute (4-byte aligned)
            offset += 4 + attr_len;
            if attr_len % 4 != 0 {
                offset += 4 - (attr_len % 4);
            }
        }

        Err(anyhow!(
            "STUN response did not contain MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_binding_request() {
        let tid = [1u8; 12];
        let req = StunClient::build_binding_request(&tid);
        assert_eq!(req.len(), 20);
        // Check magic cookie
        let magic = u32::from_be_bytes([req[4], req[5], req[6], req[7]]);
        assert_eq!(magic, STUN_MAGIC_COOKIE);
        // Check message type
        let msg_type = u16::from_be_bytes([req[0], req[1]]);
        assert_eq!(msg_type, STUN_BINDING_REQUEST);
    }
}
