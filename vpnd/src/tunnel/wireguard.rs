// vpnd/src/tunnel/wireguard.rs
// Real WireGuard protocol implementation using Cloudflare's boringtun
//
// WireGuard uses the Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s handshake pattern:
//   - Curve25519 for key exchange
//   - ChaCha20-Poly1305 for encryption
//   - BLAKE2s for hashing/PRF
//   - HKDF for key derivation
//
// boringtun is audited and deployed in production by Cloudflare (WARP)

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use boringtun::noise::{Tunn, TunnResult};
use parking_lot::Mutex;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::config::WireGuardServerConfig;
use crate::crypto::key_exchange::{decode_wg_public_key, WireGuardKeyPair};
use crate::metrics::collector::MetricsSnapshot;
use super::TunnelInfo;

/// Size of the UDP receive buffer — must hold largest WireGuard packet
const WG_BUF_SIZE: usize = 65535 + 32; // IP max + WG overhead

/// WireGuard tunnel backed by boringtun (Cloudflare userspace implementation)
pub struct WireGuardTunnel {
    /// The boringtun state machine — handles handshake and packet processing
    tunn: Arc<Mutex<Tunn>>,
    /// UDP socket for sending/receiving encrypted WireGuard packets
    udp: Arc<UdpSocket>,
    /// Peer endpoint (server address)
    peer_endpoint: SocketAddr,
    /// Assigned virtual IP (received from server configuration)
    virtual_ip: Ipv4Addr,
    /// TUN interface name
    tun_name: String,
    /// Shutdown signal
    shutdown_tx: broadcast::Sender<()>,
    /// Running flag
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl WireGuardTunnel {
    /// Create a new WireGuard tunnel (client mode)
    ///
    /// Parameters:
    ///   - local_keys: Our Curve25519 keypair
    ///   - peer_public_key: Server's public key (base64)
    ///   - preshared_key: Optional PSK for extra security
    ///   - peer_endpoint: Server UDP address  
    ///   - virtual_ip: Our assigned virtual IP in the VPN network
    ///   - tun_name: Name for the TUN interface
    pub async fn new(
        local_keys: &WireGuardKeyPair,
        peer_public_key_b64: &str,
        preshared_key_b64: Option<&str>,
        peer_endpoint: SocketAddr,
        virtual_ip: Ipv4Addr,
        keepalive: Option<u16>,
        tun_name: &str,
    ) -> Result<Self> {
        // Decode keys
        let private_key = *local_keys.private_key();
        let peer_pub = decode_wg_public_key(peer_public_key_b64)?;

        // Optional pre-shared key for additional post-quantum resistance
        let psk = if let Some(psk_b64) = preshared_key_b64 {
            let bytes = BASE64
                .decode(psk_b64.trim())
                .context("Invalid PSK base64")?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("PSK must be 32 bytes"))?;
            Some(arr)
        } else {
            None
        };

        // Create the boringtun state machine
        // This implements the full WireGuard Noise protocol
        let tunn = Tunn::new(
            private_key.into(),
            peer_pub.into(),
            psk,
            keepalive.map(|k| k as u16),
            0, // index
            None,
        )
        .map_err(|e| anyhow!("Failed to create WireGuard tunnel: {:?}", e))?;

        // Bind to a random local UDP port
        let udp = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket for WireGuard")?;

        let local_addr = udp.local_addr()?;
        info!(
            local_port = local_addr.port(),
            peer = %peer_endpoint,
            virtual_ip = %virtual_ip,
            "WireGuard tunnel initialized"
        );

        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            tunn: Arc::new(Mutex::new(tunn)),
            udp: Arc::new(udp),
            peer_endpoint,
            virtual_ip,
            tun_name: tun_name.to_string(),
            shutdown_tx,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Run the WireGuard packet processing loop.
    ///
    /// This function:
    /// 1. Triggers the WireGuard handshake (Initiator → Responder)
    /// 2. Processes incoming encrypted UDP packets → decrypts → injects into TUN
    /// 3. Processes outgoing TUN packets → encrypts → sends via UDP
    /// 4. Handles keepalive timers and key rotation (every 180s per WG spec)
    pub async fn run(
        &self,
        mut tun_device: super::tuntap::TunDevice,
        metrics_tx: tokio::sync::mpsc::Sender<MetricsSnapshot>,
    ) -> Result<()> {
        use std::sync::atomic::Ordering;

        self.running.store(true, Ordering::SeqCst);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        // Buffers for packet processing
        let mut udp_buf = vec![0u8; WG_BUF_SIZE];
        let mut tun_buf = vec![0u8; WG_BUF_SIZE];
        let mut send_buf = vec![0u8; WG_BUF_SIZE];

        // Metrics counters
        let mut rx_bytes: u64 = 0;
        let mut tx_bytes: u64 = 0;
        let mut metrics_tick = tokio::time::interval(Duration::from_secs(1));
        let mut timer_tick = tokio::time::interval(Duration::from_millis(250));

        // Initiate the WireGuard handshake immediately
        self.send_handshake_initiation(&mut send_buf).await?;

        let start = Instant::now();
        info!("WireGuard packet loop started, waiting for handshake response...");

        loop {
            tokio::select! {
                // ── Incoming encrypted UDP packet from peer ──────────────
                result = self.udp.recv_from(&mut udp_buf) => {
                    match result {
                        Ok((n, src)) => {
                            if src == self.peer_endpoint {
                                if let Err(e) = self.handle_incoming_udp(
                                    &udp_buf[..n],
                                    &mut send_buf,
                                    &mut tun_device,
                                ).await {
                                    warn!("Error processing incoming WireGuard packet: {}", e);
                                } else {
                                    rx_bytes += n as u64;
                                }
                            }
                        }
                        Err(e) => {
                            error!("UDP receive error: {}", e);
                        }
                    }
                }

                // ── Outgoing plaintext packet from TUN interface ──────────
                result = tun_device.read_packet(&mut tun_buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            if let Err(e) = self.handle_outgoing_tun(
                                &tun_buf[..n],
                                &mut send_buf,
                            ).await {
                                debug!("Error encapsulating TUN packet: {}", e);
                            } else {
                                tx_bytes += n as u64;
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            error!("TUN read error: {}", e);
                        }
                    }
                }

                // ── Periodic WireGuard timer (keepalive, key rotation) ───
                _ = timer_tick.tick() => {
                    if let Err(e) = self.handle_timer(&mut send_buf).await {
                        debug!("Timer handling: {}", e);
                    }
                }

                // ── Metrics emission ─────────────────────────────────────
                _ = metrics_tick.tick() => {
                    let rtt = self.measure_latency().await.unwrap_or(0.0);
                    let snapshot = MetricsSnapshot {
                        bytes_received: rx_bytes,
                        bytes_sent: tx_bytes,
                        packets_received: 0,
                        packets_sent: 0,
                        packets_lost: 0,
                        rtt_ms: rtt,
                        jitter_ms: 0.0,
                        loss_percent: 0.0,
                        rx_rate_bps: rx_bytes as f64,
                        tx_rate_bps: tx_bytes as f64,
                        protocol: "wireguard".into(),
                        interface: self.tun_name.clone(),
                        uptime_secs: start.elapsed().as_secs(),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    };
                    let _ = metrics_tx.try_send(snapshot);
                    rx_bytes = 0;
                    tx_bytes = 0;
                }

                // ── Shutdown signal ───────────────────────────────────────
                _ = shutdown_rx.recv() => {
                    info!("WireGuard tunnel shutting down");
                    break;
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Send the WireGuard handshake initiation packet to the peer
    async fn send_handshake_initiation(&self, buf: &mut Vec<u8>) -> Result<()> {
        buf.resize(WG_BUF_SIZE, 0);
        let result = self.tunn.lock().format_handshake_initiation(buf, false);

        match result {
            TunnResult::WriteToNetwork(packet) => {
                self.udp
                    .send_to(packet, self.peer_endpoint)
                    .await
                    .context("Failed to send WireGuard handshake initiation")?;
                info!(
                    peer = %self.peer_endpoint,
                    "WireGuard handshake initiation sent"
                );
            }
            other => {
                return Err(anyhow!("Unexpected result from handshake init: {:?}", other));
            }
        }
        Ok(())
    }

    /// Process an incoming UDP packet from the WireGuard peer
    async fn handle_incoming_udp(
        &self,
        data: &[u8],
        send_buf: &mut Vec<u8>,
        tun_device: &mut super::tuntap::TunDevice,
    ) -> Result<()> {
        send_buf.resize(WG_BUF_SIZE, 0);

        // Let boringtun process the encrypted WireGuard packet
        let result = self.tunn.lock().decapsulate(None, data, send_buf);

        match result {
            // Decapsulated IP packet → write to TUN (inject into kernel)
            TunnResult::WriteToTunnelV4(packet, _src) => {
                debug!(bytes = packet.len(), "WireGuard → TUN (IPv4)");
                tun_device.write_packet(packet).await?;
            }
            TunnResult::WriteToTunnelV6(packet, _src) => {
                debug!(bytes = packet.len(), "WireGuard → TUN (IPv6)");
                tun_device.write_packet(packet).await?;
            }
            // Handshake response or keepalive → send back to peer
            TunnResult::WriteToNetwork(packet) => {
                debug!(bytes = packet.len(), "WireGuard handshake/keepalive response");
                self.udp.send_to(packet, self.peer_endpoint).await?;
            }
            TunnResult::Done => {
                // Keepalive or handshake done, nothing to send
            }
            TunnResult::Err(e) => {
                return Err(anyhow!("WireGuard decapsulation error: {:?}", e));
            }
        }

        Ok(())
    }

    /// Encrypt a TUN packet and send it via UDP to the peer
    async fn handle_outgoing_tun(&self, packet: &[u8], send_buf: &mut Vec<u8>) -> Result<()> {
        send_buf.resize(WG_BUF_SIZE, 0);

        let result = self.tunn.lock().encapsulate(packet, send_buf);

        match result {
            TunnResult::WriteToNetwork(encrypted) => {
                debug!(
                    plain_bytes = packet.len(),
                    encrypted_bytes = encrypted.len(),
                    "TUN → WireGuard (encrypted)"
                );
                self.udp
                    .send_to(encrypted, self.peer_endpoint)
                    .await
                    .context("Failed to send encrypted WireGuard packet")?;
            }
            TunnResult::Done => {
                // Handshake in progress — packet queued internally by boringtun
            }
            TunnResult::Err(e) => {
                return Err(anyhow!("WireGuard encapsulation error: {:?}", e));
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle WireGuard timers (keepalive, handshake retry, key rotation)
    ///
    /// WireGuard rotates session keys every 180 seconds automatically.
    /// boringtun::Tunn::update_timers() implements all WireGuard timer logic.
    async fn handle_timer(&self, send_buf: &mut Vec<u8>) -> Result<()> {
        send_buf.resize(WG_BUF_SIZE, 0);

        let result = self.tunn.lock().update_timers(send_buf);
        match result {
            TunnResult::WriteToNetwork(packet) => {
                self.udp.send_to(packet, self.peer_endpoint).await?;
            }
            TunnResult::Done | TunnResult::Err(_) => {}
            _ => {}
        }
        Ok(())
    }

    /// Measure round-trip latency to peer by checking last handshake time
    async fn measure_latency(&self) -> Result<f64> {
        // WireGuard doesn't use ICMP ping; we use the time since last handshake
        // as a proxy for connectivity quality
        // For accurate latency we send a keepalive and measure response time
        // This is a best-effort metric
        Ok(0.0) // TODO: implement actual RTT measurement via keepalive timing
    }

    /// Get the virtual IP assigned to this tunnel
    pub fn virtual_ip(&self) -> Ipv4Addr {
        self.virtual_ip
    }

    /// Get the TUN interface name
    pub fn tun_name(&self) -> &str {
        &self.tun_name
    }

    /// Send shutdown signal
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Build TunnelInfo for reporting to the daemon
    pub fn tunnel_info(&self) -> TunnelInfo {
        TunnelInfo {
            virtual_ip: std::net::IpAddr::V4(self.virtual_ip),
            server_ip: self.peer_endpoint.ip(),
            interface: self.tun_name.clone(),
            mtu: 1420,
            protocol: "WireGuard".into(),
            handshake_ms: 0.0,
        }
    }
}

/// WireGuard server — manages multiple peer sessions
pub struct WireGuardServer {
    config: WireGuardServerConfig,
    local_keys: WireGuardKeyPair,
    udp: Arc<UdpSocket>,
    peers: dashmap::DashMap<[u8; 32], PeerSession>,
}

struct PeerSession {
    tunn: Arc<Mutex<Tunn>>,
    virtual_ip: Ipv4Addr,
    endpoint: Option<SocketAddr>,
}

impl WireGuardServer {
    pub async fn new(config: WireGuardServerConfig) -> Result<Self> {
        let local_keys = WireGuardKeyPair::from_private_key_base64(&config.private_key)?;

        let bind_addr = format!("0.0.0.0:{}", config.port);
        let udp = UdpSocket::bind(&bind_addr)
            .await
            .with_context(|| format!("Failed to bind WireGuard server on {}", bind_addr))?;

        info!(
            port = config.port,
            pubkey = %local_keys.public_key_base64(),
            "WireGuard server listening"
        );

        Ok(Self {
            config,
            local_keys,
            udp: Arc::new(udp),
            peers: dashmap::DashMap::new(),
        })
    }

    /// Get the server's public key (to share with clients)
    pub fn public_key_base64(&self) -> String {
        self.local_keys.public_key_base64()
    }
}
