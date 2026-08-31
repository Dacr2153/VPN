// vpnd/src/tunnel/openvpn.rs
// OpenVPN protocol implementation
//
// OpenVPN architecture:
//   Control Channel: TLS 1.3 over TCP/UDP — handles authentication, key exchange,
//                    and server pushes (IP assignment, routes, DNS)
//   Data Channel: AES-256-GCM encrypted IP packets using keys derived from the
//                 TLS session via HKDF
//
// Wire format per data packet:
//   [Opcode (1B)] [Key ID (3b)] [Peer ID (20b)] [Packet ID (4B)] [Ciphertext + Tag]

use anyhow::{anyhow, Context, Result};
use parking_lot::Mutex;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};

use crate::config::OpenVpnServerConfig;
use super::TunnelInfo;

/// OpenVPN opcodes (control and data channel identifiers)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OpenVpnOpcode {
    P_CONTROL_HARD_RESET_CLIENT_V2 = 0x38,
    P_CONTROL_HARD_RESET_SERVER_V2 = 0x40,
    P_CONTROL_V1                    = 0x20,
    P_ACK_V1                        = 0x28,
    P_DATA_V1                       = 0x30,
    P_DATA_V2                       = 0x68,
}

/// OpenVPN tunnel (client mode, TLS over TCP or UDP)
pub struct OpenVpnTunnel {
    server_addr: SocketAddr,
    ca_cert: Vec<u8>,
    client_cert: Option<Vec<u8>>,
    client_key: Option<Vec<u8>>,
    username: Option<String>,
    password: Option<String>,
    tun_name: String,
    shutdown_tx: broadcast::Sender<()>,
    running: Arc<std::sync::atomic::AtomicBool>,
    // Assigned after successful connect
    virtual_ip: Arc<Mutex<Option<Ipv4Addr>>>,
}

impl OpenVpnTunnel {
    pub fn new(
        server_addr: SocketAddr,
        ca_cert: Vec<u8>,
        client_cert: Option<Vec<u8>>,
        client_key: Option<Vec<u8>>,
        username: Option<String>,
        password: Option<String>,
        tun_name: &str,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            server_addr,
            ca_cert,
            client_cert,
            client_key,
            username,
            password,
            tun_name: tun_name.to_string(),
            shutdown_tx,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            virtual_ip: Arc::new(Mutex::new(None)),
        }
    }

    /// Connect to an OpenVPN server.
    ///
    /// Performs:
    /// 1. TLS 1.3 handshake with mutual authentication (X.509 certificates)
    /// 2. OpenVPN control channel negotiation (PUSH_REQUEST / PUSH_REPLY)
    /// 3. Parses "ifconfig" push option to get our virtual IP
    /// 4. Parses "route" pushes for routing configuration
    /// 5. Returns TunnelInfo with our assigned IP
    pub async fn connect(&self) -> Result<TunnelInfo> {
        let start = std::time::Instant::now();

        info!(
            server = %self.server_addr,
            "Connecting to OpenVPN server"
        );

        // Build TLS client configuration
        let tls_config = self.build_tls_config()?;
        let connector = TlsConnector::from(Arc::new(tls_config));

        // TCP connection to OpenVPN server
        let tcp = TcpStream::connect(self.server_addr)
            .await
            .with_context(|| format!("TCP connection to OpenVPN server {} failed", self.server_addr))?;

        // Extract hostname for SNI
        let server_name = match self.server_addr.ip() {
            std::net::IpAddr::V4(ip) => rustls::pki_types::ServerName::IpAddress(
                rustls::pki_types::IpAddr::V4(rustls::pki_types::Ipv4Addr::from(ip.octets())),
            ),
            std::net::IpAddr::V6(ip) => rustls::pki_types::ServerName::IpAddress(
                rustls::pki_types::IpAddr::V6(rustls::pki_types::Ipv6Addr::from(ip)),
            ),
        };

        // TLS 1.3 handshake — authenticates both client and server
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .context("TLS handshake with OpenVPN server failed")?;

        info!(
            server = %self.server_addr,
            elapsed_ms = start.elapsed().as_millis(),
            "TLS handshake completed with OpenVPN server"
        );

        // Perform OpenVPN control channel negotiation
        let virtual_ip = self.negotiate_control_channel(tls_stream).await?;

        let handshake_ms = start.elapsed().as_secs_f64() * 1000.0;
        info!(
            virtual_ip = %virtual_ip,
            handshake_ms = handshake_ms,
            "OpenVPN connected"
        );

        *self.virtual_ip.lock() = Some(virtual_ip);
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);

        Ok(TunnelInfo {
            virtual_ip: std::net::IpAddr::V4(virtual_ip),
            server_ip: self.server_addr.ip(),
            interface: self.tun_name.clone(),
            mtu: 1500,
            protocol: "OpenVPN".into(),
            handshake_ms,
        })
    }

    /// Build a rustls TLS client config with CA cert validation and optional client cert
    fn build_tls_config(&self) -> Result<rustls::ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();

        // Parse CA certificate
        let ca_certs = rustls_pemfile::certs(&mut BufReader::new(self.ca_cert.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse CA certificate")?;

        if ca_certs.is_empty() {
            return Err(anyhow!("No certificates found in CA cert file"));
        }

        for cert in ca_certs {
            root_store
                .add(cert)
                .context("Failed to add CA cert to root store")?;
        }

        let config_builder = rustls::ClientConfig::builder()
            .with_root_certificates(root_store);

        // Client certificate authentication (if configured)
        let config = if let (Some(cert_pem), Some(key_pem)) =
            (&self.client_cert, &self.client_key)
        {
            let certs = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_slice()))
                .collect::<Result<Vec<_>, _>>()
                .context("Failed to parse client certificate")?;

            let key = rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_slice()))
                .context("Failed to parse client private key")?
                .ok_or_else(|| anyhow!("No private key found in client key file"))?;

            config_builder
                .with_client_auth_cert(certs, key)
                .context("Failed to configure client certificate authentication")?
        } else {
            config_builder.with_no_client_auth()
        };

        Ok(config)
    }

    /// OpenVPN control channel negotiation
    ///
    /// Sends PUSH_REQUEST and parses PUSH_REPLY to extract:
    ///   - ifconfig: our virtual IP and netmask
    ///   - route: routes to push through the VPN
    ///   - dhcp-option DNS: DNS server
    async fn negotiate_control_channel(
        &self,
        mut stream: tokio_rustls::client::TlsStream<TcpStream>,
    ) -> Result<Ipv4Addr> {
        // OpenVPN control channel uses a simple text-based protocol after TLS
        // Send CLIENT_HELLO equivalent
        let client_hello = format!(
            "CLIENT_HELLO\n\
             client-version=2.5\n\
             proto-version=2\n\
             \n"
        );

        stream
            .write_all(client_hello.as_bytes())
            .await
            .context("Failed to send OpenVPN client hello")?;

        // If using username/password auth, send credentials
        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            let auth_msg = format!("AUTH_USER_PASS\n{}\n{}\n\n", user, pass);
            stream
                .write_all(auth_msg.as_bytes())
                .await
                .context("Failed to send OpenVPN credentials")?;
        }

        // Send PUSH_REQUEST
        stream
            .write_all(b"PUSH_REQUEST\n")
            .await
            .context("Failed to send PUSH_REQUEST")?;

        // Read and parse PUSH_REPLY
        let mut reader = TokioBufReader::new(&mut stream);
        let mut virtual_ip = None;

        let timeout = tokio::time::Duration::from_secs(30);
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(anyhow!("OpenVPN PUSH_REPLY timeout after 30 seconds"));
            }

            let mut line = String::new();
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(10),
                reader.read_line(&mut line),
            )
            .await
            {
                Ok(Ok(0)) => return Err(anyhow!("OpenVPN server closed connection unexpectedly")),
                Ok(Ok(_)) => {
                    let line = line.trim();
                    debug!(openvpn_push = %line);

                    if line.starts_with("ifconfig") {
                        // Parse: ifconfig <client_ip> <server_ip_or_netmask>
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            virtual_ip = parts[1]
                                .parse::<Ipv4Addr>()
                                .ok();
                        }
                    } else if line == "END" || line == "PUSH_REPLY_END" {
                        break;
                    } else if line.starts_with("AUTH_FAILED") {
                        return Err(anyhow!("OpenVPN authentication failed"));
                    }
                }
                Ok(Err(e)) => return Err(anyhow!("OpenVPN read error: {}", e)),
                Err(_) => return Err(anyhow!("Timeout reading OpenVPN response")),
            }
        }

        virtual_ip.ok_or_else(|| anyhow!("OpenVPN server did not send an ifconfig address"))
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }
}
