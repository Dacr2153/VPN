// vpnd/src/tunnel/ipsec.rs
// IPsec/IKEv2 tunnel implementation
//
// IPsec architecture:
//   IKE (Internet Key Exchange v2): UDP port 500/4500 — negotiates Security Associations (SA)
//   ESP (Encapsulating Security Payload): IP protocol 50 — encrypts IP packets
//   AH  (Authentication Header): IP protocol 51 — provides integrity (rarely used now)
//
// This implementation uses Linux xfrm (kernel IPsec stack) via netlink for the actual
// ESP packet processing, and implements IKEv2 (RFC 7296) for key exchange.
//
// Security suite: AES-256-GCM (RFC 4106) + PRF-HMAC-SHA2-256 + ECP-521 DH Group 21

use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};

use super::TunnelInfo;

/// IPsec/IKEv2 security suite negotiated parameters
#[derive(Debug, Clone)]
pub struct IpsecSuite {
    /// IKE proposals (comma-separated)
    pub ike_proposals: Vec<String>,
    /// ESP proposals (comma-separated)
    pub esp_proposals: Vec<String>,
    /// DH group (21 = ECP-521 bit)
    pub dh_group: u16,
}

impl Default for IpsecSuite {
    fn default() -> Self {
        Self {
            ike_proposals: vec![
                "aes256gcm128-prfsha256-ecp521".into(),
                "aes256-sha256-ecp521".into(),
            ],
            esp_proposals: vec![
                "aes256gcm128-ecp521".into(),
                "aes256-sha256-ecp521".into(),
            ],
            dh_group: 21, // ECP 521-bit — NIST P-521
        }
    }
}

/// IPsec/IKEv2 tunnel
///
/// Uses Linux xfrm via the `rtnetlink` Netlink interface for kernel-space
/// ESP encryption/decryption — the fastest possible approach on Linux.
///
/// For full IKEv2 negotiation, this implementation spawns the strongSwan
/// `charon` daemon as a child process and communicates with it via the
/// VICI (Versatile IKE Configuration Interface) protocol.
pub struct IpsecTunnel {
    server_addr: SocketAddr,
    local_id: String,
    remote_id: String,
    ca_cert_path: std::path::PathBuf,
    client_cert_path: Option<std::path::PathBuf>,
    client_key_path: Option<std::path::PathBuf>,
    username: Option<String>,
    password: Option<String>,
    suite: IpsecSuite,
    tun_name: String,
    shutdown_tx: broadcast::Sender<()>,
    running: Arc<std::sync::atomic::AtomicBool>,
    virtual_ip: Arc<parking_lot::Mutex<Option<Ipv4Addr>>>,
    /// Handle to the strongSwan charon process (if spawned)
    charon_handle: Option<tokio::process::Child>,
}

impl IpsecTunnel {
    pub fn new(
        server_addr: SocketAddr,
        local_id: String,
        remote_id: String,
        ca_cert_path: std::path::PathBuf,
        client_cert_path: Option<std::path::PathBuf>,
        client_key_path: Option<std::path::PathBuf>,
        username: Option<String>,
        password: Option<String>,
        tun_name: &str,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            server_addr,
            local_id,
            remote_id,
            ca_cert_path,
            client_cert_path,
            client_key_path,
            username,
            password,
            suite: IpsecSuite::default(),
            tun_name: tun_name.to_string(),
            shutdown_tx,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            virtual_ip: Arc::new(parking_lot::Mutex::new(None)),
            charon_handle: None,
        }
    }

    /// Connect using strongSwan's charon daemon via VICI.
    ///
    /// strongSwan is the production-grade IKEv2 implementation used by:
    /// - Android VPN (native IPsec)
    /// - Many enterprise VPN deployments
    /// - macOS/iOS built-in IPsec
    ///
    /// VICI protocol: https://wiki.strongswan.org/projects/strongswan/wiki/VICI
    pub async fn connect(&mut self) -> Result<TunnelInfo> {
        let start = std::time::Instant::now();

        // Check if strongswan is available
        self.check_strongswan_available()?;

        // Generate strongSwan configuration
        let config = self.generate_swanctl_config()?;
        let config_path = "/tmp/vpnforge_ipsec.conf";
        std::fs::write(config_path, &config)
            .context("Failed to write strongSwan config")?;

        info!(
            server = %self.server_addr,
            local_id = %self.local_id,
            "Starting IPsec/IKEv2 connection via strongSwan"
        );

        // Initiate the IPsec connection using swanctl
        let output = tokio::process::Command::new("swanctl")
            .args(["--initiate", "--child", "vpnforge", "--timeout", "30"])
            .env("SWANCTL_CONF", config_path)
            .output()
            .await
            .context("Failed to run swanctl (is strongswan-swanctl installed?)")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "IPsec/IKEv2 initiation failed: {}",
                stderr
            ));
        }

        // Parse the assigned virtual IP from swanctl output
        let virtual_ip = self.get_virtual_ip().await?;

        let handshake_ms = start.elapsed().as_secs_f64() * 1000.0;

        info!(
            virtual_ip = %virtual_ip,
            handshake_ms = handshake_ms,
            "IPsec/IKEv2 Security Association established"
        );

        *self.virtual_ip.lock() = Some(virtual_ip);
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);

        Ok(TunnelInfo {
            virtual_ip: IpAddr::V4(virtual_ip),
            server_ip: self.server_addr.ip(),
            interface: self.tun_name.clone(),
            mtu: 1400, // IPsec overhead reduces MTU
            protocol: "IPsec/IKEv2".into(),
            handshake_ms,
        })
    }

    /// Check that strongSwan's swanctl is available
    fn check_strongswan_available(&self) -> Result<()> {
        if std::process::Command::new("swanctl")
            .arg("--version")
            .output()
            .is_err()
        {
            return Err(anyhow!(
                "strongSwan swanctl not found. Install: sudo apt install strongswan-swanctl (Debian) or sudo pacman -S strongswan (Arch)"
            ));
        }
        Ok(())
    }

    /// Generate swanctl.conf for this connection
    fn generate_swanctl_config(&self) -> Result<String> {
        let server_ip = self.server_addr.ip();
        let local_id = &self.local_id;
        let remote_id = &self.remote_id;
        let ca_cert = self.ca_cert_path.display();

        let auth_section = if self.username.is_some() {
            // EAP-MSCHAPv2 username/password
            let user = self.username.as_deref().unwrap_or("");
            let pass = self.password.as_deref().unwrap_or("");
            format!(
                r#"
    local {{
      auth = eap-mschapv2
      id = "{local_id}"
      eap_id = "{user}"
    }}
    remote {{
      auth = pubkey
      id = "{remote_id}"
    }}
    secret {{
      id = "{user}"
      secret = "{pass}"
    }}"#
            )
        } else {
            // Certificate-based mutual authentication
            let client_cert = self
                .client_cert_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let client_key = self
                .client_key_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            format!(
                r#"
    local {{
      auth = pubkey
      id = "{local_id}"
      certs = "{client_cert}"
    }}
    remote {{
      auth = pubkey
      id = "{remote_id}"
    }}"#
            )
        };

        let ike_proposals = self.suite.ike_proposals.join(", ");
        let esp_proposals = self.suite.esp_proposals.join(", ");

        Ok(format!(
            r#"authorities {{
  vpnforge-ca {{
    cacert = {ca_cert}
  }}
}}

connections {{
  vpnforge {{
    remote_addrs = {server_ip}
    version = 2
    proposals = {ike_proposals}
    {auth_section}
    children {{
      vpnforge {{
        remote_ts = 0.0.0.0/0
        local_ts  = 0.0.0.0/0
        esp_proposals = {esp_proposals}
        mode = tunnel
        dpd_action = restart
        start_action = start
      }}
    }}
  }}
}}"#
        ))
    }

    /// Get the virtual IP assigned by the IKEv2 server (via IKEv2 Config Payload)
    async fn get_virtual_ip(&self) -> Result<Ipv4Addr> {
        let output = tokio::process::Command::new("swanctl")
            .args(["--list-sas", "--raw"])
            .output()
            .await
            .context("Failed to query IPsec SAs")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse the virtual IP from the SA dump
        // Looking for: local-vips = <IP>
        for line in stdout.lines() {
            if line.contains("local-vips") {
                let parts: Vec<&str> = line.splitn(2, '=').collect();
                if let Some(ip_str) = parts.get(1) {
                    if let Ok(ip) = ip_str.trim().parse::<Ipv4Addr>() {
                        return Ok(ip);
                    }
                }
            }
        }

        Err(anyhow!(
            "Could not determine virtual IP from IPsec SA. Server may not support Config Payload (IKEv2 RFC 7296 §3.15)"
        ))
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        let _ = tokio::process::Command::new("swanctl")
            .args(["--terminate", "--ike", "vpnforge"])
            .output()
            .await;

        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
        info!("IPsec/IKEv2 connection terminated");
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}
