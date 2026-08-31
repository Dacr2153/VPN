// vpnd/src/tunnel/mod.rs

pub mod tuntap;
pub mod wireguard;
pub mod openvpn;
pub mod ipsec;

use anyhow::Result;
use std::net::IpAddr;

pub use tuntap::TunDevice;
pub use wireguard::WireGuardTunnel;
pub use openvpn::OpenVpnTunnel;
pub use ipsec::IpsecTunnel;

/// Unified tunnel trait for all VPN protocol engines
#[async_trait::async_trait]
pub trait Tunnel: Send + Sync {
    /// Start the tunnel (connects/binds and begins processing packets)
    async fn start(&mut self) -> Result<TunnelInfo>;

    /// Stop the tunnel gracefully
    async fn stop(&mut self) -> Result<()>;

    /// Returns true if the tunnel is currently active
    fn is_running(&self) -> bool;

    /// Protocol name
    fn protocol_name(&self) -> &'static str;
}

/// Information returned after a successful tunnel establishment
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    /// Virtual IP assigned to this client
    pub virtual_ip: IpAddr,
    /// Server IP we connected to
    pub server_ip: IpAddr,
    /// Interface name (e.g. "tun0")
    pub interface: String,
    /// MTU of the tunnel interface
    pub mtu: u16,
    /// Protocol used
    pub protocol: String,
    /// Handshake time in milliseconds
    pub handshake_ms: f64,
}
