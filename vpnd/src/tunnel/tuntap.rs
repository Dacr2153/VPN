// vpnd/src/tunnel/tuntap.rs
// Creates and manages a real TUN interface in the Linux kernel
// The interface is visible via `ip link show` and `ip addr show`

use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use tun::AsyncDevice;
use tracing::{debug, info};

/// A real TUN (layer 3) device managed by the kernel
pub struct TunDevice {
    device: AsyncDevice,
    name: String,
    address: Ipv4Addr,
    mtu: u16,
}

impl TunDevice {
    /// Create a new TUN interface with the given parameters.
    ///
    /// This calls into the Linux kernel via ioctl(TUNSETIFF) to create
    /// a real /dev/net/tun device. The interface will be visible with:
    ///   ip link show <name>
    ///   ip addr show <name>
    ///
    /// Requires CAP_NET_ADMIN capability.
    pub fn create(name: &str, address: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> Result<Self> {
        let mut config = tun::Configuration::default();
        config
            .name(name)
            .address(address)
            .netmask(netmask)
            .mtu(mtu as i32)
            .up();

        // tun::create_as_async performs the ioctl TUNSETIFF syscall
        let device = tun::create_as_async(&config)
            .with_context(|| format!("Failed to create TUN interface '{}'. Ensure CAP_NET_ADMIN capability is set (sudo setcap cap_net_admin+ep target/debug/vpnd)", name))?;

        info!(
            interface = name,
            address = %address,
            netmask = %netmask,
            mtu = mtu,
            "TUN interface created"
        );

        Ok(Self {
            device,
            name: name.to_string(),
            address,
            mtu,
        })
    }

    /// Read a packet from the TUN interface (from user-space traffic)
    ///
    /// Returns the number of bytes read. The buffer will contain a raw IP packet.
    pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        use tokio::io::AsyncReadExt;
        let n = self.device.read(buf).await
            .with_context(|| format!("Failed to read from TUN interface '{}'", self.name))?;
        debug!(interface = %self.name, bytes = n, "Packet read from TUN");
        Ok(n)
    }

    /// Write a packet to the TUN interface (inject traffic into the kernel)
    ///
    /// The kernel routes this IP packet to the appropriate user-space process.
    pub async fn write_packet(&mut self, buf: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        self.device.write_all(buf).await
            .with_context(|| format!("Failed to write to TUN interface '{}'", self.name))?;
        debug!(interface = %self.name, bytes = buf.len(), "Packet written to TUN");
        Ok(())
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }
}

/// Returns the standard /24 netmask
pub fn netmask_from_prefix(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask = !((1u32 << (32 - prefix)) - 1);
    Ipv4Addr::from(mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netmask_calculation() {
        assert_eq!(netmask_from_prefix(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(netmask_from_prefix(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(netmask_from_prefix(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(netmask_from_prefix(30), Ipv4Addr::new(255, 255, 255, 252));
        assert_eq!(netmask_from_prefix(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(netmask_from_prefix(32), Ipv4Addr::new(255, 255, 255, 255));
    }
}
