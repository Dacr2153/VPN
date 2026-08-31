// vpnd/src/kill_switch/firewall.rs
// Kill switch implementation using nftables (preferred) or iptables (fallback)
//
// When active, the kill switch:
// 1. Drops ALL outgoing traffic EXCEPT:
//    - Loopback traffic (lo)
//    - Traffic on the VPN tunnel interface (tun0)
//    - UDP traffic to the VPN server (so the tunnel can be maintained)
// 2. On disconnect: removes rules immediately
//
// nftables ruleset installed:
//   table inet vpnforge_killswitch {
//     chain output {
//       type filter hook output priority -100; policy drop;
//       oif "lo"   accept
//       oif "tun0" accept
//       ip  daddr <vpn_ip> udp dport <vpn_port> accept
//       ip  daddr <vpn_ip> tcp dport <vpn_port> accept
//     }
//     chain input {
//       type filter hook input priority -100; policy drop;
//       iif "lo"   accept
//       iif "tun0" accept
//       ip  saddr <vpn_ip> accept
//       ct state established,related accept
//     }
//   }

use anyhow::{anyhow, Context, Result};
use std::net::IpAddr;
use tokio::process::Command;
use tracing::{info, warn};

const NFTABLES_TABLE: &str = "vpnforge_killswitch";

/// Kill switch manager — blocks all non-VPN traffic at the firewall level
pub struct KillSwitch {
    active: bool,
    backend: FirewallBackend,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum FirewallBackend {
    Nftables,
    Iptables,
}

impl KillSwitch {
    /// Create a new kill switch, detecting available backend
    pub async fn new() -> Result<Self> {
        let backend = detect_firewall_backend().await?;
        info!(backend = ?backend, "Kill switch firewall backend detected");
        Ok(Self {
            active: false,
            backend,
        })
    }

    /// Create an uninitialised kill switch (backend will be detected on first enable)
    pub fn uninitialised() -> Self {
        Self {
            active: false,
            backend: FirewallBackend::Nftables, // will be overridden on enable
        }
    }

    /// Activate the kill switch
    ///
    /// After this call, ALL traffic except VPN server comms and loopback is dropped.
    /// Verified with: `nft list ruleset` or `iptables -L -n -v`
    pub async fn enable(
        &mut self,
        vpn_server_ip: IpAddr,
        vpn_port: u16,
        tun_interface: &str,
        transport: &str, // "udp" or "tcp"
    ) -> Result<()> {
        if self.active {
            return Ok(());
        }

        // Re-detect backend on first enable (handles uninitialised case)
        self.backend = detect_firewall_backend().await?;

        match self.backend {
            FirewallBackend::Nftables => {
                self.enable_nftables(vpn_server_ip, vpn_port, tun_interface, transport)
                    .await?
            }
            FirewallBackend::Iptables => {
                self.enable_iptables(vpn_server_ip, vpn_port, tun_interface, transport)
                    .await?
            }
        }

        self.active = true;
        info!(
            vpn_server = %vpn_server_ip,
            vpn_port = vpn_port,
            tun = tun_interface,
            "Kill switch ENABLED — non-VPN traffic blocked"
        );
        Ok(())
    }

    /// Disable the kill switch and restore normal traffic flow
    pub async fn disable(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }

        match self.backend {
            FirewallBackend::Nftables => self.disable_nftables().await?,
            FirewallBackend::Iptables => self.disable_iptables().await?,
        }

        self.active = false;
        info!("Kill switch DISABLED — normal traffic restored");
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    // ──────────────────────────────────────────────
    //  nftables backend
    // ──────────────────────────────────────────────

    async fn enable_nftables(
        &self,
        vpn_server_ip: IpAddr,
        vpn_port: u16,
        tun_interface: &str,
        transport: &str,
    ) -> Result<()> {
        // First remove any existing table to start clean
        let _ = run_cmd("nft", &["delete", "table", "inet", NFTABLES_TABLE]).await;

        let ruleset = format!(
            r#"table inet {table} {{
    chain output {{
        type filter hook output priority -100; policy drop;
        oif "lo" accept
        oif "{tun}" accept
        ip daddr {vpn_ip} {proto} dport {port} accept
        ip6 daddr ::{vpn_ip} {proto} dport {port} accept
    }}
    chain input {{
        type filter hook input priority -100; policy drop;
        iif "lo" accept
        iif "{tun}" accept
        ip saddr {vpn_ip} accept
        ct state established,related accept
    }}
    chain forward {{
        type filter hook forward priority -100; policy drop;
    }}
}}"#,
            table = NFTABLES_TABLE,
            tun = tun_interface,
            vpn_ip = vpn_server_ip,
            proto = transport,
            port = vpn_port,
        );

        // Write ruleset to a secure temp file in a root-owned directory.
        // Using /run/vpnd/ (created at daemon start with restricted perms) prevents
        // symlink attacks that are possible when writing to world-writable /tmp.
        let tmp = format!("/run/vpnd/ks_{}.nft", std::process::id());
        std::fs::write(&tmp, &ruleset)
            .context("Failed to write nftables ruleset")?;
        // Restrict file so only root can read it
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }

        run_cmd("nft", &["-f", &tmp])
            .await
            .context("Failed to apply nftables kill switch ruleset")?;

        std::fs::remove_file(&tmp).ok();
        Ok(())
    }

    async fn disable_nftables(&self) -> Result<()> {
        run_cmd("nft", &["delete", "table", "inet", NFTABLES_TABLE])
            .await
            .context("Failed to remove nftables kill switch")?;
        Ok(())
    }

    // ──────────────────────────────────────────────
    //  iptables backend (fallback)
    // ──────────────────────────────────────────────

    async fn enable_iptables(
        &self,
        vpn_server_ip: IpAddr,
        vpn_port: u16,
        tun_interface: &str,
        transport: &str,
    ) -> Result<()> {
        let vpn_ip = vpn_server_ip.to_string();
        let port = vpn_port.to_string();

        // Flush existing VPN chain if present
        let _ = run_cmd("iptables", &["-D", "OUTPUT", "-j", "VPNFORGE_KS"]).await;
        let _ = run_cmd("iptables", &["-F", "VPNFORGE_KS"]).await;
        let _ = run_cmd("iptables", &["-X", "VPNFORGE_KS"]).await;

        // Create chain
        run_cmd("iptables", &["-N", "VPNFORGE_KS"]).await?;

        // Allow loopback
        run_cmd("iptables", &["-A", "VPNFORGE_KS", "-o", "lo", "-j", "ACCEPT"]).await?;
        // Allow VPN tunnel
        run_cmd("iptables", &["-A", "VPNFORGE_KS", "-o", tun_interface, "-j", "ACCEPT"]).await?;
        // Allow traffic to VPN server
        run_cmd("iptables", &["-A", "VPNFORGE_KS", "-d", &vpn_ip, "-p", transport, "--dport", &port, "-j", "ACCEPT"]).await?;
        // Allow established connections
        run_cmd("iptables", &["-A", "VPNFORGE_KS", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"]).await?;
        // Drop everything else
        run_cmd("iptables", &["-A", "VPNFORGE_KS", "-j", "DROP"]).await?;
        // Insert at top of OUTPUT chain
        run_cmd("iptables", &["-I", "OUTPUT", "1", "-j", "VPNFORGE_KS"]).await?;

        Ok(())
    }

    async fn disable_iptables(&self) -> Result<()> {
        let _ = run_cmd("iptables", &["-D", "OUTPUT", "-j", "VPNFORGE_KS"]).await;
        let _ = run_cmd("iptables", &["-F", "VPNFORGE_KS"]).await;
        let _ = run_cmd("iptables", &["-X", "VPNFORGE_KS"]).await;
        Ok(())
    }
}

/// Detect which firewall backend is available
async fn detect_firewall_backend() -> Result<FirewallBackend> {
    if is_command_available("nft").await {
        return Ok(FirewallBackend::Nftables);
    }
    if is_command_available("iptables").await {
        return Ok(FirewallBackend::Iptables);
    }
    Err(anyhow!(
        "No firewall backend found. Install nftables (preferred) or iptables."
    ))
}

async fn is_command_available(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .await
        .with_context(|| format!("Failed to execute '{}'", cmd))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "'{}' failed (code {:?}): {}",
            cmd,
            output.status.code(),
            stderr.trim()
        ));
    }

    Ok(())
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        if self.active {
            // Best-effort cleanup — sync version
            warn!("KillSwitch dropped while active — attempting cleanup");
            let backend = self.backend;
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    match backend {
                        FirewallBackend::Nftables => {
                            let _ = run_cmd("nft", &["delete", "table", "inet", NFTABLES_TABLE]).await;
                        }
                        FirewallBackend::Iptables => {
                            let _ = run_cmd("iptables", &["-D", "OUTPUT", "-j", "VPNFORGE_KS"]).await;
                            let _ = run_cmd("iptables", &["-F", "VPNFORGE_KS"]).await;
                            let _ = run_cmd("iptables", &["-X", "VPNFORGE_KS"]).await;
                        }
                    }
                });
            });
        }
    }
}
