// vpnd/src/routing/split_tunnel.rs
// Split tunneling: route only specific subnets through the VPN,
// let the rest go through the physical interface directly.

use anyhow::Result;
use ipnetwork::IpNetwork;
use tracing::info;

use super::netlink::RouteManager;

/// Split tunnel policy
#[derive(Debug, Clone, Default)]
pub struct SplitTunnelPolicy {
    /// These subnets are routed through the VPN tunnel
    pub vpn_routes: Vec<IpNetwork>,
    /// These subnets explicitly bypass the VPN (use physical interface)
    pub exclude_routes: Vec<IpNetwork>,
}

impl SplitTunnelPolicy {
    pub fn new(vpn_routes: Vec<IpNetwork>, exclude_routes: Vec<IpNetwork>) -> Self {
        Self { vpn_routes, exclude_routes }
    }

    /// Apply: add routes for vpn_routes via tun, let exclude_routes use default
    pub async fn apply(
        &self,
        route_manager: &mut RouteManager,
        tun_if_index: u32,
    ) -> Result<()> {
        info!(
            vpn_routes = self.vpn_routes.len(),
            exclude_routes = self.exclude_routes.len(),
            "Applying split tunnel policy"
        );

        for network in &self.vpn_routes {
            route_manager
                .add_split_tunnel_route(*network, tun_if_index)
                .await?;
            info!(network = %network, "Split tunnel: route via VPN");
        }

        Ok(())
    }

    /// Parse routes from string slices (CIDR notation)
    pub fn from_strings(
        vpn_routes: &[String],
        exclude_routes: &[String],
    ) -> Result<Self> {
        let vpn: Result<Vec<IpNetwork>> = vpn_routes
            .iter()
            .map(|s| {
                s.parse::<IpNetwork>()
                    .map_err(|e| anyhow::anyhow!("Invalid CIDR '{}': {}", s, e))
            })
            .collect();

        let exclude: Result<Vec<IpNetwork>> = exclude_routes
            .iter()
            .map(|s| {
                s.parse::<IpNetwork>()
                    .map_err(|e| anyhow::anyhow!("Invalid CIDR '{}': {}", s, e))
            })
            .collect();

        Ok(Self::new(vpn?, exclude?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_from_strings() {
        let vpn_routes = vec!["10.0.0.0/8".into(), "192.168.1.0/24".into()];
        let exclude = vec!["8.8.8.8/32".into()];

        let policy = SplitTunnelPolicy::from_strings(&vpn_routes, &exclude).unwrap();
        assert_eq!(policy.vpn_routes.len(), 2);
        assert_eq!(policy.exclude_routes.len(), 1);
    }

    #[test]
    fn test_invalid_cidr_rejected() {
        let result = SplitTunnelPolicy::from_strings(&["not-a-cidr".into()], &[]);
        assert!(result.is_err());
    }
}
