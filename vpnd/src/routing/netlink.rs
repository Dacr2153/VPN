// vpnd/src/routing/netlink.rs
// Real routing table manipulation via Linux Netlink sockets
//
// Uses `rtnetlink` crate which wraps the NETLINK_ROUTE socket family.
// All operations are equivalent to `ip route` commands but done via
// programmatic Netlink messages — no subprocess overhead.
//
// Routing strategy for "route all traffic through VPN":
//   1. Add host route: <vpn_server_ip>/32 via <current_default_gateway>
//   2. Add 0.0.0.0/1 via tun0   (covers 0.0.0.0 – 127.255.255.255)
//   3. Add 128.0.0.0/1 via tun0  (covers 128.0.0.0 – 255.255.255.255)
//   These two /1 routes have higher precedence than the default /0 route,
//   forcing ALL traffic through the VPN tunnel.

use anyhow::{anyhow, Context, Result};
use futures::stream::TryStreamExt;
use ipnetwork::IpNetwork;
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use rtnetlink::{Handle, RouteAddRequest};
use std::net::{IpAddr, Ipv4Addr};
use tracing::{debug, info, warn};

/// Manages routing table entries for VPN traffic
pub struct RouteManager {
    handle: Handle,
    /// Routes added by us — tracked for cleanup on disconnect
    added_routes: Vec<(IpNetwork, Option<IpAddr>, u32)>, // (dst, gateway, if_index)
    /// Original default gateway (saved before we override it)
    original_default_gateway: Option<IpAddr>,
    original_default_if_index: Option<u32>,
}

impl RouteManager {
    /// Create a new RouteManager
    pub async fn new() -> Result<Self> {
        let (conn, handle, _) =
            rtnetlink::new_connection().context("Failed to open Netlink connection")?;
        tokio::spawn(conn);

        Ok(Self {
            handle,
            added_routes: Vec::new(),
            original_default_gateway: None,
            original_default_if_index: None,
        })
    }

    /// Set up routing to send all traffic through the VPN tunnel.
    ///
    /// Equivalent to:
    ///   ip route add <server>/32 via <gw> dev <physical_if>
    ///   ip route add 0.0.0.0/1 dev tun0
    ///   ip route add 128.0.0.0/1 dev tun0
    pub async fn route_all_traffic_via_vpn(
        &mut self,
        vpn_server_ip: IpAddr,
        tun_if_index: u32,
    ) -> Result<()> {
        // Save current default route so we can restore it on disconnect
        self.save_default_route().await?;

        let (gw, phys_if_index) = match (self.original_default_gateway, self.original_default_if_index) {
            (Some(gw), Some(idx)) => (gw, idx),
            _ => return Err(anyhow!("No default route found — cannot set up VPN routing")),
        };

        // 1. Route VPN server traffic through physical interface (bypass the VPN)
        self.add_host_route(vpn_server_ip, gw, phys_if_index).await?;

        // 2. Route all other traffic through TUN interface
        // Using two /1 routes instead of modifying default /0 — cleaner and
        // easily reversible without breaking other routing rules
        let lower_half: IpNetwork = "0.0.0.0/1".parse().unwrap();
        let upper_half: IpNetwork = "128.0.0.0/1".parse().unwrap();

        self.add_route_via_interface(lower_half, tun_if_index).await?;
        self.add_route_via_interface(upper_half, tun_if_index).await?;

        info!(
            vpn_server = %vpn_server_ip,
            gateway = %gw,
            tun_if = tun_if_index,
            "All traffic routed through VPN"
        );

        Ok(())
    }

    /// Restore all original routes (called on VPN disconnect)
    pub async fn restore_original_routes(&mut self) -> Result<()> {
        info!("Restoring original routing table");

        // Collect routes to remove, then remove them
        let routes: Vec<_> = self.added_routes.drain(..).rev().collect();
        for (network, gateway, if_index) in routes {
            if let Err(e) = self.delete_route(network, gateway, if_index).await {
                warn!(network = %network, "Failed to remove route: {}", e);
            }
        }

        info!("Routing table restored");
        Ok(())
    }

    /// Add a split-tunnel route: specific subnet goes through VPN
    pub async fn add_split_tunnel_route(
        &mut self,
        network: IpNetwork,
        tun_if_index: u32,
    ) -> Result<()> {
        self.add_route_via_interface(network, tun_if_index).await
    }

    /// Get the interface index by name (e.g. "tun0" → 5)
    pub async fn get_if_index(&self, name: &str) -> Result<u32> {
        let mut links = self.handle.link().get().match_name(name.to_string()).execute();

        if let Some(link) = links.try_next().await? {
            Ok(link.header.index)
        } else {
            Err(anyhow!("Interface '{}' not found", name))
        }
    }

    /// Get the current default IPv4 route (gateway + interface)
    pub async fn get_default_route(&self) -> Result<(IpAddr, u32)> {
        let mut routes = self.handle.route().get(rtnetlink::IpVersion::V4).execute();

        while let Some(route) = routes.try_next().await? {
            // Default route has destination prefix length 0
            if route.header.destination_prefix_length == 0 {
                let mut gateway = None;
                let mut if_index = None;

                for attr in &route.attributes {
                    match attr {
                        RouteAttribute::Gateway(RouteAddress::Inet(ip)) => {
                            gateway = Some(IpAddr::V4(*ip));
                        }
                        RouteAttribute::Oif(idx) => {
                            if_index = Some(*idx);
                        }
                        _ => {}
                    }
                }

                if let (Some(gw), Some(idx)) = (gateway, if_index) {
                    return Ok((gw, idx));
                }
            }
        }

        Err(anyhow!("No default IPv4 route found in routing table"))
    }

    // ──────────────────────────────────────────────
    //  Private helpers
    // ──────────────────────────────────────────────

    async fn save_default_route(&mut self) -> Result<()> {
        match self.get_default_route().await {
            Ok((gw, idx)) => {
                self.original_default_gateway = Some(gw);
                self.original_default_if_index = Some(idx);
                info!(gateway = %gw, if_index = idx, "Saved original default route");
                Ok(())
            }
            Err(e) => {
                warn!("Could not save default route: {}", e);
                Err(e)
            }
        }
    }

    async fn add_host_route(
        &mut self,
        host: IpAddr,
        gateway: IpAddr,
        if_index: u32,
    ) -> Result<()> {
        let network: IpNetwork = match host {
            IpAddr::V4(ip) => IpNetwork::V4(ipnetwork::Ipv4Network::new(ip, 32)?),
            IpAddr::V6(ip) => IpNetwork::V6(ipnetwork::Ipv6Network::new(ip, 128)?),
        };

        self.add_route(network, Some(gateway), if_index).await
    }

    async fn add_route_via_interface(
        &mut self,
        network: IpNetwork,
        if_index: u32,
    ) -> Result<()> {
        self.add_route(network, None, if_index).await
    }

    async fn add_route(
        &mut self,
        network: IpNetwork,
        gateway: Option<IpAddr>,
        if_index: u32,
    ) -> Result<()> {
        let mut req = self.handle.route().add();

        match network {
            IpNetwork::V4(net) => {
                let mut r = req
                    .v4()
                    .destination_prefix(net.network(), net.prefix())
                    .output_interface(if_index);

                if let Some(IpAddr::V4(gw)) = gateway {
                    r = r.gateway(gw);
                }

                r.execute()
                    .await
                    .with_context(|| format!("Failed to add route {} via if {}", network, if_index))?;
            }
            IpNetwork::V6(net) => {
                let mut r = req
                    .v6()
                    .destination_prefix(net.network(), net.prefix())
                    .output_interface(if_index);

                if let Some(IpAddr::V6(gw)) = gateway {
                    r = r.gateway(gw);
                }

                r.execute()
                    .await
                    .with_context(|| format!("Failed to add IPv6 route {}", network))?;
            }
        }

        debug!(network = %network, gateway = ?gateway, if_index = if_index, "Route added");
        self.added_routes.push((network, gateway, if_index));
        Ok(())
    }

    async fn delete_route(
        &self,
        network: IpNetwork,
        gateway: Option<IpAddr>,
        if_index: u32,
    ) -> Result<()> {
        // Build a route message matching what we added and delete it
        // rtnetlink doesn't have a direct delete_route_by_attrs helper yet,
        // so we use raw route deletion
        match network {
            IpNetwork::V4(net) => {
                self.handle
                    .route()
                    .del(build_v4_route_msg(net.network(), net.prefix(), gateway, if_index))
                    .execute()
                    .await
                    .with_context(|| format!("Failed to delete route {}", network))?;
            }
            IpNetwork::V6(_) => {
                // IPv6 route deletion — handled similarly
                debug!("IPv6 route deletion not yet implemented");
            }
        }
        Ok(())
    }
}

/// Build a RouteMessage for IPv4 route deletion
fn build_v4_route_msg(
    dest: Ipv4Addr,
    prefix: u8,
    gateway: Option<IpAddr>,
    if_index: u32,
) -> RouteMessage {
    use netlink_packet_route::route::{RouteAttribute, RouteHeader, RouteProtocol, RouteScope, RouteType};

    let mut msg = RouteMessage::default();
    msg.header.address_family =
        netlink_packet_route::AddressFamily::Inet;
    msg.header.destination_prefix_length = prefix;
    msg.header.protocol = RouteProtocol::Static;
    msg.header.scope = RouteScope::Universe;
    msg.header.kind = RouteType::Unicast;

    msg.attributes.push(RouteAttribute::Destination(
        netlink_packet_route::route::RouteAddress::Inet(dest),
    ));
    msg.attributes.push(RouteAttribute::Oif(if_index));

    if let Some(IpAddr::V4(gw)) = gateway {
        msg.attributes.push(RouteAttribute::Gateway(
            netlink_packet_route::route::RouteAddress::Inet(gw),
        ));
    }

    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_network_parsing() {
        let lower: IpNetwork = "0.0.0.0/1".parse().unwrap();
        let upper: IpNetwork = "128.0.0.0/1".parse().unwrap();
        assert_eq!(lower.prefix(), 1);
        assert_eq!(upper.prefix(), 1);
    }
}
