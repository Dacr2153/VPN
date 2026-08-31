// vpnd/src/routing/mod.rs

pub mod netlink;
pub mod split_tunnel;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

pub use netlink::RouteManager;
pub use split_tunnel::SplitTunnelPolicy;
