// vpnd/src/network/mod.rs

pub mod dns_guard;
pub mod dns_resolver;
pub mod nat_traversal;

pub use dns_guard::DnsGuard;
pub use dns_resolver::{start_dot_proxy, DotProxy, DotUpstream};
pub use nat_traversal::StunClient;
