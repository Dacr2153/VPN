// vpnd/src/lib.rs
// Re-exports and module declarations for the vpnd library crate

pub mod config;
pub mod crypto;
pub mod ipc;
pub mod kill_switch;
pub mod metrics;
pub mod network;
pub mod routing;
pub mod session;
pub mod tunnel;
pub mod utils;

pub use config::VpndConfig;
pub use session::manager::SessionManager;

/// Version of the daemon
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default Unix socket path for IPC
pub const IPC_SOCKET_PATH: &str = "/run/vpnd/control.sock";

/// Fallback socket path for non-root development
pub const IPC_SOCKET_PATH_DEV: &str = "/tmp/vpnd.sock";

