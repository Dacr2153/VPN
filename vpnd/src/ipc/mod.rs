// vpnd/src/ipc/mod.rs

pub mod grpc_server;
pub mod peer_cred;

pub use grpc_server::VpndService;
pub use peer_cred::{AuthDecision, AuthenticatedListener, AuthenticatedUnixStream, PeerCred};
