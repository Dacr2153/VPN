// vpnd/src/session/manager.rs
// VPN session lifecycle management
//
// Tracks all active VPN sessions (server-mode: multiple clients,
// client-mode: single session). Thread-safe via DashMap.

use crate::metrics::collector::MetricsSnapshot;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};
use uuid::Uuid;

/// Current state of a VPN session
#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    /// Handshake in progress
    Connecting,
    /// VPN tunnel is active and passing traffic
    Connected,
    /// Temporary disconnect — reconnect in progress
    Reconnecting,
    /// Intentional disconnect
    Disconnected,
    /// Non-recoverable error
    Failed(String),
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connecting => write!(f, "Connecting"),
            Self::Connected => write!(f, "Connected"),
            Self::Reconnecting => write!(f, "Reconnecting"),
            Self::Disconnected => write!(f, "Disconnected"),
            Self::Failed(e) => write!(f, "Failed: {}", e),
        }
    }
}

/// A single VPN session
#[derive(Debug, Clone)]
pub struct VpnSession {
    /// Unique session identifier
    pub id: String,
    /// Profile name used for this session
    pub profile_name: String,
    /// VPN protocol
    pub protocol: String,
    /// Virtual IP assigned in the VPN subnet
    pub virtual_ip: Option<IpAddr>,
    /// Remote VPN server address
    pub server_ip: IpAddr,
    /// Current state
    pub state: SessionState,
    /// When this session was created
    pub connected_at: Instant,
    /// Last time inbound or outbound traffic was observed.
    /// Used by the idle-timeout reaper to tear down forgotten sessions.
    pub last_activity_at: Instant,
    /// Last observed metrics snapshot
    pub last_metrics: Option<MetricsSnapshot>,
    /// Total bytes sent/received
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Number of reconnection attempts
    pub reconnect_count: u32,
}

impl VpnSession {
    pub fn new(profile_name: String, protocol: String, server_ip: IpAddr) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            profile_name,
            protocol,
            virtual_ip: None,
            server_ip,
            state: SessionState::Connecting,
            connected_at: Instant::now(),
            last_activity_at: Instant::now(),
            last_metrics: None,
            bytes_sent: 0,
            bytes_received: 0,
            reconnect_count: 0,
        }
    }

    pub fn uptime(&self) -> Duration {
        self.connected_at.elapsed()
    }

    pub fn idle_for(&self) -> Duration {
        self.last_activity_at.elapsed()
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state, SessionState::Connected | SessionState::Reconnecting)
    }
}

/// Thread-safe session registry
pub struct SessionManager {
    sessions: Arc<DashMap<String, VpnSession>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }

    /// Register a new session and return its ID
    pub fn create_session(
        &self,
        profile_name: String,
        protocol: String,
        server_ip: IpAddr,
    ) -> String {
        let session = VpnSession::new(profile_name, protocol, server_ip);
        let id = session.id.clone();
        info!(session_id = %id, "Session created");
        self.sessions.insert(id.clone(), session);
        id
    }

    /// Update session state
    pub fn set_state(&self, id: &str, state: SessionState) {
        if let Some(mut session) = self.sessions.get_mut(id) {
            info!(
                session_id = %id,
                old_state = %session.state,
                new_state = %state,
                "Session state changed"
            );
            session.state = state;
        }
    }

    /// Set the virtual IP after tunnel establishment
    pub fn set_virtual_ip(&self, id: &str, ip: IpAddr) {
        if let Some(mut session) = self.sessions.get_mut(id) {
            session.virtual_ip = Some(ip);
        }
    }

    /// Update metrics for a session
    pub fn update_metrics(&self, id: &str, metrics: MetricsSnapshot) {
        if let Some(mut session) = self.sessions.get_mut(id) {
            // Only count *change* in counters as real activity — a tunnel
            // that is up but idle should still time out.
            if metrics.bytes_sent > session.bytes_sent
                || metrics.bytes_received > session.bytes_received
            {
                session.last_activity_at = Instant::now();
            }
            session.bytes_sent = metrics.bytes_sent;
            session.bytes_received = metrics.bytes_received;
            session.last_metrics = Some(metrics);
        }
    }

    /// Return IDs of sessions that have been idle longer than `timeout`.
    pub fn expired_session_ids(&self, timeout: Duration) -> Vec<String> {
        if timeout.is_zero() {
            return Vec::new();
        }
        self.sessions
            .iter()
            .filter(|s| s.is_active() && s.idle_for() > timeout)
            .map(|s| s.id.clone())
            .collect()
    }

    /// Increment reconnect counter
    pub fn increment_reconnect_count(&self, id: &str) {
        if let Some(mut session) = self.sessions.get_mut(id) {
            session.reconnect_count += 1;
        }
    }

    /// Mark session as disconnected
    pub fn disconnect(&self, id: &str) {
        if let Some(mut session) = self.sessions.get_mut(id) {
            info!(session_id = %id, "Session disconnected");
            session.state = SessionState::Disconnected;
        }
    }

    /// Remove a session from the registry
    pub fn remove_session(&self, id: &str) {
        self.sessions.remove(id);
    }

    /// Get a clone of a session
    pub fn get_session(&self, id: &str) -> Option<VpnSession> {
        self.sessions.get(id).map(|s| s.clone())
    }

    /// List all active sessions
    pub fn list_sessions(&self) -> Vec<VpnSession> {
        self.sessions.iter().map(|s| s.clone()).collect()
    }

    /// Find first session in Connected state
    pub fn first_connected_session(&self) -> Option<VpnSession> {
        self.sessions
            .iter()
            .find(|s| s.state == SessionState::Connected)
            .map(|s| s.clone())
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_session_manager() -> SessionManager {
        SessionManager::new()
    }

    #[test]
    fn test_create_and_get_session() {
        let mgr = test_session_manager();
        let server: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let id = mgr.create_session("test_profile".into(), "wireguard".into(), server);
        let session = mgr.get_session(&id).unwrap();
        assert_eq!(session.profile_name, "test_profile");
        assert_eq!(session.state, SessionState::Connecting);
    }

    #[test]
    fn test_state_transitions() {
        let mgr = test_session_manager();
        let server: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let id = mgr.create_session("p".into(), "wg".into(), server);

        mgr.set_state(&id, SessionState::Connected);
        assert_eq!(mgr.get_session(&id).unwrap().state, SessionState::Connected);

        mgr.set_state(&id, SessionState::Reconnecting);
        assert!(mgr.get_session(&id).unwrap().is_active());

        mgr.disconnect(&id);
        assert_eq!(mgr.get_session(&id).unwrap().state, SessionState::Disconnected);
    }

    #[test]
    fn test_remove_session() {
        let mgr = test_session_manager();
        let server: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let id = mgr.create_session("p".into(), "wg".into(), server);
        mgr.remove_session(&id);
        assert!(mgr.get_session(&id).is_none());
    }
}
