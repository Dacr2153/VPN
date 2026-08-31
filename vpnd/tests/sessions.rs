// vpnd/tests/sessions.rs
// Integration tests for VPN session management

use vpnd::session::manager::{SessionManager, SessionState};

#[test]
fn session_manager_starts_empty() {
    let mgr = SessionManager::new();
    assert_eq!(mgr.session_count(), 0);
    assert!(mgr.list_sessions().is_empty());
}

#[test]
fn session_create_and_retrieve() {
    let mgr = SessionManager::new();
    let id = mgr.create_session(
        "test-profile".into(),
        "wireguard".into(),
        "1.2.3.4".parse().unwrap(),
    );

    assert!(!id.is_empty());
    assert_eq!(mgr.session_count(), 1);

    let session = mgr.get_session(&id).expect("Session must exist after create");
    assert_eq!(session.profile_name, "test-profile");
    assert_eq!(session.protocol, "wireguard");
    assert!(matches!(session.state, SessionState::Connecting));
}

#[test]
fn session_ids_are_unique() {
    let mgr = SessionManager::new();
    let id1 = mgr.create_session("a".into(), "wg".into(), "1.1.1.1".parse().unwrap());
    let id2 = mgr.create_session("b".into(), "wg".into(), "2.2.2.2".parse().unwrap());
    assert_ne!(id1, id2);
}

#[test]
fn session_get_nonexistent_returns_none() {
    let mgr = SessionManager::new();
    assert!(mgr.get_session("nonexistent-uuid").is_none());
}

#[test]
fn session_list_returns_all() {
    let mgr = SessionManager::new();
    mgr.create_session("profile-a".into(), "wg".into(), "1.1.1.1".parse().unwrap());
    mgr.create_session("profile-b".into(), "openvpn".into(), "2.2.2.2".parse().unwrap());
    mgr.create_session("profile-c".into(), "ipsec".into(), "3.3.3.3".parse().unwrap());

    assert_eq!(mgr.list_sessions().len(), 3);
}

#[test]
fn session_disconnect_sets_state() {
    let mgr = SessionManager::new();
    let id = mgr.create_session("p1".into(), "wg".into(), "10.0.0.1".parse().unwrap());

    mgr.disconnect(&id);
    let session = mgr.get_session(&id).expect("Session should still exist after disconnect");
    assert!(matches!(session.state, SessionState::Disconnected));
}

#[test]
fn session_remove_clears_count() {
    let mgr = SessionManager::new();
    let id = mgr.create_session("p".into(), "wg".into(), "1.1.1.1".parse().unwrap());
    assert_eq!(mgr.session_count(), 1);

    mgr.remove_session(&id);
    assert_eq!(mgr.session_count(), 0);
}

#[test]
fn session_state_transitions() {
    let mgr = SessionManager::new();
    let id = mgr.create_session("p".into(), "wg".into(), "1.1.1.1".parse().unwrap());

    mgr.set_state(&id, SessionState::Connected);
    assert!(matches!(mgr.get_session(&id).unwrap().state, SessionState::Connected));

    mgr.set_state(&id, SessionState::Reconnecting);
    assert!(matches!(mgr.get_session(&id).unwrap().state, SessionState::Reconnecting));

    mgr.set_state(&id, SessionState::Failed("connection timeout".into()));
    assert!(matches!(mgr.get_session(&id).unwrap().state, SessionState::Failed(_)));
}
