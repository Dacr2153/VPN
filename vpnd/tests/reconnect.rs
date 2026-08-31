// vpnd/tests/reconnect.rs
// Integration tests for reconnection policy

use std::time::Duration;
use vpnd::session::reconnect::ReconnectPolicy;

#[test]
fn first_delay_is_at_least_base() {
    let policy = ReconnectPolicy {
        enabled: true,
        base_delay: Duration::from_millis(500),
        max_delay: Duration::from_secs(30),
        max_attempts: 10,
    };
    let delay = policy.delay_for_attempt(0);
    assert!(delay >= Duration::from_millis(500));
    // Max = base + 500ms jitter
    assert!(delay <= Duration::from_millis(1000));
}

#[test]
fn delay_is_capped_at_max() {
    let policy = ReconnectPolicy {
        enabled: true,
        base_delay: Duration::from_secs(1),
        max_delay: Duration::from_secs(5),
        max_attempts: 100,
    };
    // Attempt 10 would be 2^10 = 1024s — must cap at 5s (+500ms jitter)
    let delay = policy.delay_for_attempt(10);
    assert!(
        delay <= Duration::from_millis(5500),
        "Delay must be capped at max_delay + jitter, got {:?}",
        delay
    );
}

#[test]
fn jitter_produces_varying_delays() {
    let policy = ReconnectPolicy {
        enabled: true,
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(10),
        max_attempts: 10,
    };
    let samples: Vec<_> = (0..20).map(|_| policy.delay_for_attempt(0)).collect();
    let unique: std::collections::HashSet<_> = samples.iter().map(|d| d.as_millis()).collect();
    assert!(unique.len() > 1, "Jitter should vary across calls, got {} unique values", unique.len());
}

#[test]
fn higher_attempt_generally_longer() {
    let policy = ReconnectPolicy {
        enabled: true,
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(60),
        max_attempts: 20,
    };
    // Minimum at attempt N = 2^N * base_delay
    // Attempt 0 minimum = 100ms, Attempt 5 minimum = 3200ms
    // Even with max 500ms jitter, attempt 5 should dominate
    let d0 = policy.delay_for_attempt(0);
    let d5 = policy.delay_for_attempt(5);
    assert!(
        d5 > d0,
        "Attempt 5 delay ({:?}) should exceed attempt 0 ({:?})",
        d5,
        d0
    );
}
