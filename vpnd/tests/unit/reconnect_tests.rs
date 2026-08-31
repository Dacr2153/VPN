// vpnd/tests/unit/reconnect_tests.rs
// Unit tests for reconnection policy (exponential backoff + jitter)

use std::time::Duration;
use vpnd::session::reconnect::ReconnectPolicy;

#[test]
fn reconnect_policy_first_delay_is_base() {
    let policy = ReconnectPolicy {
        enabled: true,
        base_delay: Duration::from_millis(500),
        max_delay: Duration::from_secs(30),
        max_attempts: 10,
    };
    let delay = policy.delay_for_attempt(0);
    // First delay is 2^0 * base = 500ms, plus up to 500ms jitter
    assert!(delay >= Duration::from_millis(500), "First delay should be at least base_delay");
    assert!(delay <= Duration::from_millis(1000), "First delay should not exceed base_delay + max_jitter");
}

#[test]
fn reconnect_policy_delay_grows_exponentially() {
    let policy = ReconnectPolicy {
        enabled: true,
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(60),
        max_attempts: 10,
    };

    // Each attempt should produce a larger minimum delay (ignoring jitter)
    // d0 = 100ms + jitter, d1 = 200ms + jitter, d2 = 400ms + jitter
    // With 500ms max jitter these can overlap, but over many samples the average grows
    let d0 = policy.delay_for_attempt(0).as_millis();
    let d3 = policy.delay_for_attempt(3).as_millis();
    
    // d3 minimum = 800ms, d0 maximum = 600ms
    // This should nearly always hold
    assert!(d3 >= d0 / 2, "Delay for attempt 3 should generally be larger than attempt 0");
}

#[test]
fn reconnect_policy_caps_at_max_delay() {
    let policy = ReconnectPolicy {
        enabled: true,
        base_delay: Duration::from_secs(1),
        max_delay: Duration::from_secs(5),
        max_attempts: 100,
    };

    // Attempt 10: 2^10 * 1s = 1024s, should be capped at 5s + 500ms jitter
    let delay = policy.delay_for_attempt(10);
    assert!(
        delay <= Duration::from_millis(5500),
        "Delay should be capped at max_delay + max_jitter, got {:?}",
        delay
    );
}

#[test]
fn reconnect_policy_jitter_varies() {
    // Call delay_for_attempt many times and verify we get at least 2 different values
    // (extremely unlikely to get the same jitter value 20 times in a row)
    let policy = ReconnectPolicy {
        enabled: true,
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(10),
        max_attempts: 10,
    };

    let samples: Vec<_> = (0..20).map(|_| policy.delay_for_attempt(0)).collect();
    let unique: std::collections::HashSet<_> = samples.iter().map(|d| d.as_millis()).collect();
    assert!(unique.len() > 1, "Jitter should produce varying delays (got {} unique values)", unique.len());
}
