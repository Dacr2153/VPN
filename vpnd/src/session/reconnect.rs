// vpnd/src/session/reconnect.rs
// Automatic reconnection with exponential backoff + jitter
//
// Implements IEEE-style truncated binary exponential backoff:
//   delay = min(base * 2^attempt, max_delay) + jitter(0..500ms)
//
// Example with default settings:
//   Attempt 0: ~1s
//   Attempt 1: ~2s
//   Attempt 2: ~4s
//   Attempt 3: ~8s
//   Attempt 4: ~16s
//   Attempt 5+: ~30s (capped)

use std::time::Duration;
use tokio::sync::watch;
use tracing::{info, warn};

/// Reconnection configuration
#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    /// Enable automatic reconnection
    pub enabled: bool,
    /// Initial delay between reconnection attempts
    pub base_delay: Duration,
    /// Maximum delay (exponential backoff cap)
    pub max_delay: Duration,
    /// Maximum number of reconnection attempts (0 = unlimited)
    pub max_attempts: u32,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            max_attempts: 0, // unlimited
        }
    }
}

impl ReconnectPolicy {
    pub fn new(enabled: bool, base_secs: u64, max_secs: u64, max_attempts: u32) -> Self {
        Self {
            enabled,
            base_delay: Duration::from_secs(base_secs),
            max_delay: Duration::from_secs(max_secs),
            max_attempts,
        }
    }

    /// Calculate delay for attempt N using truncated exponential backoff
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        // base * 2^attempt, capped at max_delay
        let multiplier = 2u32.saturating_pow(attempt);
        let raw = self.base_delay.saturating_mul(multiplier);
        let capped = raw.min(self.max_delay);

        // Add jitter (0..500ms) to avoid thundering herd
        let jitter_ms = (rand::random::<u32>() % 500) as u64;
        capped + Duration::from_millis(jitter_ms)
    }

    /// Should we attempt reconnection after `attempt` failures?
    pub fn should_reconnect(&self, attempt: u32) -> bool {
        if !self.enabled {
            return false;
        }
        self.max_attempts == 0 || attempt < self.max_attempts
    }
}

/// Drives reconnection loop — caller provides the connect closure
pub struct Reconnector {
    policy: ReconnectPolicy,
    /// Signal sent when shutdown is requested
    shutdown: watch::Receiver<bool>,
}

impl Reconnector {
    pub fn new(policy: ReconnectPolicy, shutdown: watch::Receiver<bool>) -> Self {
        Self { policy, shutdown }
    }

    /// Run the reconnection loop.
    ///
    /// `connect_fn` should return `Ok(())` on success, `Err(e)` on failure.
    /// Returns when:
    ///   - connect_fn succeeds
    ///   - max_attempts exceeded
    ///   - shutdown signal received
    pub async fn run<F, Fut>(&mut self, mut connect_fn: F) -> anyhow::Result<()>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<()>>,
    {
        let mut attempt: u32 = 0;

        loop {
            // Check shutdown
            if *self.shutdown.borrow() {
                info!("Reconnection cancelled by shutdown signal");
                return Err(anyhow::anyhow!("Shutdown requested"));
            }

            // Check limits
            if !self.policy.should_reconnect(attempt) {
                return Err(anyhow::anyhow!(
                    "Max reconnection attempts ({}) exceeded",
                    self.policy.max_attempts
                ));
            }

            if attempt > 0 {
                let delay = self.policy.delay_for_attempt(attempt - 1);
                info!(
                    attempt = attempt,
                    delay_ms = delay.as_millis(),
                    "Reconnecting..."
                );

                // Wait for delay or shutdown
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {},
                    _ = self.shutdown.changed() => {
                        info!("Reconnection interrupted by shutdown");
                        return Err(anyhow::anyhow!("Shutdown requested during reconnect delay"));
                    }
                }
            }

            match connect_fn().await {
                Ok(()) => {
                    if attempt > 0 {
                        info!(attempts = attempt, "Reconnection successful");
                    }
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        attempt = attempt,
                        error = %e,
                        "Connection attempt failed"
                    );
                    attempt += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_progression() {
        let policy = ReconnectPolicy {
            base_delay: Duration::from_millis(1000),
            max_delay: Duration::from_millis(30_000),
            ..Default::default()
        };

        // Without jitter: 1s, 2s, 4s, 8s, 16s, 30s (capped)
        let d0 = policy.delay_for_attempt(0);
        let d1 = policy.delay_for_attempt(1);
        let d2 = policy.delay_for_attempt(2);
        let d5 = policy.delay_for_attempt(5);

        // Should be within jitter range (base..base+jitter)
        assert!(d0 >= Duration::from_millis(1000));
        assert!(d0 < Duration::from_millis(1600));

        assert!(d1 >= Duration::from_millis(2000));
        assert!(d1 < Duration::from_millis(2600));

        assert!(d2 >= Duration::from_millis(4000));
        assert!(d2 < Duration::from_millis(4600));

        // Capped at max_delay + jitter
        assert!(d5 >= Duration::from_millis(30_000));
        assert!(d5 < Duration::from_millis(30_600));
    }

    #[test]
    fn test_max_attempts_limit() {
        let policy = ReconnectPolicy {
            max_attempts: 3,
            ..Default::default()
        };
        assert!(policy.should_reconnect(0));
        assert!(policy.should_reconnect(2));
        assert!(!policy.should_reconnect(3));
    }

    #[test]
    fn test_disabled_policy() {
        let policy = ReconnectPolicy {
            enabled: false,
            ..Default::default()
        };
        assert!(!policy.should_reconnect(0));
    }

    #[tokio::test]
    async fn test_reconnector_succeeds_on_first_try() {
        let policy = ReconnectPolicy::default();
        let (tx, rx) = watch::channel(false);
        let mut reconnector = Reconnector::new(policy, rx);

        let result = reconnector
            .run(|| async { Ok::<(), anyhow::Error>(()) })
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_reconnector_respects_max_attempts() {
        let policy = ReconnectPolicy {
            base_delay: Duration::from_millis(1), // fast for tests
            max_delay: Duration::from_millis(5),
            max_attempts: 2,
            enabled: true,
        };
        let (_tx, rx) = watch::channel(false);
        let mut reconnector = Reconnector::new(policy, rx);

        let result = reconnector
            .run(|| async { Err::<(), _>(anyhow::anyhow!("always fail")) })
            .await;

        assert!(result.is_err());
    }
}
