// vpnd/src/metrics/collector.rs
// Real-time VPN tunnel metrics
//
// MetricsCollector tracks:
//   - Bytes sent/received (from TUN interface counters)
//   - Packets sent/received
//   - Round-trip latency (measured by periodic ICMP echo / UDP echo)
//   - Jitter (variance in RTT measurements)
//   - Packet loss percentage
//   - Handshake timestamp
//   - Current connection uptime
//
// Metrics are exposed via:
//   1. gRPC streaming (StreamMetrics RPC)
//   2. In-memory snapshot for kill switch and routing decisions

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::debug;

/// Snapshot of metrics at a point in time (Clone-friendly)
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    /// Round-trip time in milliseconds
    pub rtt_ms: f64,
    /// Jitter in milliseconds (std dev of RTT)
    pub jitter_ms: f64,
    /// Loss percentage 0.0–100.0
    pub loss_percent: f64,
    /// Effective throughput (downstream) in bytes/sec
    pub rx_rate_bps: f64,
    /// Effective throughput (upstream) in bytes/sec
    pub tx_rate_bps: f64,
    /// Protocol in use
    pub protocol: String,
    /// VPN interface name
    pub interface: String,
    /// How long this session has been connected
    pub uptime_secs: u64,
    /// Unix timestamp of last measurement
    pub timestamp: u64,
}

/// Thread-safe metrics counters — updated from the tunnel hot path
pub struct MetricsCounters {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub packets_lost: AtomicU64,
}

impl MetricsCounters {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            packets_lost: AtomicU64::new(0),
        })
    }

    pub fn add_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_bytes_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_packets_sent(&self, n: u64) {
        self.packets_sent.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_packets_received(&self, n: u64) {
        self.packets_received.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_packets_lost(&self, n: u64) {
        self.packets_lost.fetch_add(n, Ordering::Relaxed);
    }
}

impl Default for MetricsCounters {
    fn default() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            packets_lost: AtomicU64::new(0),
        }
    }
}

/// Aggregates counters into snapshots, computes rates/jitter
pub struct MetricsCollector {
    counters: Arc<MetricsCounters>,
    protocol: String,
    interface: String,
    started_at: Instant,
    /// Channel for streaming metrics to gRPC clients
    snapshot_tx: watch::Sender<MetricsSnapshot>,
    snapshot_rx: watch::Receiver<MetricsSnapshot>,
    /// Previous sample for rate calculation
    prev_bytes_sent: u64,
    prev_bytes_received: u64,
    prev_sample_time: Instant,
    /// RTT samples for jitter calculation
    rtt_samples: Vec<f64>,
}

impl MetricsCollector {
    pub fn new(counters: Arc<MetricsCounters>, protocol: String, interface: String) -> Self {
        let (tx, rx) = watch::channel(MetricsSnapshot::default());
        Self {
            counters,
            protocol,
            interface,
            started_at: Instant::now(),
            snapshot_tx: tx,
            snapshot_rx: rx,
            prev_bytes_sent: 0,
            prev_bytes_received: 0,
            prev_sample_time: Instant::now(),
            rtt_samples: Vec::with_capacity(30),
        }
    }

    /// Subscribe to a stream of metric snapshots (for gRPC streaming)
    pub fn subscribe(&self) -> watch::Receiver<MetricsSnapshot> {
        self.snapshot_rx.clone()
    }

    /// Record a new RTT measurement
    pub fn record_rtt(&mut self, rtt_ms: f64) {
        self.rtt_samples.push(rtt_ms);
        if self.rtt_samples.len() > 30 {
            self.rtt_samples.remove(0);
        }
    }

    /// Take a new sample and publish it
    pub fn sample(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.prev_sample_time).as_secs_f64();

        let bytes_sent = self.counters.bytes_sent.load(Ordering::Relaxed);
        let bytes_received = self.counters.bytes_received.load(Ordering::Relaxed);
        let packets_sent = self.counters.packets_sent.load(Ordering::Relaxed);
        let packets_received = self.counters.packets_received.load(Ordering::Relaxed);
        let packets_lost = self.counters.packets_lost.load(Ordering::Relaxed);

        // Throughput rates
        let tx_rate = if elapsed > 0.0 {
            (bytes_sent.saturating_sub(self.prev_bytes_sent)) as f64 / elapsed
        } else {
            0.0
        };
        let rx_rate = if elapsed > 0.0 {
            (bytes_received.saturating_sub(self.prev_bytes_received)) as f64 / elapsed
        } else {
            0.0
        };

        // RTT and jitter
        let (rtt_ms, jitter_ms) = self.compute_rtt_jitter();

        // Loss percent
        let total_expected = packets_sent + packets_lost;
        let loss_percent = if total_expected > 0 {
            (packets_lost as f64 / total_expected as f64) * 100.0
        } else {
            0.0
        };

        let snapshot = MetricsSnapshot {
            bytes_sent,
            bytes_received,
            packets_sent,
            packets_received,
            packets_lost,
            rtt_ms,
            jitter_ms,
            loss_percent,
            rx_rate_bps: rx_rate,
            tx_rate_bps: tx_rate,
            protocol: self.protocol.clone(),
            interface: self.interface.clone(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        debug!(
            tx_bps = snapshot.tx_rate_bps as u64,
            rx_bps = snapshot.rx_rate_bps as u64,
            rtt_ms = snapshot.rtt_ms,
            "Metrics sample"
        );

        self.prev_bytes_sent = bytes_sent;
        self.prev_bytes_received = bytes_received;
        self.prev_sample_time = now;

        // Broadcast to all gRPC subscribers
        let _ = self.snapshot_tx.send(snapshot);
    }

    /// Get the most recent snapshot without waiting
    pub fn current_snapshot(&self) -> MetricsSnapshot {
        self.snapshot_rx.borrow().clone()
    }

    fn compute_rtt_jitter(&self) -> (f64, f64) {
        if self.rtt_samples.is_empty() {
            return (0.0, 0.0);
        }
        let mean = self.rtt_samples.iter().sum::<f64>() / self.rtt_samples.len() as f64;
        let variance = self.rtt_samples.iter()
            .map(|&x| (x - mean).powi(2))
            .sum::<f64>()
            / self.rtt_samples.len() as f64;
        (mean, variance.sqrt())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counters_thread_safe() {
        let counters = MetricsCounters::new();
        counters.add_bytes_sent(1024);
        counters.add_bytes_received(512);
        assert_eq!(counters.bytes_sent.load(Ordering::Relaxed), 1024);
        assert_eq!(counters.bytes_received.load(Ordering::Relaxed), 512);
    }

    #[test]
    fn test_rtt_jitter_calculation() {
        let counters = MetricsCounters::new();
        let mut collector = MetricsCollector::new(
            Arc::new(MetricsCounters::default()),
            "wireguard".into(),
            "tun0".into(),
        );
        collector.record_rtt(10.0);
        collector.record_rtt(12.0);
        collector.record_rtt(11.0);
        let (rtt, jitter) = collector.compute_rtt_jitter();
        assert!((rtt - 11.0).abs() < 0.01);
        assert!(jitter > 0.0);
    }

    #[test]
    fn test_loss_percent_zero_when_no_loss() {
        let counters = Arc::new(MetricsCounters::default());
        counters.add_packets_sent(100);
        let mut collector = MetricsCollector::new(counters, "wg".into(), "tun0".into());
        collector.sample();
        let snap = collector.current_snapshot();
        assert_eq!(snap.loss_percent, 0.0);
    }
}
