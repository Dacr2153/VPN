// vpnd/src/metrics/mod.rs

pub mod collector;
pub mod system;

pub use collector::{MetricsCollector, MetricsSnapshot};
pub use system::{CpuSampler, SystemSnapshot, collect_system_snapshot, read_memory, read_load_avg, read_uptime_seconds};
