// vpnd/src/metrics/system.rs
// Real system metrics from Linux /proc filesystem
//
// Reads CPU usage from /proc/stat and memory from /proc/meminfo.
// No external crates required — pure procfs parsing.
//
// CPU calculation per Linux kernel documentation:
//   cpu_percent = 100 * (idle_delta / total_delta) subtracted from 100
//   where delta = current - previous sample values

use anyhow::{Context, Result};
use std::time::Instant;

/// System-level metrics sampled from /proc
#[derive(Debug, Clone)]
pub struct SystemSnapshot {
    /// CPU usage in percent (0.0–100.0), averaged across all cores
    pub cpu_percent: f32,
    /// Memory used in bytes (total - available)
    pub memory_used_bytes: i64,
    /// Total physical memory in bytes
    pub memory_total_bytes: i64,
    /// 1-minute load average
    pub load_avg_1m: f32,
    /// 5-minute load average
    pub load_avg_5m: f32,
    /// System uptime in seconds
    pub uptime_seconds: i64,
    /// When this sample was taken
    pub sampled_at: Instant,
}

/// Persistent state for CPU delta calculation
#[derive(Default)]
pub struct CpuSampler {
    prev_idle: u64,
    prev_total: u64,
}

impl CpuSampler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sample /proc/stat and compute CPU usage since the last call.
    /// Returns None on the first call (no delta available yet).
    pub fn sample(&mut self) -> Result<Option<f32>> {
        let (idle, total) = read_cpu_times()?;

        let idle_delta = idle.saturating_sub(self.prev_idle);
        let total_delta = total.saturating_sub(self.prev_total);

        let is_first_call = self.prev_total == 0;

        self.prev_idle = idle;
        self.prev_total = total;

        if is_first_call {
            // First sample — no delta to compute
            return Ok(None);
        }

        if total_delta == 0 {
            // CPU counters haven't ticked yet (sampled too quickly)
            // Return 0% busy (effectively 100% idle) — this is the conservative safe value
            return Ok(Some(0.0));
        }

        let cpu_percent = 100.0 * (1.0 - (idle_delta as f64 / total_delta as f64));
        Ok(Some(cpu_percent.clamp(0.0, 100.0) as f32))
    }
}

/// Read CPU jiffies from /proc/stat (first `cpu` line)
///
/// Format: `cpu user nice system idle iowait irq softirq steal guest guest_nice`
fn read_cpu_times() -> Result<(u64, u64)> {
    let content = std::fs::read_to_string("/proc/stat")
        .context("Failed to read /proc/stat")?;

    let line = content
        .lines()
        .find(|l| l.starts_with("cpu "))
        .context("No 'cpu' line in /proc/stat")?;

    let mut parts = line.split_whitespace();
    let _ = parts.next(); // skip "cpu"

    let values: Vec<u64> = parts
        .map(|s| s.parse::<u64>().unwrap_or(0))
        .collect();

    // idle = idle + iowait (index 3 + 4)
    let idle = values.get(3).copied().unwrap_or(0)
        + values.get(4).copied().unwrap_or(0);

    let total: u64 = values.iter().sum();

    Ok((idle, total))
}

/// Read memory info from /proc/meminfo
///
/// Returns (used_bytes, total_bytes)
pub fn read_memory() -> Result<(i64, i64)> {
    let content = std::fs::read_to_string("/proc/meminfo")
        .context("Failed to read /proc/meminfo")?;

    let mut mem_total: i64 = 0;
    let mut mem_available: i64 = 0;

    for line in content.lines() {
        if let Some(val) = parse_meminfo_line(line, "MemTotal:") {
            mem_total = val * 1024; // kB → bytes
        } else if let Some(val) = parse_meminfo_line(line, "MemAvailable:") {
            mem_available = val * 1024;
        }
    }

    let used = mem_total - mem_available;
    Ok((used.max(0), mem_total))
}

fn parse_meminfo_line(line: &str, key: &str) -> Option<i64> {
    if !line.starts_with(key) {
        return None;
    }
    // Format: "MemTotal:       16384000 kB"
    line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<i64>().ok())
}

/// Read load averages from /proc/loadavg
///
/// Format: `1.23 4.56 7.89 1/234 5678`
pub fn read_load_avg() -> Result<(f32, f32)> {
    let content = std::fs::read_to_string("/proc/loadavg")
        .context("Failed to read /proc/loadavg")?;

    let mut parts = content.split_whitespace();
    let one = parts.next()
        .and_then(|s| s.parse::<f32>().ok())
        .unwrap_or(0.0);
    let five = parts.next()
        .and_then(|s| s.parse::<f32>().ok())
        .unwrap_or(0.0);

    Ok((one, five))
}

/// Read system uptime from /proc/uptime
pub fn read_uptime_seconds() -> Result<i64> {
    let content = std::fs::read_to_string("/proc/uptime")
        .context("Failed to read /proc/uptime")?;

    let uptime = content
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);

    Ok(uptime as i64)
}

/// Collect a full system snapshot
pub fn collect_system_snapshot(cpu_sampler: &mut CpuSampler) -> SystemSnapshot {
    let cpu_percent = cpu_sampler.sample().ok().flatten().unwrap_or(0.0);
    let (memory_used_bytes, memory_total_bytes) = read_memory().unwrap_or((0, 0));
    let (load_avg_1m, load_avg_5m) = read_load_avg().unwrap_or((0.0, 0.0));
    let uptime_seconds = read_uptime_seconds().unwrap_or(0);

    SystemSnapshot {
        cpu_percent,
        memory_used_bytes,
        memory_total_bytes,
        load_avg_1m,
        load_avg_5m,
        uptime_seconds,
        sampled_at: Instant::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_memory_positive() {
        let (used, total) = read_memory().expect("Should read /proc/meminfo");
        assert!(total > 0, "Total memory should be positive");
        assert!(used <= total, "Used should not exceed total");
        assert!(used >= 0, "Used memory should be non-negative");
    }

    #[test]
    fn test_read_load_avg() {
        let (one, five) = read_load_avg().expect("Should read /proc/loadavg");
        assert!(one >= 0.0, "Load avg should be non-negative");
        assert!(five >= 0.0);
    }

    #[test]
    fn test_read_uptime() {
        let uptime = read_uptime_seconds().expect("Should read /proc/uptime");
        assert!(uptime > 0, "Uptime should be positive");
    }

    #[test]
    fn test_cpu_sampler_two_samples() {
        let mut sampler = CpuSampler::new();
        // First sample: no delta
        let first = sampler.sample().expect("First sample should succeed");
        assert!(first.is_none(), "First call should return None (no delta)");
        // Second sample: should have a delta
        let second = sampler.sample().expect("Second sample should succeed");
        assert!(second.is_some(), "Second call should return Some");
        let pct = second.unwrap();
        assert!(pct >= 0.0 && pct <= 100.0, "CPU% should be 0-100, got {}", pct);
    }

    #[test]
    fn test_parse_meminfo_line() {
        let result = parse_meminfo_line("MemTotal:       16384000 kB", "MemTotal:");
        assert_eq!(result, Some(16384000));
    }
}
