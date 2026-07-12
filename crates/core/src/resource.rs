//! Global CPU/memory budget guard.
//!
//! In addition to the per-call bounds (timeout, output cap), the server can
//! enforce a whole-process resource budget: when the server's resident memory
//! or CPU usage exceeds the configured budget, *new* tool calls are rejected
//! with a retryable [`ToolError::ResourceExhausted`] until usage falls back
//! under budget. In-flight calls are never killed by the guard.
//!
//! Usage is sampled from the OS via `sysinfo`, throttled to at most one
//! refresh per [`SAMPLE_INTERVAL`] so the guard adds no measurable overhead to
//! the dispatch path.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

use crate::error::ToolError;

/// Minimum interval between OS samples.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(500);

/// A point-in-time sample of this process's resource usage.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceUsage {
    /// Resident memory in bytes.
    pub memory_bytes: u64,
    /// CPU usage in percent of one core (may exceed 100 on multi-core hosts).
    pub cpu_percent: f32,
}

struct Sampler {
    sys: System,
    pid: Pid,
    sampled_at: Option<Instant>,
    usage: ResourceUsage,
}

impl Sampler {
    fn sample(&mut self) -> ResourceUsage {
        let now = Instant::now();
        if let Some(at) = self.sampled_at {
            if now.duration_since(at) < SAMPLE_INTERVAL {
                return self.usage;
            }
        }
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[self.pid]),
            true,
            ProcessRefreshKind::new().with_cpu().with_memory(),
        );
        if let Some(proc) = self.sys.process(self.pid) {
            self.usage = ResourceUsage {
                memory_bytes: proc.memory(),
                cpu_percent: proc.cpu_usage(),
            };
        }
        self.sampled_at = Some(now);
        self.usage
    }
}

/// Shared, cheap-to-clone guard that samples this process's usage on demand.
#[derive(Clone)]
pub struct ResourceGuard {
    inner: Arc<Mutex<Sampler>>,
}

impl Default for ResourceGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceGuard {
    /// Create a guard for the current process.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Sampler {
                sys: System::new(),
                pid: Pid::from_u32(std::process::id()),
                sampled_at: None,
                usage: ResourceUsage::default(),
            })),
        }
    }

    /// Latest (possibly cached) usage sample.
    #[must_use]
    pub fn usage(&self) -> ResourceUsage {
        self.inner.lock().sample()
    }

    /// Reject with [`ToolError::ResourceExhausted`] when usage exceeds either
    /// budget. `None` budgets are not enforced; with both `None` this returns
    /// immediately without sampling.
    pub fn check(
        &self,
        max_memory_bytes: Option<u64>,
        max_cpu_percent: Option<f32>,
    ) -> Result<(), ToolError> {
        if max_memory_bytes.is_none() && max_cpu_percent.is_none() {
            return Ok(());
        }
        let usage = self.usage();
        if let Some(limit) = max_memory_bytes {
            if usage.memory_bytes > limit {
                return Err(ToolError::ResourceExhausted(format!(
                    "server memory {} bytes exceeds the {} byte budget; retry once usage drops",
                    usage.memory_bytes, limit
                )));
            }
        }
        if let Some(limit) = max_cpu_percent {
            if usage.cpu_percent > limit {
                return Err(ToolError::ResourceExhausted(format!(
                    "server CPU {:.1}% exceeds the {:.1}% budget; retry once usage drops",
                    usage.cpu_percent, limit
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_budget_never_rejects() {
        let g = ResourceGuard::new();
        g.check(None, None).unwrap();
    }

    #[test]
    fn generous_budget_admits() {
        let g = ResourceGuard::new();
        // A terabyte of memory and 100000% CPU can't be exceeded by this test.
        g.check(Some(1 << 40), Some(100_000.0)).unwrap();
    }

    #[test]
    fn tiny_memory_budget_rejects() {
        let g = ResourceGuard::new();
        // Any live process uses more than one byte of resident memory.
        let err = g.check(Some(1), None).unwrap_err();
        assert!(matches!(err, ToolError::ResourceExhausted(_)));
        assert_eq!(err.category(), "resource_exhausted");
    }

    #[test]
    fn samples_are_cached_between_calls() {
        let g = ResourceGuard::new();
        let a = g.usage();
        let b = g.usage();
        // Within the sample interval the cached value is returned verbatim.
        assert_eq!(a.memory_bytes, b.memory_bytes);
    }
}
