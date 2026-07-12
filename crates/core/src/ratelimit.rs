//! Per-tool sliding-window rate limiting.
//!
//! The server consults a shared [`RateLimiter`] before executing each
//! `tools/call`. Limits are resolved per tool from the effective policy
//! (baseline `security.rate_limit_per_minute`, overridable per tool), so hot
//! reloads take effect immediately — the limiter only stores call timestamps,
//! never configuration.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;

use crate::error::ToolError;

/// Length of the sliding window.
const WINDOW: Duration = Duration::from_secs(60);

/// A thread-safe sliding-window (last 60 s) rate limiter keyed by tool name.
#[derive(Clone, Default)]
pub struct RateLimiter {
    windows: Arc<DashMap<String, Mutex<VecDeque<Instant>>>>,
}

impl RateLimiter {
    /// Create an empty limiter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an attempt for `tool` under `limit` calls per minute.
    ///
    /// Returns `Ok(())` and counts the call when it is admitted, or
    /// [`ToolError::RateLimited`] without counting it when the window is full.
    /// A `limit` of `None` always admits.
    pub fn check(&self, tool: &str, limit: Option<u32>) -> Result<(), ToolError> {
        let Some(limit) = limit else { return Ok(()) };
        let entry = self
            .windows
            .entry(tool.to_string())
            .or_insert_with(|| Mutex::new(VecDeque::new()));
        let mut window = entry.lock();
        let now = Instant::now();
        while let Some(front) = window.front() {
            if now.duration_since(*front) >= WINDOW {
                window.pop_front();
            } else {
                break;
            }
        }
        if window.len() >= limit as usize {
            return Err(ToolError::RateLimited {
                tool: tool.to_string(),
                limit,
            });
        }
        window.push_back(now);
        Ok(())
    }

    /// Number of admitted calls currently inside the window for `tool`.
    #[must_use]
    pub fn current(&self, tool: &str) -> usize {
        self.windows.get(tool).map_or(0, |w| {
            let mut window = w.lock();
            let now = Instant::now();
            while let Some(front) = window.front() {
                if now.duration_since(*front) >= WINDOW {
                    window.pop_front();
                } else {
                    break;
                }
            }
            window.len()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_always_admits() {
        let l = RateLimiter::new();
        for _ in 0..10_000 {
            l.check("fs.read", None).unwrap();
        }
        // Unlimited calls are not tracked.
        assert_eq!(l.current("fs.read"), 0);
    }

    #[test]
    fn limit_rejects_after_quota() {
        let l = RateLimiter::new();
        for _ in 0..3 {
            l.check("terminal.run", Some(3)).unwrap();
        }
        let err = l.check("terminal.run", Some(3)).unwrap_err();
        assert!(matches!(err, ToolError::RateLimited { limit: 3, .. }));
        assert_eq!(err.category(), "rate_limited");
        // The rejected call is not counted against the window.
        assert_eq!(l.current("terminal.run"), 3);
    }

    #[test]
    fn limits_are_per_tool() {
        let l = RateLimiter::new();
        l.check("a", Some(1)).unwrap();
        assert!(l.check("a", Some(1)).is_err());
        // A different tool has its own window.
        l.check("b", Some(1)).unwrap();
    }

    #[test]
    fn window_slides() {
        let l = RateLimiter::new();
        // Insert an artificially old timestamp, then verify it is evicted.
        {
            let entry = l
                .windows
                .entry("t".to_string())
                .or_insert_with(|| Mutex::new(VecDeque::new()));
            entry
                .lock()
                .push_back(Instant::now() - Duration::from_secs(61));
        }
        assert_eq!(l.current("t"), 0);
        l.check("t", Some(1)).unwrap();
        assert_eq!(l.current("t"), 1);
    }
}
