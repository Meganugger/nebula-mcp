//! Progress reporting from a tool call to the client.

use tokio::sync::mpsc;

/// How many updates may wait to be delivered before new ones are dropped.
/// Progress is advisory, so a slow client loses updates rather than letting a
/// tool grow an unbounded queue.
const BACKLOG: usize = 64;

/// One progress update.
#[derive(Debug, Clone)]
pub struct ProgressUpdate {
    /// Amount of work completed so far; never decreases.
    pub progress: f64,
    /// Total amount of work, when known.
    pub total: Option<f64>,
    /// Human-readable status.
    pub message: Option<String>,
}

/// The sending half given to a tool. Cloneable; sending never blocks.
#[derive(Debug, Clone)]
pub struct ProgressSink {
    tx: mpsc::Sender<ProgressUpdate>,
}

impl ProgressSink {
    /// Create a sink and the receiver the transport drains.
    #[must_use]
    pub fn channel() -> (Self, mpsc::Receiver<ProgressUpdate>) {
        let (tx, rx) = mpsc::channel(BACKLOG);
        (Self { tx }, rx)
    }

    /// Report progress. Dropped if the receiver is gone or behind.
    pub fn report(&self, progress: f64, total: Option<f64>, message: Option<String>) {
        let _ = self.tx.try_send(ProgressUpdate {
            progress,
            total,
            message,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn updates_are_delivered_in_order_and_overflow_is_dropped() {
        let (sink, mut rx) = ProgressSink::channel();
        for i in 0..(BACKLOG + 10) {
            sink.report(i as f64, None, None);
        }
        let mut seen = Vec::new();
        while let Ok(update) = rx.try_recv() {
            seen.push(update.progress);
        }
        assert_eq!(seen.len(), BACKLOG);
        assert!(seen.windows(2).all(|w| w[0] < w[1]));
    }
}
