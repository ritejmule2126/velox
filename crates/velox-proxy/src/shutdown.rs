//! Cooperative graceful shutdown shared by every listener and connection.

use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// Two-phase shutdown: **drain** (stop accepting, finish in-flight work) then
/// **kill** (give up on stragglers).
#[derive(Debug, Clone, Default)]
pub struct Shutdown {
    /// Cancelled when draining starts: listeners stop, connections wind down.
    pub drain: CancellationToken,
    /// Cancelled when the drain deadline passes: remaining work is abandoned.
    pub kill: CancellationToken,
    /// Every connection / tunnel task, so shutdown can wait for them.
    pub tasks: TaskTracker,
}

impl Shutdown {
    /// A fresh, un-triggered shutdown handle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin draining and wait up to `timeout` for tracked tasks.
    ///
    /// Returns `true` if everything finished on its own, `false` if the
    /// deadline forced a kill.
    pub async fn graceful(&self, timeout: Duration) -> bool {
        self.drain.cancel();
        self.tasks.close();
        if tokio::time::timeout(timeout, self.tasks.wait()).await.is_ok() {
            return true;
        }
        self.kill.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.tasks.wait()).await;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn drains_cleanly_when_tasks_finish() {
        let sd = Shutdown::new();
        let d = sd.drain.clone();
        sd.tasks.spawn(async move {
            d.cancelled().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        assert!(sd.graceful(Duration::from_secs(10)).await);
        assert!(!sd.kill.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn kills_stragglers_after_the_deadline() {
        let sd = Shutdown::new();
        let k = sd.kill.clone();
        sd.tasks.spawn(async move {
            k.cancelled().await;
        });
        assert!(!sd.graceful(Duration::from_secs(2)).await);
        assert!(sd.kill.is_cancelled());
    }
}
