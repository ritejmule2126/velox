//! A process-wide monotonic millisecond clock usable from atomics.

use std::sync::OnceLock;
use std::time::Instant;

static EPOCH: OnceLock<Instant> = OnceLock::new();

/// Milliseconds elapsed since the first call in this process (monotonic).
///
/// Used to store deadlines inside `AtomicU64`s (ejection windows, etc.).
pub fn now_ms() -> u64 {
    let epoch = EPOCH.get_or_init(Instant::now);
    u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
}
