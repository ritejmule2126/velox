//! Passive outlier detection.
//!
//! Real traffic is the best health signal. After `consecutive_failures`
//! gateway failures in a row a backend is *ejected* for
//! `base_ejection_time × 2^(n-1)` (capped), unless that would eject more than
//! `max_ejection_percent` of its pool.

use std::sync::Arc;
use velox_core::clock::now_ms;
use velox_core::config::OutlierConfig;
use velox_core::{Backend, UpstreamGroup};

/// Result of one proxied attempt, as the outlier detector sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The backend answered; `status` is the HTTP status.
    Response {
        /// HTTP status code.
        status: u16,
    },
    /// Connect failure, reset, or timeout before response headers.
    TransportError,
}

impl Outcome {
    /// Is this a *gateway-class* failure that counts against the backend?
    ///
    /// Only 502/503/504 and transport errors count; an application `500`
    /// says nothing about the host's health.
    pub fn is_failure(self) -> bool {
        match self {
            Self::TransportError => true,
            Self::Response { status } => matches!(status, 502..=504),
        }
    }
}

/// Feed one outcome into the detector. Returns `true` if this call ejected
/// the backend.
pub fn record_outcome(group: &UpstreamGroup, backend: &Arc<Backend>, outcome: Outcome) -> bool {
    let cfg: &OutlierConfig = &group.config.outlier;
    if !cfg.enabled {
        return false;
    }
    if !outcome.is_failure() {
        backend.record_success();
        return false;
    }
    let streak = backend.record_failure();
    if streak < cfg.consecutive_failures {
        return false;
    }
    eject_if_allowed(group, backend, cfg)
}

fn eject_if_allowed(group: &UpstreamGroup, backend: &Arc<Backend>, cfg: &OutlierConfig) -> bool {
    let now = now_ms();
    if backend.is_ejected(now) {
        return false;
    }
    let total = group.backends.len();
    let ejected = group.backends.iter().filter(|b| b.is_ejected(now)).count();
    // Keep at least (100 - max_ejection_percent)% of the pool in rotation, and
    // never eject the last member.
    let max_ejected = total * cfg.max_ejection_percent as usize / 100;
    if ejected + 1 > max_ejected || ejected + 1 >= total {
        return false;
    }
    let prior = backend.ejection_count();
    let factor = 1u64 << prior.min(16);
    let base = u64::try_from(cfg.base_ejection_time.as_millis()).unwrap_or(u64::MAX);
    let cap = u64::try_from(cfg.max_ejection_time.as_millis()).unwrap_or(u64::MAX);
    let duration = base.saturating_mul(factor).min(cap);
    backend.eject_until(now.saturating_add(duration));
    tracing::warn!(
        upstream = &*group.name,
        backend = &*backend.name,
        ejected_for_ms = duration,
        "backend ejected by outlier detection"
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use velox_core::{Config, SharedState};

    fn group(n: usize, extra: &str) -> Arc<UpstreamGroup> {
        let backends: Vec<String> = (0..n).map(|i| format!("{{ addr = \"127.0.0.1:{}\" }}", 9000 + i)).collect();
        let text = format!(
            "[server]\nhttp_addr = \"127.0.0.1:1\"\n[[upstream]]\nname = \"a\"\nbackends = [{}]\n{extra}",
            backends.join(",")
        );
        let s = SharedState::new(Config::from_toml_str(&text).unwrap()).unwrap();
        Arc::clone(&s.load().upstreams["a"])
    }

    const FAIL: Outcome = Outcome::TransportError;

    #[test]
    fn ejects_after_consecutive_failures_only() {
        let g = group(3, "[upstream.outlier]\nconsecutive_failures = 3\n");
        let b = &g.backends[0];
        assert!(!record_outcome(&g, b, FAIL));
        assert!(!record_outcome(&g, b, FAIL));
        record_outcome(&g, b, Outcome::Response { status: 200 });
        assert_eq!(b.consecutive_failures(), 0, "success resets the streak");
        for _ in 0..2 {
            assert!(!record_outcome(&g, b, FAIL));
        }
        assert!(record_outcome(&g, b, FAIL));
        assert!(!b.is_available());
        assert!(g.backends[1].is_available());
    }

    #[test]
    fn only_gateway_statuses_count() {
        let g = group(2, "[upstream.outlier]\nconsecutive_failures = 1\n");
        let b = &g.backends[0];
        assert!(!record_outcome(&g, b, Outcome::Response { status: 500 }));
        assert!(!record_outcome(&g, b, Outcome::Response { status: 404 }));
        assert!(record_outcome(&g, b, Outcome::Response { status: 503 }));
    }

    #[test]
    fn never_ejects_more_than_max_percent_or_the_last_backend() {
        let g = group(4, "[upstream.outlier]\nconsecutive_failures = 1\nmax_ejection_percent = 50\n");
        assert!(record_outcome(&g, &g.backends[0], FAIL));
        assert!(record_outcome(&g, &g.backends[1], FAIL));
        assert!(!record_outcome(&g, &g.backends[2], FAIL), "50% cap reached");
        assert_eq!(g.available_count(), 2);

        let single = group(1, "[upstream.outlier]\nconsecutive_failures = 1\n");
        assert!(!record_outcome(&single, &single.backends[0], FAIL), "last backend is never ejected");
        assert!(single.backends[0].is_available());
    }

    #[test]
    fn repeat_ejections_back_off_exponentially_up_to_the_cap() {
        let g = group(
            3,
            "[upstream.outlier]\nconsecutive_failures = 1\nbase_ejection_time = \"1s\"\nmax_ejection_time = \"3s\"\nmax_ejection_percent = 100\n",
        );
        let b = &g.backends[0];
        let mut windows = Vec::new();
        for _ in 0..4 {
            assert!(record_outcome(&g, b, FAIL));
            windows.push(b.ejected_for_ms());
            b.clear_ejection(); // window elapses
        }
        assert!((900..=1000).contains(&windows[0]), "{windows:?}");
        assert!((1900..=2000).contains(&windows[1]), "{windows:?}");
        assert!((2900..=3000).contains(&windows[2]), "{windows:?}");
        assert!((2900..=3000).contains(&windows[3]), "capped: {windows:?}");
    }

    #[test]
    fn disabled_detector_is_inert() {
        let g = group(2, "[upstream.outlier]\nenabled = false\nconsecutive_failures = 1\n");
        assert!(!record_outcome(&g, &g.backends[0], FAIL));
        assert!(g.backends[0].is_available());
    }
}
