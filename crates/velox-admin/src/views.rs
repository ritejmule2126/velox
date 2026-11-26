//! JSON representations returned by the admin API.

use serde::Serialize;
use velox_core::{Backend, UpstreamGroup};

/// A backend's live state.
#[derive(Debug, Serialize)]
pub struct BackendView {
    /// `host:port` or `unix:/path`.
    pub addr: String,
    /// Configured weight.
    pub weight: u32,
    /// Result of active health checks.
    pub healthy: bool,
    /// Operator drain flag.
    pub draining: bool,
    /// Milliseconds of passive ejection remaining.
    pub ejected_for_ms: u64,
    /// `true` if the backend currently receives new requests.
    pub available: bool,
    /// In-flight requests.
    pub active_requests: u64,
    /// Lifetime requests.
    pub total_requests: u64,
    /// Lifetime gateway failures.
    pub total_failures: u64,
    /// Current failure streak.
    pub consecutive_failures: u32,
}

impl From<&Backend> for BackendView {
    fn from(b: &Backend) -> Self {
        Self {
            addr: b.name.to_string(),
            weight: b.weight,
            healthy: b.is_healthy(),
            draining: b.is_draining(),
            ejected_for_ms: b.ejected_for_ms(),
            available: b.is_available(),
            active_requests: b.active(),
            total_requests: b.total_requests(),
            total_failures: b.total_failures(),
            consecutive_failures: b.consecutive_failures(),
        }
    }
}

/// An upstream pool and its members.
#[derive(Debug, Serialize)]
pub struct UpstreamView {
    /// Pool name.
    pub name: String,
    /// Balancing algorithm.
    pub algorithm: velox_core::config::Algorithm,
    /// Upstream wire protocol.
    pub protocol: velox_core::config::UpstreamProtocol,
    /// Members.
    pub backends: Vec<BackendView>,
}

impl From<&UpstreamGroup> for UpstreamView {
    fn from(g: &UpstreamGroup) -> Self {
        Self {
            name: g.name.to_string(),
            algorithm: g.config.algorithm,
            protocol: g.config.protocol,
            backends: g.backends.iter().map(|b| BackendView::from(&**b)).collect(),
        }
    }
}

/// A route with its effective id.
#[derive(Debug, Serialize)]
pub struct RouteView {
    /// Stable id (`name` or `route-<index>`).
    pub id: String,
    /// The route definition.
    #[serde(flatten)]
    pub route: velox_core::config::RouteConfig,
}
