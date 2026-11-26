//! # velox-telemetry
//!
//! Structured JSON logging (`tracing`) and the Prometheus metric registry
//! shared by every Velox component.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod logging;
mod metrics;

pub use logging::init_logging;
pub use metrics::{ConnectionGuard, Metrics, Protocol};

/// Errors from telemetry setup and rendering.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// The log filter directive could not be parsed.
    #[error("invalid log filter `{0}`")]
    Filter(String),
    /// A metric could not be registered or encoded.
    #[error("metrics error: {0}")]
    Metrics(#[from] prometheus::Error),
}
