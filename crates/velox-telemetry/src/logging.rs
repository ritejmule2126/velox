//! `tracing` subscriber setup.

use crate::TelemetryError;
use velox_core::config::{LogFormat, TelemetryConfig};

/// Install the global `tracing` subscriber.
///
/// `RUST_LOG`, when set, overrides `telemetry.log_level`. Calling this more
/// than once is harmless (later calls are ignored).
pub fn init_logging(cfg: &TelemetryConfig) -> Result<(), TelemetryError> {
    let directive = std::env::var("RUST_LOG").unwrap_or_else(|_| cfg.log_level.clone());
    let filter =
        tracing_subscriber::EnvFilter::try_new(&directive).map_err(|_| TelemetryError::Filter(directive.clone()))?;
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stdout);
    let result = match cfg.log_format {
        LogFormat::Json => builder.json().flatten_event(true).with_current_span(true).with_span_list(false).try_init(),
        LogFormat::Pretty => builder.try_init(),
    };
    // `Err` only means a subscriber is already installed.
    let _ = result;
    Ok(())
}
