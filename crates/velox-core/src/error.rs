//! Error types for configuration loading, validation and application.

use std::path::PathBuf;

/// Errors produced while loading, validating or applying configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("cannot read config file {path}: {source}")]
    Io {
        /// Path that failed to open.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The configuration text is not valid TOML / does not match the schema.
    #[error("config parse error: {0}")]
    Parse(String),
    /// The configuration parsed but failed semantic validation.
    #[error("invalid configuration:\n  - {}", .0.join("\n  - "))]
    Invalid(Vec<String>),
}
