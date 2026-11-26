//! # velox-core
//!
//! The dependency-light heart of Velox:
//!
//! * [`config`]: the `velox.toml` schema and validation.
//! * [`state`]: lock-free atomic config swapping ([`SharedState`]).
//! * [`router`]: host/path routing over immutable tables.
//! * [`upstream`]: backend runtime state shared by the proxy, health checker
//!   and admin API.
//! * [`sanitize`]: strict HTTP parsing/normalisation that defeats request
//!   smuggling.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod clock;
pub mod config;
pub mod error;
pub mod router;
pub mod sanitize;
pub mod state;
pub mod upstream;

pub use config::Config;
pub use error::ConfigError;
pub use state::{SharedState, Snapshot};
pub use upstream::{Backend, UpstreamGroup};
