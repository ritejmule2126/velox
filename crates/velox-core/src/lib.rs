//! # velox-core
//!
//! The dependency-light heart of Velox:
//!
//! * [`config`]: the `velox.toml` schema and validation.
//! * [`state`]: lock-free atomic config swapping ([`SharedState`]).
//! * [`router`]: host/path routing over immutable tables.
//! * [`upstream`]: backend runtime state shared by the proxy, health checker
//!   and admin API.
//! * [`cors`] / [`trace`]: per-route CORS policy and W3C trace-context propagation.
//! * [`sanitize`]: strict HTTP parsing/normalisation that defeats request
//!   smuggling.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod acl;
pub mod cache_admin;
pub mod clock;
pub mod config;
pub mod cors;
pub mod error;
pub mod router;
pub mod sanitize;
pub mod state;
pub mod trace;
pub mod upstream;

pub use config::Config;
pub use error::ConfigError;
pub use state::{SharedState, Snapshot};
pub use upstream::{Backend, UpstreamGroup};
