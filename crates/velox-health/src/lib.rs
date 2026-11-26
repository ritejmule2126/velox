//! # velox-health
//!
//! * [`active`]: background TCP/HTTP probes with jitter and hysteresis.
//! * [`passive`]: outlier detection (circuit breaking) driven by real traffic.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod active;
pub mod passive;

pub use active::HealthChecker;
pub use passive::{record_outcome, Outcome};
