//! # velox-cli
//!
//! Application wiring ([`app::App`]) and the command-line interface
//! ([`cli`]). The same `App` powers the `velox` binary and the end-to-end
//! test suite.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod app;
pub mod cli;
pub mod doctor;

pub use app::{App, FileReloader};
