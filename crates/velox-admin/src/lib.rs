//! # velox-admin
//!
//! A small REST API for operating a running Velox instance **without
//! restarts**: inspect upstreams, drain backends, edit routes and upstreams,
//! trigger a config-file reload, and scrape `/metrics`.
//!
//! Hardening: loopback-only bind (enforced by config validation) *and* a
//! loopback peer check; `Host` must be a loopback name (DNS-rebinding
//! defence); mutations require `Content-Type: application/json`
//! (CSRF defence); optional bearer token; request bodies are size-capped.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod api;
mod server;
mod views;

pub use api::{AdminApi, Reloader};
pub use server::{serve, serve_metrics, ServeError};
pub use views::{BackendView, RouteView, UpstreamView};
