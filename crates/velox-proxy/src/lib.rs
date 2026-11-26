//! # velox-proxy
//! (work in progress)
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod body;
pub mod compress;
pub mod error;
pub mod h3;
pub mod handler;
pub mod io;
pub mod l4;
pub mod lb;
pub mod proxy_protocol;
pub mod server;
pub mod shutdown;
pub mod socket;
pub mod tcp;
pub mod upstream;

pub use handler::{ConnMeta, Proxy};
pub use server::{start, Running, StartError};
pub use shutdown::Shutdown;
