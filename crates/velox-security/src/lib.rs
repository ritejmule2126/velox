//! # velox-security
//!
//! * [`ratelimit`]: lock-free GCRA token buckets keyed by IP or header.
//! * [`connlimit`]: global and per-IP connection caps with RAII permits.
//! * [`client_cert`]: inbound mutual TLS (hot-reloadable CA bundle, verified identity).
//! * [`tls`]: `rustls` configuration, SNI certificate selection with hot
//!   reload, and development self-signed certificates.
//! * [`upstream_tls`]: client-side TLS / mTLS for `https://` backends.
//! * [`jwt`]: edge JWT verification (HS256 / RS256 / ES256, JWKS, rotation).
//! * [`headers`]: HSTS and response-header policy.
//! * `acme` (feature `acme`): HTTP-01 certificate issuance and renewal.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[cfg(feature = "acme")]
pub mod acme;
pub mod challenge;
pub mod client_cert;
pub mod connlimit;
pub mod headers;
pub mod jwt;
pub mod ratelimit;
pub mod tls;
pub mod upstream_tls;

pub use challenge::ChallengeStore;
pub use connlimit::{ConnectionLimiter, ConnectionPermit};
pub use headers::ResponsePolicy;
pub use jwt::JwtRegistry;
pub use ratelimit::{rate_key, Decision, RateKey, RateLimiter, RateLimiters};
pub use tls::{SniResolver, TlsError};
pub use upstream_tls::UpstreamTlsRegistry;
