//! Strict HTTP request/response sanitisation.
//!
//! * [`h1`]: byte-level HTTP/1.x validation that runs *before* the HTTP
//!   library normalises anything (request-smuggling defence).
//! * [`headers`]: typed validation for every protocol, hop-by-hop stripping,
//!   `X-Forwarded-*` / `Forwarded` handling and request-id hygiene.
//! * [`Violation`]: the shared rejection type.

pub mod h1;
pub mod headers;
mod violation;

#[cfg(test)]
mod tests;

pub use h1::{
    parse_request_head, BodyFraming, ChunkedDecoder, GuardError, H1Guard, H1Limits, HeadInfo, HeadScanner, Release,
};
pub use headers::{
    apply_forwarded_headers, host_without_port, is_websocket_upgrade, request_id_from, resolve_client_ip,
    strip_hop_by_hop, validate_host, validate_host_pattern, validate_request_headers, X_REQUEST_ID,
};
pub use violation::Violation;

/// Upper bound on headers the wire parser can hold (stack-allocated).
pub const MAX_PARSE_HEADERS: usize = 128;
