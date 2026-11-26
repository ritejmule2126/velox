//! Proxy error type and its mapping to client-visible HTTP responses.

use bytes::Bytes;
use http::{header, HeaderValue, Response, StatusCode};
use std::time::Duration;
use velox_core::sanitize::Violation;

/// Boxed error used for streaming bodies.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub use crate::body::ProxyBody;

/// Everything that can go wrong while serving a request. Each variant maps to
/// exactly one status code; none of them can panic the request path.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// No route matches host + path.
    #[error("no route for this host/path")]
    NoRoute,
    /// The request failed strict parsing.
    #[error("rejected request: {0}")]
    Rejected(#[from] Violation),
    /// The client exceeded its rate limit.
    #[error("rate limit exceeded")]
    RateLimited {
        /// Suggested `Retry-After`.
        retry_after: Duration,
    },
    /// The request body exceeds `limits.max_request_body_bytes`.
    #[error("request body too large")]
    BodyTooLarge,
    /// The client stalled while sending the request body.
    #[error("client request body timed out")]
    ClientTimeout,
    /// Every backend is unavailable.
    #[error("no healthy upstream available")]
    NoHealthyUpstream,
    /// Every eligible backend is at its `max_inflight` cap.
    #[error("every upstream backend is at its in-flight limit")]
    UpstreamSaturated,
    /// Could not connect to / talk to the backend.
    #[error("upstream connection failed: {0}")]
    UpstreamConnect(String),
    /// The backend produced no response in time.
    #[error("upstream timed out")]
    UpstreamTimeout,
    /// The backend sent something unusable.
    #[error("bad upstream response: {0}")]
    BadGateway(String),
    /// No valid token. `invalid` distinguishes "a token was presented and is
    /// bad" (`error="invalid_token"`) from "none was presented" (RFC 6750 §3).
    #[error("authentication required")]
    Unauthorized {
        /// A token was presented but refused.
        invalid: bool,
    },
    /// The route's verification keys could not be loaded (fail closed).
    #[error("authentication is temporarily unavailable")]
    AuthUnavailable,
    /// The client's address is not allowed (global or route ACL).
    #[error("client address refused by an access list")]
    Forbidden,
    /// A CORS preflight the route's policy does not allow.
    #[error("cors preflight refused")]
    CorsDenied,
    /// Internal inconsistency (never expected; logged, answered 500).
    #[error("internal error: {0}")]
    Internal(String),
}

impl ProxyError {
    /// The status code returned to the client.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::NoRoute => StatusCode::NOT_FOUND,
            Self::Rejected(v) => v.status(),
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::ClientTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::NoHealthyUpstream | Self::UpstreamSaturated => StatusCode::SERVICE_UNAVAILABLE,
            Self::UpstreamConnect(_) | Self::BadGateway(_) => StatusCode::BAD_GATEWAY,
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::CorsDenied | Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::AuthUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// A short, safe message (never echoes attacker-controlled input).
    pub fn public_message(&self) -> &'static str {
        match self {
            Self::NoRoute => "no route matches this request",
            Self::Rejected(_) => "malformed or ambiguous request",
            Self::RateLimited { .. } => "rate limit exceeded",
            Self::BodyTooLarge => "request body too large",
            Self::ClientTimeout => "timed out reading request",
            Self::NoHealthyUpstream => "no healthy upstream",
            Self::UpstreamSaturated => "upstream is overloaded, retry shortly",
            Self::UpstreamConnect(_) | Self::BadGateway(_) => "bad gateway",
            Self::UpstreamTimeout => "upstream timed out",
            Self::CorsDenied => "cross-origin request not allowed",
            // Deliberately vague: do not say which list, or that one exists.
            Self::Forbidden => "forbidden",
            // Never say *why* a token failed: that helps an attacker, not a client.
            Self::Unauthorized { .. } => "unauthorized",
            Self::AuthUnavailable => "authentication is temporarily unavailable",
            Self::Internal(_) => "internal error",
        }
    }

    /// Build the client response.
    pub fn into_response(self) -> Response<ProxyBody> {
        let status = self.status();
        let mut resp = simple_response(status, self.public_message());
        match &self {
            Self::RateLimited { retry_after } => {
                let secs = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
                if let Ok(v) = HeaderValue::from_str(&secs.max(1).to_string()) {
                    resp.headers_mut().insert(header::RETRY_AFTER, v);
                }
            }
            Self::NoHealthyUpstream | Self::UpstreamSaturated | Self::AuthUnavailable => {
                resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            }
            Self::Unauthorized { invalid } => {
                let challenge = if *invalid {
                    HeaderValue::from_static("Bearer realm=\"velox\", error=\"invalid_token\"")
                } else {
                    HeaderValue::from_static("Bearer realm=\"velox\"")
                };
                resp.headers_mut().insert(header::WWW_AUTHENTICATE, challenge);
            }
            _ => {}
        }
        resp
    }
}

/// A `text/plain` response with a fixed body.
pub fn simple_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let mut resp = Response::new(full(Bytes::from(format!("{message}\n"))));
    *resp.status_mut() = status;
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    resp
}

/// A complete in-memory body (allocation-free).
pub fn full(data: Bytes) -> ProxyBody {
    ProxyBody::full(data)
}

/// An empty body (allocation-free).
pub fn empty() -> ProxyBody {
    ProxyBody::Empty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping_is_complete_and_stable() {
        let cases = [
            (ProxyError::NoRoute, 404),
            (ProxyError::Rejected(Violation::Host), 400),
            (ProxyError::Rejected(Violation::HeadTooLarge), 431),
            (ProxyError::Rejected(Violation::UnsupportedTransferCoding), 501),
            (ProxyError::RateLimited { retry_after: Duration::from_millis(1500) }, 429),
            (ProxyError::BodyTooLarge, 413),
            (ProxyError::ClientTimeout, 408),
            (ProxyError::NoHealthyUpstream, 503),
            (ProxyError::UpstreamSaturated, 503),
            (ProxyError::CorsDenied, 403),
            (ProxyError::Forbidden, 403),
            (ProxyError::Unauthorized { invalid: true }, 401),
            (ProxyError::AuthUnavailable, 503),
            (ProxyError::UpstreamConnect("x".into()), 502),
            (ProxyError::BadGateway("x".into()), 502),
            (ProxyError::UpstreamTimeout, 504),
            (ProxyError::Internal("x".into()), 500),
        ];
        for (e, code) in cases {
            assert_eq!(e.status().as_u16(), code, "{e}");
            assert_eq!(e.into_response().status().as_u16(), code);
        }
    }

    #[test]
    fn retry_after_rounds_up() {
        let r = ProxyError::RateLimited { retry_after: Duration::from_millis(1200) }.into_response();
        assert_eq!(r.headers()[header::RETRY_AFTER], "2");
        let r = ProxyError::RateLimited { retry_after: Duration::from_millis(1) }.into_response();
        assert_eq!(r.headers()[header::RETRY_AFTER], "1");
    }

    #[test]
    fn public_messages_do_not_leak_internals() {
        let e = ProxyError::UpstreamConnect("10.0.0.5:8080 refused".into());
        assert!(!e.public_message().contains("10.0.0.5"));
    }
}
