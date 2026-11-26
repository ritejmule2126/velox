//! The error type for every strict-parsing rejection.

use http::StatusCode;

/// Why a request was rejected by the sanitiser.
///
/// Each variant maps to a stable HTTP status via [`Violation::status`] and a
/// short, attacker-input-free slug via [`Violation::slug`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Violation {
    /// Request line + headers exceed the configured byte limit.
    #[error("request head too large")]
    HeadTooLarge,
    /// More headers than the configured limit.
    #[error("too many request headers")]
    TooManyHeaders,
    /// The request target exceeds the configured length.
    #[error("request target too long")]
    UriTooLong,
    /// Request line or header syntax is invalid.
    #[error("malformed request line or header")]
    Malformed,
    /// A bare CR or LF (not part of CRLF) was seen.
    #[error("bare CR or LF in request head")]
    BareLineEnding,
    /// A NUL or other control character was seen.
    #[error("control character in request head")]
    ControlCharacter,
    /// Obsolete line folding (obs-fold) was used.
    #[error("obsolete line folding is not allowed")]
    ObsFold,
    /// HTTP version other than 1.0 / 1.1.
    #[error("unsupported HTTP version")]
    Version,
    /// Method rejected by policy (`CONNECT`, `TRACE`).
    #[error("method not allowed")]
    Method,
    /// The request target is not origin-form.
    #[error("request target must be origin-form")]
    Target,
    /// Missing, duplicate, conflicting or syntactically invalid `Host`.
    #[error("missing, duplicate or invalid Host")]
    Host,
    /// Invalid or duplicate `Content-Length`.
    #[error("invalid Content-Length")]
    ContentLength,
    /// `Content-Length` together with `Transfer-Encoding` (CL.TE / TE.CL).
    #[error("both Content-Length and Transfer-Encoding present")]
    ContentLengthWithTransferEncoding,
    /// Malformed or obfuscated `Transfer-Encoding` (TE.TE).
    #[error("invalid Transfer-Encoding")]
    TransferEncoding,
    /// A well-formed but unsupported transfer coding.
    #[error("unsupported transfer coding")]
    UnsupportedTransferCoding,
    /// A header name that proxies and backends may disagree on
    /// (e.g. `Transfer_Encoding`).
    #[error("ambiguous header name")]
    AmbiguousHeaderName,
    /// `Connection` nominates a framing header (`Content-Length`, `Host`, …).
    #[error("Connection header nominates a framing header")]
    ConnectionNominatesFraming,
    /// Chunked body framing is invalid.
    #[error("invalid chunked encoding")]
    Chunk,
    /// HTTP/2 or HTTP/3 request carries connection-specific headers.
    #[error("connection-specific header in HTTP/2 or HTTP/3 request")]
    ConnectionSpecificHeader,
    /// An `Upgrade` request carried a body.
    #[error("upgrade request must not have a body")]
    UpgradeWithBody,
}

impl Violation {
    /// The HTTP status this rejection should be answered with.
    pub fn status(self) -> StatusCode {
        match self {
            Self::HeadTooLarge | Self::TooManyHeaders => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            Self::UriTooLong => StatusCode::URI_TOO_LONG,
            Self::Method => StatusCode::METHOD_NOT_ALLOWED,
            Self::UnsupportedTransferCoding => StatusCode::NOT_IMPLEMENTED,
            Self::Version => StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    /// A short machine-friendly identifier safe to log and put in URLs.
    pub fn slug(self) -> &'static str {
        match self {
            Self::HeadTooLarge => "head-too-large",
            Self::TooManyHeaders => "too-many-headers",
            Self::UriTooLong => "uri-too-long",
            Self::Malformed => "malformed",
            Self::BareLineEnding => "bare-line-ending",
            Self::ControlCharacter => "control-character",
            Self::ObsFold => "obs-fold",
            Self::Version => "version",
            Self::Method => "method",
            Self::Target => "target",
            Self::Host => "host",
            Self::ContentLength => "content-length",
            Self::ContentLengthWithTransferEncoding => "cl-te-conflict",
            Self::TransferEncoding => "transfer-encoding",
            Self::UnsupportedTransferCoding => "unsupported-transfer-coding",
            Self::AmbiguousHeaderName => "ambiguous-header-name",
            Self::ConnectionNominatesFraming => "connection-nominates-framing",
            Self::Chunk => "chunk",
            Self::ConnectionSpecificHeader => "connection-specific-header",
            Self::UpgradeWithBody => "upgrade-with-body",
        }
    }

    /// Inverse of [`Violation::slug`] (used by the proxy's reject channel).
    pub fn from_slug(slug: &str) -> Option<Self> {
        const ALL: [Violation; 20] = [
            Violation::HeadTooLarge,
            Violation::TooManyHeaders,
            Violation::UriTooLong,
            Violation::Malformed,
            Violation::BareLineEnding,
            Violation::ControlCharacter,
            Violation::ObsFold,
            Violation::Version,
            Violation::Method,
            Violation::Target,
            Violation::Host,
            Violation::ContentLength,
            Violation::ContentLengthWithTransferEncoding,
            Violation::TransferEncoding,
            Violation::UnsupportedTransferCoding,
            Violation::AmbiguousHeaderName,
            Violation::ConnectionNominatesFraming,
            Violation::Chunk,
            Violation::ConnectionSpecificHeader,
            Violation::UpgradeWithBody,
        ];
        ALL.into_iter().find(|v| v.slug() == slug)
    }
}
