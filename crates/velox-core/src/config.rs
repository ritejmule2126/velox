//! Declarative configuration schema (`velox.toml`) and its validation.
//!
//! Every struct uses `deny_unknown_fields` so typos fail loudly instead of
//! silently falling back to defaults.

use crate::error::ConfigError;
use crate::sanitize::validate_host_pattern;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

/// Root configuration document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Listener sockets and process-level behaviour.
    pub server: ServerConfig,
    /// Hard bounds on request size and concurrency.
    pub limits: LimitsConfig,
    /// Timeouts applied on every stage of a request.
    pub timeouts: TimeoutsConfig,
    /// TLS certificates, HSTS and ACME.
    pub tls: TlsConfig,
    /// Header hygiene and trusted proxy settings.
    pub security: SecurityConfig,
    /// Streaming response compression (opt-in).
    pub compression: CompressionConfig,
    /// Sizing of the in-memory response cache (routes opt in with `cache`).
    pub cache: CacheConfig,
    /// Default rate-limit policy applied to every route (routes may override).
    pub rate_limit: Option<RateLimitConfig>,
    /// Localhost-only admin API.
    pub admin: AdminConfig,
    /// Logging and metrics.
    pub telemetry: TelemetryConfig,
    /// Backend pools.
    #[serde(rename = "upstream", alias = "upstreams")]
    pub upstreams: Vec<UpstreamConfig>,
    /// L7 routes.
    #[serde(rename = "route", alias = "routes")]
    pub routes: Vec<RouteConfig>,
    /// Raw L4 (TCP) proxies.
    #[serde(rename = "tcp_proxy", alias = "tcp_proxies")]
    pub tcp_proxies: Vec<TcpProxyConfig>,
}

/// Listener sockets and process-level behaviour.
///
/// Changing listener addresses requires a restart; everything else is
/// hot-reloadable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// Plain-text HTTP/1.1 listener (e.g. `0.0.0.0:80`). `None` disables it.
    pub http_addr: Option<SocketAddr>,
    /// TLS listener for HTTP/2 + HTTP/1.1 over TCP (e.g. `0.0.0.0:443`).
    pub https_addr: Option<SocketAddr>,
    /// Enable HTTP/3 (QUIC over UDP) on the HTTPS port.
    pub h3: bool,
    /// UDP address for HTTP/3; defaults to `https_addr`.
    pub h3_addr: Option<SocketAddr>,
    /// `Alt-Svc` max-age (seconds) advertised for HTTP/3.
    pub alt_svc_max_age: u64,
    /// Number of parallel accept loops per TCP listener.
    pub accept_workers: usize,
    /// Use `SO_REUSEPORT` so multiple accept loops can share a port.
    pub reuse_port: bool,
    /// Set `TCP_NODELAY` on accepted and upstream sockets.
    pub tcp_nodelay: bool,
    /// Listen backlog.
    pub backlog: i32,
    /// Maximum time to wait for in-flight requests on shutdown.
    #[serde(with = "humantime_serde")]
    pub drain_timeout: Duration,
    /// Expect a PROXY protocol v1/v2 header on every `http_addr` / `https_addr`
    /// connection (AWS NLB, HAProxy, …) and take the client address from it.
    /// Requires `proxy_protocol_trusted`. Not applicable to HTTP/3 (UDP).
    pub proxy_protocol: bool,
    /// The only peers allowed to send a PROXY header. Connections from anyone
    /// else on a PROXY-protocol listener are refused, so a client can never
    /// forge its own address.
    pub proxy_protocol_trusted: Vec<IpNet>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_addr: None,
            https_addr: None,
            h3: true,
            h3_addr: None,
            alt_svc_max_age: 86_400,
            accept_workers: 1,
            reuse_port: true,
            tcp_nodelay: true,
            backlog: 1024,
            drain_timeout: Duration::from_secs(30),
            proxy_protocol: false,
            proxy_protocol_trusted: Vec::new(),
        }
    }
}

/// Hard bounds on request size and concurrency (DoS hardening).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsConfig {
    /// Maximum size of the request line + headers, in bytes (HTTP/1).
    pub max_header_bytes: usize,
    /// Maximum number of request headers (at most 128).
    pub max_headers: usize,
    /// Maximum request-target length in bytes.
    pub max_uri_bytes: usize,
    /// Maximum request body size in bytes (`0` = unlimited).
    pub max_request_body_bytes: u64,
    /// Maximum simultaneous client connections overall (`0` = unlimited).
    pub max_connections: usize,
    /// Maximum simultaneous client connections per source IP (`0` = unlimited).
    pub max_connections_per_ip: usize,
    /// Maximum concurrent streams per HTTP/2 or HTTP/3 connection.
    pub max_streams_per_connection: u32,
    /// Largest request body (bytes) buffered so a failed attempt can be retried.
    pub retry_body_buffer_bytes: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: 16 * 1024,
            max_headers: 100,
            max_uri_bytes: 8 * 1024,
            max_request_body_bytes: 10 * 1024 * 1024,
            max_connections: 10_000,
            max_connections_per_ip: 256,
            max_streams_per_connection: 100,
            retry_body_buffer_bytes: 64 * 1024,
        }
    }
}

/// Timeouts applied on every stage of a request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TimeoutsConfig {
    /// TLS / QUIC handshake deadline.
    #[serde(with = "humantime_serde")]
    pub tls_handshake: Duration,
    /// Time allowed to receive a complete request head (Slowloris guard).
    #[serde(with = "humantime_serde")]
    pub header_read: Duration,
    /// Idle keep-alive time between requests on a client connection.
    #[serde(with = "humantime_serde")]
    pub idle_keepalive: Duration,
    /// Maximum gap between client request-body frames.
    #[serde(with = "humantime_serde")]
    pub request_body_idle: Duration,
    /// Upstream TCP/Unix connect deadline.
    #[serde(with = "humantime_serde")]
    pub upstream_connect: Duration,
    /// Deadline to receive upstream response *headers*.
    #[serde(with = "humantime_serde")]
    pub upstream_response: Duration,
    /// Maximum gap between upstream response-body frames.
    #[serde(with = "humantime_serde")]
    pub upstream_body_idle: Duration,
    /// Abort a client connection whose socket stays unwritable this long
    /// (slow-reader / "slow read" DoS guard).
    #[serde(with = "humantime_serde")]
    pub write_stall: Duration,
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            tls_handshake: Duration::from_secs(10),
            header_read: Duration::from_secs(10),
            idle_keepalive: Duration::from_secs(60),
            request_body_idle: Duration::from_secs(30),
            upstream_connect: Duration::from_secs(3),
            upstream_response: Duration::from_secs(30),
            upstream_body_idle: Duration::from_secs(60),
            write_stall: Duration::from_secs(30),
        }
    }
}

/// TLS settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct TlsConfig {
    /// Certificates selected by SNI.
    pub certs: Vec<CertConfig>,
    /// Generate an in-memory self-signed certificate when no cert matches
    /// (development only).
    pub self_signed_fallback: bool,
    /// HTTP Strict Transport Security.
    pub hsts: HstsConfig,
    /// Automatic certificates via ACME HTTP-01 (requires the `acme` feature).
    pub acme: Option<AcmeConfig>,
    /// PEM bundle of CAs that client certificates must chain to (mutual TLS on
    /// the HTTPS and HTTP/3 listeners). Re-read on reload / `SIGHUP`; a bundle
    /// that fails to load keeps the previous one.
    pub client_ca_file: Option<PathBuf>,
    /// With `client_ca_file`: `true` (the default) rejects clients that present
    /// no valid certificate during the handshake; `false` lets anonymous clients
    /// through but still rejects a certificate that does not verify.
    pub client_auth_required: Option<bool>,
}

/// A certificate / key pair and the SNI names it serves.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertConfig {
    /// SNI names (exact or `*.example.com`). Empty makes this the default cert.
    #[serde(default)]
    pub server_names: Vec<String>,
    /// PEM certificate chain.
    pub cert_file: PathBuf,
    /// PEM private key (PKCS#8, PKCS#1 or SEC1).
    pub key_file: PathBuf,
}

/// HSTS settings (only emitted on TLS connections).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HstsConfig {
    /// Emit `Strict-Transport-Security`.
    pub enabled: bool,
    /// `max-age` in seconds.
    pub max_age: u64,
    /// Add `includeSubDomains`.
    pub include_subdomains: bool,
    /// Add `preload`.
    pub preload: bool,
}

impl Default for HstsConfig {
    fn default() -> Self {
        Self { enabled: true, max_age: 31_536_000, include_subdomains: false, preload: false }
    }
}

/// ACME (Let's Encrypt) settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    /// Domain names to obtain a certificate for.
    pub domains: Vec<String>,
    /// Account contact e-mail.
    pub contact_email: String,
    /// ACME directory URL.
    #[serde(default = "default_acme_directory")]
    pub directory_url: String,
    /// Directory where account credentials and certificates are cached.
    #[serde(default = "default_acme_cache")]
    pub cache_dir: PathBuf,
    /// Renew when fewer than this many days remain.
    #[serde(default = "default_renew_days")]
    pub renew_before_days: u32,
}

fn default_acme_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_owned()
}
fn default_acme_cache() -> PathBuf {
    PathBuf::from("./acme-cache")
}
fn default_renew_days() -> u32 {
    30
}

/// Header hygiene and trust settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SecurityConfig {
    /// Peers whose `X-Forwarded-*` / `Forwarded` headers are trusted.
    pub trusted_proxies: Vec<IpNet>,
    /// Add `X-Content-Type-Options: nosniff` when the upstream did not.
    pub nosniff: bool,
    /// Extra response headers added when the upstream did not set them.
    pub response_headers: BTreeMap<String, String>,
    /// Remove the upstream `Server` header from responses.
    pub hide_server_header: bool,
    /// Accept `_` in `Host` labels (e.g. `my_service`). Off by default because
    /// underscores are not valid hostname characters (RFC 1123) and lenient
    /// parsing invites host-confusion bugs.
    pub allow_underscores_in_host: bool,
    /// If non-empty, only these client networks may use any route (matched
    /// against the client address *after* PROXY protocol / `trusted_proxies`).
    pub ip_allow: Vec<IpNet>,
    /// Client networks refused on every route. Deny always wins over allow.
    pub ip_deny: Vec<IpNet>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            nosniff: true,
            response_headers: BTreeMap::new(),
            hide_server_header: false,
            allow_underscores_in_host: false,
            ip_allow: Vec::new(),
            ip_deny: Vec::new(),
        }
    }
}

/// What a rate limit bucket is keyed on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum KeySource {
    /// The client IP address.
    Ip,
    /// The value of the named request header (falls back to the IP).
    Header(String),
}

impl FromStr for KeySource {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("ip") {
            return Ok(Self::Ip);
        }
        match s.split_once(':') {
            Some((kind, name)) if kind.eq_ignore_ascii_case("header") => {
                http::HeaderName::from_bytes(name.trim().as_bytes())
                    .map(|n| Self::Header(n.as_str().to_owned()))
                    .map_err(|_| format!("invalid header name in key `{s}`"))
            }
            _ => Err(format!("key must be `ip` or `header:<name>`, got `{s}`")),
        }
    }
}

impl fmt::Display for KeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip => f.write_str("ip"),
            Self::Header(h) => write!(f, "header:{h}"),
        }
    }
}

impl TryFrom<String> for KeySource {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<KeySource> for String {
    fn from(value: KeySource) -> Self {
        value.to_string()
    }
}

/// A token-bucket rate-limit policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RateLimitConfig {
    /// Set to `false` on a route to opt out of the global policy.
    pub enabled: bool,
    /// Sustained refill rate in requests per second.
    pub requests_per_second: f64,
    /// Bucket capacity (maximum burst).
    pub burst: u32,
    /// What to key buckets on: `ip` or `header:<name>`.
    pub key: KeySource,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self { enabled: true, requests_per_second: 100.0, burst: 200, key: KeySource::Ip }
    }
}

/// Admin API settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AdminConfig {
    /// Loopback address of the admin API. `None` disables it.
    pub addr: Option<SocketAddr>,
    /// Name of an environment variable holding a bearer token; when set (and
    /// the variable is non-empty) every admin request must present it.
    pub token_env: Option<String>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self { addr: Some(SocketAddr::from(([127, 0, 0, 1], 9901))), token_env: None }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// One JSON object per line.
    #[default]
    Json,
    /// Human-friendly text.
    Pretty,
}

/// Logging and metrics settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TelemetryConfig {
    /// `tracing` filter directive, e.g. `info` or `velox_proxy=debug`.
    pub log_level: String,
    /// Log output format.
    pub log_format: LogFormat,
    /// Emit one access-log line per request.
    pub access_log: bool,
    /// Optional dedicated listener serving only `/metrics` (may be non-loopback).
    pub metrics_addr: Option<SocketAddr>,
    /// Propagate W3C Trace Context: continue a valid inbound `traceparent`
    /// (new span id for this hop), mint one otherwise, and log the trace id.
    pub traceparent: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_owned(),
            log_format: LogFormat::Json,
            access_log: true,
            metrics_addr: None,
            traceparent: false,
        }
    }
}

/// Where a backend lives: `host:port`, `http://host[:port]`, `https://host[:port]`
/// or `unix:/path`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum BackendAddr {
    /// A TCP endpoint (`host:port`; IPv6 hosts keep their brackets).
    Tcp {
        /// Host name or IP literal.
        host: String,
        /// TCP port.
        port: u16,
    },
    /// A TCP endpoint spoken to over TLS (`https://host[:port]`, default port 443).
    Tls {
        /// Host name or IP literal (also the default SNI / verification name).
        host: String,
        /// TCP port.
        port: u16,
    },
    /// A Unix domain socket (`unix:/path/to.sock`).
    Unix(PathBuf),
}

impl BackendAddr {
    /// The host name if this is a TCP/TLS backend addressed by name (not by IP
    /// literal) — the ones DNS refresh applies to.
    pub fn hostname(&self) -> Option<&str> {
        match self {
            Self::Tcp { host, .. } | Self::Tls { host, .. } => {
                (Self::connect_host(host).parse::<std::net::IpAddr>().is_err()).then_some(host.as_str())
            }
            Self::Unix(_) => None,
        }
    }

    /// The same endpoint at a resolved `ip` (`None` for Unix sockets).
    pub fn at_ip(&self, ip: std::net::IpAddr) -> Option<Self> {
        let host = match ip {
            std::net::IpAddr::V4(v4) => v4.to_string(),
            std::net::IpAddr::V6(v6) => format!("[{v6}]"),
        };
        match self {
            Self::Tcp { port, .. } => Some(Self::Tcp { host, port: *port }),
            Self::Tls { port, .. } => Some(Self::Tls { host, port: *port }),
            Self::Unix(_) => None,
        }
    }

    /// The host without IPv6 brackets, suitable for `TcpStream::connect`.
    pub fn connect_host(host: &str) -> &str {
        host.trim_start_matches('[').trim_end_matches(']')
    }
}

impl FromStr for BackendAddr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(path) = s.strip_prefix("unix:") {
            if path.is_empty() {
                return Err("empty unix socket path".to_owned());
            }
            return Ok(Self::Unix(PathBuf::from(path)));
        }
        // `https://host[:port]` (TLS, default 443) and `http://host[:port]`
        // (cleartext, default 80) are accepted next to the bare `host:port`.
        let (tls, rest, default_port) = if let Some(r) = s.strip_prefix("https://") {
            (true, r, Some(443))
        } else if let Some(r) = s.strip_prefix("http://") {
            (false, r, Some(80))
        } else {
            (false, s, None)
        };
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) if !p.ends_with(']') => {
                (h, p.parse::<u16>().map_err(|_| format!("backend `{s}` has an invalid port"))?)
            }
            _ => (rest, default_port.ok_or_else(|| format!("backend `{s}` must be host:port or unix:/path"))?),
        };
        let bare = Self::connect_host(host);
        let ok = !bare.is_empty()
            && (host.starts_with('[') == host.ends_with(']'))
            && bare.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
        if !ok {
            return Err(format!("backend `{s}` has an invalid host"));
        }
        let host = host.to_owned();
        Ok(if tls { Self::Tls { host, port } } else { Self::Tcp { host, port } })
    }
}

impl fmt::Display for BackendAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp { host, port } => write!(f, "{host}:{port}"),
            Self::Tls { host, port } => write!(f, "https://{host}:{port}"),
            Self::Unix(p) => write!(f, "unix:{}", p.display()),
        }
    }
}

impl TryFrom<String> for BackendAddr {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<BackendAddr> for String {
    fn from(value: BackendAddr) -> Self {
        value.to_string()
    }
}

/// Load-balancing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    /// Weighted round-robin.
    #[default]
    RoundRobin,
    /// Fewest in-flight requests (weight-normalised).
    LeastConn,
    /// Power-of-two-choices on in-flight requests.
    P2c,
    /// Ketama-style consistent hashing.
    ConsistentHash,
}

/// Wire protocol spoken to backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocol {
    /// HTTP/1.1 with keep-alive pooling.
    #[default]
    Http1,
    /// HTTP/2 with prior knowledge (cleartext, multiplexed).
    H2c,
    /// HTTP/2 everywhere: prior knowledge on cleartext backends, ALPN `h2` on
    /// `https://` backends.
    H2,
}

impl UpstreamProtocol {
    /// Does this protocol speak HTTP/2 to the backend?
    pub fn is_h2(self) -> bool {
        matches!(self, Self::H2c | Self::H2)
    }
}

/// A response content-coding Velox can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompressionAlgorithm {
    /// Zstandard (`zstd`).
    Zstd,
    /// Brotli (`br`).
    #[serde(alias = "br")]
    Brotli,
    /// Gzip (`gzip`).
    Gzip,
}

impl CompressionAlgorithm {
    /// The `Content-Encoding` / `Accept-Encoding` token.
    pub fn token(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
            Self::Brotli => "br",
            Self::Gzip => "gzip",
        }
    }
}

/// CPU / ratio trade-off for response compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CompressionLevel {
    /// Lowest CPU cost.
    Fast,
    /// A balanced default.
    #[default]
    Default,
    /// Best ratio that is still practical for on-the-fly compression.
    Best,
}

/// Streaming response compression.
///
/// Compression is skipped for responses that are already encoded, too small,
/// not compressible by `content_types`, `text/event-stream`, `no-transform`,
/// partial (`206`) or bodyless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CompressionConfig {
    /// Master switch (routes may override with `compress`).
    pub enabled: bool,
    /// Offered encodings in server preference order (used to break `q` ties).
    pub algorithms: Vec<CompressionAlgorithm>,
    /// Do not compress bodies known to be smaller than this many bytes.
    pub min_size: u64,
    /// CPU / ratio trade-off.
    pub level: CompressionLevel,
    /// Compressible media types: `type/subtype`, `type/*`, or a `*` glob in
    /// the subtype (`application/*+json`).
    pub content_types: Vec<String>,
    /// At most this many responses are compressed at once (each holds an
    /// encoder). Beyond it, responses pass through uncompressed — compression
    /// is an optimisation and never queues or fails traffic.
    pub max_concurrent_encoders: usize,
    /// Slices of at least this many bytes are compressed on dedicated worker
    /// threads instead of the async runtime; smaller ones run inline.
    pub offload_threshold: usize,
    /// Compression worker threads (`0` = one per CPU, between 2 and 16).
    pub worker_threads: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            algorithms: vec![CompressionAlgorithm::Zstd, CompressionAlgorithm::Brotli, CompressionAlgorithm::Gzip],
            min_size: 1024,
            level: CompressionLevel::Default,
            content_types: [
                "text/*",
                "application/json",
                "application/*+json",
                "application/javascript",
                "application/xml",
                "application/*+xml",
                "application/wasm",
                "application/x-ndjson",
                "image/svg+xml",
            ]
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
            max_concurrent_encoders: 256,
            offload_threshold: 32 * 1024,
            worker_threads: 0,
        }
    }
}

/// A single backend in a pool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendConfig {
    /// `host:port` or `unix:/path`.
    pub addr: BackendAddr,
    /// Relative weight (≥ 1).
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Circuit breaker: at most this many requests in flight on this backend
    /// (overrides the upstream's `max_inflight`; `None` inherits it).
    #[serde(default)]
    pub max_inflight: Option<u32>,
}

fn default_weight() -> u32 {
    1
}

/// Kind of active health probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HealthKind {
    /// Successful TCP connect.
    Tcp,
    /// HTTP GET returning an acceptable status.
    #[default]
    Http,
}

/// Active health-check settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HealthConfig {
    /// Probe type.
    pub kind: HealthKind,
    /// Request path for HTTP probes.
    pub path: String,
    /// `Host` header for HTTP probes.
    pub host: String,
    /// Time between probes.
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// Probe deadline.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Random jitter as a fraction of `interval` (0.0–1.0).
    pub jitter: f64,
    /// Consecutive successes before an unhealthy backend returns.
    pub healthy_threshold: u32,
    /// Consecutive failures before a backend is marked unhealthy.
    pub unhealthy_threshold: u32,
    /// Lowest acceptable HTTP status.
    pub status_min: u16,
    /// Highest acceptable HTTP status.
    pub status_max: u16,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            kind: HealthKind::Http,
            path: "/".to_owned(),
            host: "velox-health".to_owned(),
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(2),
            jitter: 0.2,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            status_min: 200,
            status_max: 399,
        }
    }
}

/// Passive outlier-detection (circuit-breaking) settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OutlierConfig {
    /// Master switch.
    pub enabled: bool,
    /// Consecutive gateway failures (connect error, timeout, 502/503/504)
    /// that eject a backend.
    pub consecutive_failures: u32,
    /// First ejection duration; doubles on each repeat ejection.
    #[serde(with = "humantime_serde")]
    pub base_ejection_time: Duration,
    /// Cap for the exponential back-off.
    #[serde(with = "humantime_serde")]
    pub max_ejection_time: Duration,
    /// Never eject more than this percentage of the pool.
    pub max_ejection_percent: u32,
}

impl Default for OutlierConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            consecutive_failures: 5,
            base_ejection_time: Duration::from_secs(30),
            max_ejection_time: Duration::from_secs(300),
            max_ejection_percent: 50,
        }
    }
}

/// Upstream connection-pool settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PoolConfig {
    /// Evict idle pooled connections after this long.
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Maximum idle connections kept per backend.
    pub max_idle_per_backend: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self { idle_timeout: Duration::from_secs(60), max_idle_per_backend: 64 }
    }
}

/// What the consistent-hash balancer hashes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum HashOn {
    /// Client IP.
    Ip,
    /// Request path.
    Path,
    /// A request header value (falls back to client IP).
    Header(String),
}

impl FromStr for HashOn {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("ip") {
            Ok(Self::Ip)
        } else if s.eq_ignore_ascii_case("path") {
            Ok(Self::Path)
        } else if let Some(name) = s.strip_prefix("header:") {
            http::HeaderName::from_bytes(name.trim().as_bytes())
                .map(|n| Self::Header(n.as_str().to_owned()))
                .map_err(|_| format!("invalid header name in hash_on `{s}`"))
        } else {
            Err(format!("hash_on must be ip, path or header:<name>, got `{s}`"))
        }
    }
}

impl fmt::Display for HashOn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip => f.write_str("ip"),
            Self::Path => f.write_str("path"),
            Self::Header(h) => write!(f, "header:{h}"),
        }
    }
}

impl TryFrom<String> for HashOn {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<HashOn> for String {
    fn from(value: HashOn) -> Self {
        value.to_string()
    }
}

/// A pool of backends sharing a balancing policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Unique name referenced by routes.
    pub name: String,
    /// Balancing algorithm.
    #[serde(default)]
    pub algorithm: Algorithm,
    /// Hash key for `consistent_hash`.
    #[serde(default = "default_hash_on")]
    pub hash_on: HashOn,
    /// Protocol spoken to the backends.
    #[serde(default)]
    pub protocol: UpstreamProtocol,
    /// Extra attempts on another backend after a retryable failure.
    #[serde(default = "default_retries")]
    pub retries: u32,
    /// Members of the pool.
    pub backends: Vec<BackendConfig>,
    /// Active health checks (omit to disable).
    #[serde(default)]
    pub health: Option<HealthConfig>,
    /// Passive outlier detection.
    #[serde(default)]
    pub outlier: OutlierConfig,
    /// Connection pool tuning.
    #[serde(default)]
    pub pool: PoolConfig,
    /// Default per-backend in-flight cap (circuit breaker). A saturated backend
    /// is skipped by the balancer; when every backend is saturated the request
    /// is answered `503` immediately instead of queueing. `None` = unlimited.
    #[serde(default)]
    pub max_inflight: Option<u32>,
    /// TLS settings for `https://` backends (trust roots, SNI, mTLS client
    /// certificate). Optional: the defaults verify against the public web PKI.
    #[serde(default)]
    pub tls: Option<UpstreamTlsConfig>,
    /// Periodically re-resolve hostname backends and use *every* address they
    /// return (Kubernetes headless services, multi-A records). Omit to keep the
    /// old behaviour: the OS resolves the name on each new connection.
    #[serde(default)]
    pub dns: Option<DnsConfig>,
}

/// Periodic DNS resolution of hostname backends.
///
/// Each hostname backend (`app.svc.cluster.local:8080`) becomes one pool member
/// per resolved address, each with its own health, ejection, `max_inflight` and
/// in-flight accounting. A refresh that returns the same addresses changes
/// nothing; a changed answer adds new members and retires vanished ones
/// *without* touching surviving members or their pooled connections. If a
/// lookup fails or returns nothing, the last good answer stays in use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DnsConfig {
    /// Time between lookups of each hostname.
    #[serde(with = "humantime_serde")]
    pub refresh_interval: Duration,
    /// Deadline for one lookup.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Use at most this many addresses per hostname (lowest first, so every
    /// instance picks the same ones).
    pub max_addrs: usize,
    /// Also use IPv6 (`AAAA`) answers.
    pub ipv6: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self { refresh_interval: Duration::from_secs(30), timeout: Duration::from_secs(5), max_addrs: 32, ipv6: true }
    }
}

/// TLS used to reach `https://` backends.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamTlsConfig {
    /// Name sent as SNI and checked against the backend certificate. Defaults
    /// to the backend's host (which may be an IP, verified against IP SANs).
    pub server_name: Option<String>,
    /// PEM bundle of trusted CA certificates. When set it is the *only* trust
    /// anchor set (private PKI / zero-trust); when absent the bundled Mozilla
    /// roots (`webpki-roots`) are used.
    pub ca_file: Option<PathBuf>,
    /// Do not verify the backend certificate at all. Dangerous: any
    /// on-path attacker can impersonate the backend. Default `false`.
    pub insecure_skip_verify: bool,
    /// PEM client certificate chain presented to the backend (mTLS).
    pub client_cert_file: Option<PathBuf>,
    /// PEM private key for `client_cert_file`.
    pub client_key_file: Option<PathBuf>,
    /// How often the CA / client-certificate files are checked for rotation.
    /// Rotated material applies to new connections without a reload.
    #[serde(with = "humantime_serde")]
    pub reload_interval: Duration,
}

impl Default for UpstreamTlsConfig {
    fn default() -> Self {
        Self {
            server_name: None,
            ca_file: None,
            insecure_skip_verify: false,
            client_cert_file: None,
            client_key_file: None,
            reload_interval: Duration::from_secs(5),
        }
    }
}

fn default_hash_on() -> HashOn {
    HashOn::Ip
}
fn default_retries() -> u32 {
    1
}

/// An L7 route.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Optional stable id (defaults to `route-<index>`).
    #[serde(default)]
    pub name: Option<String>,
    /// Hosts (exact or `*.example.com`); empty matches any host.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Path prefix matched on segment boundaries.
    #[serde(default = "default_prefix")]
    pub path_prefix: String,
    /// Upstream to forward to.
    pub upstream: String,
    /// Remove `path_prefix` before forwarding.
    #[serde(default)]
    pub strip_prefix: bool,
    /// Answer plain-HTTP requests with a 308 redirect to HTTPS.
    ///
    /// The redirect target host is the request's `Host` unless `canonical_host`
    /// is set. A catch-all route (`hosts = []`) must set `canonical_host`,
    /// otherwise any `Host` header would be reflected into `Location` (open
    /// redirect).
    #[serde(default)]
    pub redirect_https: bool,
    /// Fixed host used in the HTTPS redirect `Location` (no port, no wildcard).
    #[serde(default)]
    pub canonical_host: Option<String>,
    /// Per-route rate limit (overrides the global policy; `enabled=false` opts out).
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    /// Headers set on the upstream request.
    #[serde(default)]
    pub request_headers: BTreeMap<String, String>,
    /// Override of `timeouts.upstream_response` for this route.
    #[serde(default, with = "humantime_serde::option")]
    pub timeout: Option<Duration>,
    /// Override of `compression.enabled` for this route.
    #[serde(default)]
    pub compress: Option<bool>,
    /// CORS policy enforced at the edge (preflights answered by Velox).
    #[serde(default)]
    pub cors: Option<CorsConfig>,
    /// Cache `GET`/`HEAD` responses of this route in memory (see `[cache]`).
    /// `cache = {}` turns it on with defaults.
    #[serde(default)]
    pub cache: Option<RouteCacheConfig>,
    /// Extra allow-list for this route; the client must also pass the global
    /// `[security]` lists (a route can only narrow access).
    #[serde(default)]
    pub ip_allow: Vec<IpNet>,
    /// Extra deny-list for this route.
    #[serde(default)]
    pub ip_deny: Vec<IpNet>,
    /// Verify a JSON Web Token at the edge; invalid tokens never reach the backend.
    #[serde(default)]
    pub jwt: Option<JwtConfig>,
}

/// A JWT signature algorithm Velox verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwtAlgorithm {
    /// HMAC-SHA256 with a shared secret.
    HS256,
    /// RSASSA-PKCS1-v1_5 with SHA-256 (RSA keys of 2048–8192 bits).
    RS256,
    /// ECDSA over P-256 with SHA-256.
    ES256,
}

impl JwtAlgorithm {
    /// The `alg` header value.
    pub fn name(self) -> &'static str {
        match self {
            Self::HS256 => "HS256",
            Self::RS256 => "RS256",
            Self::ES256 => "ES256",
        }
    }
}

/// Per-route edge JWT verification.
///
/// Only the listed `algorithms` are accepted (`none` never is), and each token
/// is checked only against keys of the matching type, which closes the classic
/// "verify an HS256 token with the RSA public key as the secret" confusion.
/// `exp` is mandatory by default; `nbf`, `iss` and `aud` are checked when
/// configured / present.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct JwtConfig {
    /// Accepted signature algorithms. `HS256` must be listed explicitly: shared
    /// secrets are opt-in.
    pub algorithms: Vec<JwtAlgorithm>,
    /// Environment variable holding the HS256 secret (at least 32 bytes).
    pub secret_env: Option<String>,
    /// File holding the HS256 secret (one trailing newline is ignored).
    pub secret_file: Option<PathBuf>,
    /// PEM file with one or more `PUBLIC KEY` (SPKI) blocks: RSA or P-256.
    pub public_key_file: Option<PathBuf>,
    /// JWKS document (`{"keys": [...]}`) with RSA / P-256 public keys, selected by `kid`.
    pub jwks_file: Option<PathBuf>,
    /// Required `iss`.
    pub issuer: Option<String>,
    /// Accepted `aud` values (the token needs at least one of them).
    pub audience: Vec<String>,
    /// Clock-skew allowance for `exp` / `nbf`.
    #[serde(with = "humantime_serde")]
    pub leeway: Duration,
    /// Reject tokens without an `exp` claim.
    pub require_exp: bool,
    /// `true`: a missing token is `401`. `false`: a missing token is allowed
    /// (anonymous) but a *present* one must still be valid.
    pub required: bool,
    /// The request header carrying the token.
    pub header: String,
    /// Scheme prefix of that header's value (`Bearer`); empty for a bare token.
    pub scheme: String,
    /// Claims passed to the backend as `X-Jwt-<claim>` headers (strings,
    /// numbers, booleans, or arrays of strings joined with `,`). Any
    /// client-supplied `X-Jwt-*` header is removed on JWT routes.
    pub forward_claims: Vec<String>,
    /// How often key files are checked for rotation.
    #[serde(with = "humantime_serde")]
    pub reload_interval: Duration,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            algorithms: vec![JwtAlgorithm::RS256, JwtAlgorithm::ES256],
            secret_env: None,
            secret_file: None,
            public_key_file: None,
            jwks_file: None,
            issuer: None,
            audience: Vec::new(),
            leeway: Duration::from_secs(30),
            require_exp: true,
            required: true,
            header: "authorization".to_owned(),
            scheme: "Bearer".to_owned(),
            forward_claims: Vec::new(),
            reload_interval: Duration::from_secs(5),
        }
    }
}

/// Sizing of the shared response cache. Which routes use it, and how long
/// their responses live, is decided per route and by the backend's own
/// `Cache-Control`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CacheConfig {
    /// Total bytes the cache may hold (bodies + headers + keys).
    pub max_bytes: u64,
    /// Responses with a larger body are streamed through uncached; this also
    /// bounds what is buffered per in-flight cacheable miss.
    pub max_entry_bytes: u64,
    /// Independent LRU shards (lock granularity). Fixed once the cache exists.
    pub shards: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self { max_bytes: 64 * 1024 * 1024, max_entry_bytes: 1024 * 1024, shards: 16 }
    }
}

/// Per-route cache settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RouteCacheConfig {
    /// Master switch for this route (handy to turn it off without deleting the table).
    pub enabled: bool,
    /// Freshness to assume for a cacheable response that states none
    /// (no `max-age`, `s-maxage` or `Expires`). Without it such responses are
    /// never cached: Velox does not guess lifetimes.
    #[serde(with = "humantime_serde::option")]
    pub default_ttl: Option<Duration>,
    /// Upper bound on how long anything is kept, whatever the backend says.
    #[serde(with = "humantime_serde::option")]
    pub max_ttl: Option<Duration>,
    /// Ignore the query string when forming the cache key (`?utm=…` busting).
    /// Only safe if the backend's answer really does not depend on it.
    pub ignore_query: bool,
    /// Collapse concurrent misses on the same object into one backend fetch
    /// (the "leader"); the others wait for it and share the result. If the
    /// response turns out not to be cacheable, or the leader fails, waiters
    /// simply fetch for themselves.
    pub coalesce: bool,
    /// How long a waiting request will wait for the leader before it fetches
    /// for itself.
    #[serde(with = "humantime_serde")]
    pub coalesce_timeout: Duration,
    /// Serve an entry up to this long past its expiry **immediately** while one
    /// background request refreshes it (RFC 5861 `stale-while-revalidate`).
    /// A response's own `stale-while-revalidate=N` takes precedence; this is the
    /// default for responses that say nothing. Never applied to `must-revalidate`.
    #[serde(with = "humantime_serde::option")]
    pub stale_while_revalidate: Option<Duration>,
    /// Serve an entry up to this long past its expiry when the backend is
    /// failing (connect error, timeout, `500`/`502`/`503`/`504`) (RFC 5861
    /// `stale-if-error`). Same precedence and `must-revalidate` rules.
    #[serde(with = "humantime_serde::option")]
    pub stale_if_error: Option<Duration>,
    /// Serve and store requests that carry a `Cookie` header. Off by default:
    /// a backend that personalises on cookies without saying `Vary: Cookie` or
    /// `private` would otherwise show one visitor's page to another. Turn it on
    /// only for routes whose cacheable responses never depend on cookies.
    pub allow_cookies: bool,
}

impl Default for RouteCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_ttl: None,
            max_ttl: None,
            ignore_query: false,
            coalesce: true,
            coalesce_timeout: Duration::from_secs(10),
            stale_while_revalidate: None,
            stale_if_error: None,
            allow_cookies: false,
        }
    }
}

/// Per-route CORS policy. See [`crate::cors`] for the exact semantics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    /// Allowed origins: `"https://app.example.com"`, `"https://*.example.com"`
    /// (subdomains), or `"*"` (any origin; not with `allow_credentials`).
    pub allow_origins: Vec<String>,
    /// Allowed methods (`"*"` = any).
    #[serde(default = "default_cors_methods")]
    pub allow_methods: Vec<String>,
    /// Allowed request headers (`"*"` = reflect whatever the preflight asks for).
    #[serde(default)]
    pub allow_headers: Vec<String>,
    /// Response headers scripts may read.
    #[serde(default)]
    pub expose_headers: Vec<String>,
    /// Allow cookies / `Authorization` (`Access-Control-Allow-Credentials`).
    #[serde(default)]
    pub allow_credentials: bool,
    /// How long browsers may cache a preflight answer (at most one day).
    #[serde(default, with = "humantime_serde::option")]
    pub max_age: Option<Duration>,
}

fn default_cors_methods() -> Vec<String> {
    vec!["GET".to_owned(), "HEAD".to_owned(), "POST".to_owned()]
}

fn default_prefix() -> String {
    "/".to_owned()
}

/// A raw TCP (L4) proxy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpProxyConfig {
    /// Listen address.
    pub listen: SocketAddr,
    /// Upstream whose backends receive the connections.
    pub upstream: String,
    /// Close connections idle for this long (`None` = never).
    #[serde(default, with = "humantime_serde::option")]
    pub idle_timeout: Option<Duration>,
    /// Expect a PROXY protocol v1/v2 header from `server.proxy_protocol_trusted`
    /// peers and use the client address it carries.
    #[serde(default)]
    pub proxy_protocol: bool,
}

impl Config {
    /// Parse a configuration from TOML text and validate it.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Read, parse and validate a configuration file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io { path: path.to_owned(), source })?;
        Self::from_toml_str(&text)
    }

    /// Effective route id: explicit name or `route-<index>`.
    pub fn route_id(&self, index: usize) -> String {
        self.routes.get(index).and_then(|r| r.name.clone()).unwrap_or_else(|| format!("route-{index}"))
    }

    /// Pure (filesystem-free) semantic validation. Collects every problem.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errs: Vec<String> = Vec::new();
        self.validate_server(&mut errs);
        self.validate_limits(&mut errs);
        self.validate_timeouts(&mut errs);
        self.validate_upstreams(&mut errs);
        self.validate_routes(&mut errs);
        self.validate_misc(&mut errs);
        if errs.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(errs))
        }
    }

    /// Additional checks that touch the filesystem (certificate files).
    pub fn validate_files(&self) -> Result<(), ConfigError> {
        let mut errs = Vec::new();
        for c in &self.tls.certs {
            for p in [&c.cert_file, &c.key_file] {
                if !p.is_file() {
                    errs.push(format!("tls: file {} does not exist", p.display()));
                }
            }
        }
        for (i, r) in self.routes.iter().enumerate() {
            let Some(j) = &r.jwt else { continue };
            for p in [&j.secret_file, &j.public_key_file, &j.jwks_file].into_iter().flatten() {
                if !p.is_file() {
                    errs.push(format!("route `{}`: jwt file {} does not exist", self.route_id(i), p.display()));
                }
            }
        }
        if let Some(p) = &self.tls.client_ca_file {
            if !p.is_file() {
                errs.push(format!("tls: client_ca_file {} does not exist", p.display()));
            }
        }
        for u in &self.upstreams {
            let Some(t) = &u.tls else { continue };
            for p in [&t.ca_file, &t.client_cert_file, &t.client_key_file].into_iter().flatten() {
                if !p.is_file() {
                    errs.push(format!("upstream `{}`: tls file {} does not exist", u.name, p.display()));
                }
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(errs))
        }
    }

    fn validate_server(&self, errs: &mut Vec<String>) {
        let s = &self.server;
        if s.http_addr.is_none() && s.https_addr.is_none() && self.tcp_proxies.is_empty() {
            errs.push("server: configure at least one of http_addr, https_addr or a tcp_proxy".into());
        }
        if s.https_addr.is_some()
            && self.tls.certs.is_empty()
            && !self.tls.self_signed_fallback
            && self.tls.acme.is_none()
        {
            errs.push("tls: https_addr requires `certs`, `self_signed_fallback` or `acme`".into());
        }
        if s.accept_workers == 0 || s.accept_workers > 256 {
            errs.push("server.accept_workers must be within 1..=256".into());
        }
        if s.backlog < 1 {
            errs.push("server.backlog must be positive".into());
        }
        if s.h3 && s.h3_addr.is_some() && s.https_addr.is_none() {
            errs.push("server.h3_addr requires https_addr (TLS material)".into());
        }
        if self.tls.client_auth_required.is_some() && self.tls.client_ca_file.is_none() {
            errs.push("tls.client_auth_required needs tls.client_ca_file (otherwise nothing would be verified)".into());
        }
        if self.tls.client_ca_file.is_some() && s.https_addr.is_none() {
            errs.push(
                "tls.client_ca_file needs https_addr (client certificates are checked on the TLS listeners)".into(),
            );
        }
        if s.proxy_protocol {
            if s.proxy_protocol_trusted.is_empty() {
                errs.push(
                    "server.proxy_protocol requires `proxy_protocol_trusted` (the load balancer addresses allowed to \
                     send a PROXY header); without it any client could forge its address"
                        .into(),
                );
            }
            if s.http_addr.is_none() && s.https_addr.is_none() {
                errs.push("server.proxy_protocol needs `http_addr` or `https_addr`".into());
            }
        }
    }

    fn validate_limits(&self, errs: &mut Vec<String>) {
        let l = &self.limits;
        if l.max_header_bytes < 1024 || l.max_header_bytes > 1024 * 1024 {
            errs.push("limits.max_header_bytes must be within 1KiB..=1MiB".into());
        }
        if l.max_headers == 0 || l.max_headers > crate::sanitize::MAX_PARSE_HEADERS {
            errs.push(format!("limits.max_headers must be within 1..={}", crate::sanitize::MAX_PARSE_HEADERS));
        }
        if l.max_uri_bytes == 0 || l.max_uri_bytes > l.max_header_bytes {
            errs.push("limits.max_uri_bytes must be >0 and <= max_header_bytes".into());
        }
        if l.max_streams_per_connection == 0 {
            errs.push("limits.max_streams_per_connection must be >0".into());
        }
    }

    fn validate_timeouts(&self, errs: &mut Vec<String>) {
        let t = &self.timeouts;
        for (name, d) in [
            ("tls_handshake", t.tls_handshake),
            ("header_read", t.header_read),
            ("idle_keepalive", t.idle_keepalive),
            ("request_body_idle", t.request_body_idle),
            ("upstream_connect", t.upstream_connect),
            ("upstream_response", t.upstream_response),
            ("upstream_body_idle", t.upstream_body_idle),
            ("write_stall", t.write_stall),
        ] {
            if d.is_zero() {
                errs.push(format!("timeouts.{name} must be greater than zero"));
            }
        }
    }

    fn validate_upstreams(&self, errs: &mut Vec<String>) {
        let mut seen = HashSet::new();
        for u in &self.upstreams {
            let n = &u.name;
            if n.is_empty() || !n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
                errs.push(format!("upstream `{n}`: name must be non-empty [A-Za-z0-9_.-]"));
            }
            if !seen.insert(n.as_str()) {
                errs.push(format!("upstream `{n}`: duplicate name"));
            }
            if u.backends.is_empty() {
                errs.push(format!("upstream `{n}`: at least one backend is required"));
            }
            let mut addrs = HashSet::new();
            for b in &u.backends {
                if b.weight == 0 || b.weight > 1000 {
                    errs.push(format!("upstream `{n}`: backend {} weight must be 1..=1000", b.addr));
                }
                if !addrs.insert(b.addr.to_string()) {
                    errs.push(format!("upstream `{n}`: duplicate backend {}", b.addr));
                }
            }
            if let Some(h) = &u.health {
                if h.interval.is_zero() || h.timeout.is_zero() {
                    errs.push(format!("upstream `{n}`: health interval/timeout must be >0"));
                }
                if h.healthy_threshold == 0 || h.unhealthy_threshold == 0 {
                    errs.push(format!("upstream `{n}`: health thresholds must be >=1"));
                }
                if !(0.0..=1.0).contains(&h.jitter) {
                    errs.push(format!("upstream `{n}`: health jitter must be within 0..=1"));
                }
                if h.kind == HealthKind::Http && !h.path.starts_with('/') {
                    errs.push(format!("upstream `{n}`: health path must start with `/`"));
                }
                if h.status_min > h.status_max {
                    errs.push(format!("upstream `{n}`: health status_min > status_max"));
                }
            }
            let o = &u.outlier;
            if o.enabled && (o.consecutive_failures == 0 || o.max_ejection_percent > 100) {
                errs.push(format!("upstream `{n}`: invalid outlier settings"));
            }
            if o.base_ejection_time > o.max_ejection_time {
                errs.push(format!("upstream `{n}`: outlier base_ejection_time > max_ejection_time"));
            }
            if u.retries > 5 {
                errs.push(format!("upstream `{n}`: retries must be <= 5"));
            }
            if u.max_inflight == Some(0) || u.backends.iter().any(|b| b.max_inflight == Some(0)) {
                errs.push(format!("upstream `{n}`: max_inflight must be >= 1 (omit it for no limit)"));
            }
            if let Some(d) = &u.dns {
                if !u.backends.iter().any(|b| b.addr.hostname().is_some()) {
                    errs.push(format!("upstream `{n}`: `dns` is set but no backend uses a host name"));
                }
                if d.refresh_interval < Duration::from_secs(1) {
                    errs.push(format!("upstream `{n}`: dns.refresh_interval must be at least 1s"));
                }
                if d.timeout.is_zero() {
                    errs.push(format!("upstream `{n}`: dns.timeout must be >0"));
                }
                if !(1..=512).contains(&d.max_addrs) {
                    errs.push(format!("upstream `{n}`: dns.max_addrs must be within 1..=512"));
                }
            }
            let has_tls = u.backends.iter().any(|b| matches!(b.addr, BackendAddr::Tls { .. }));
            if let Some(t) = &u.tls {
                if !has_tls {
                    errs.push(format!("upstream `{n}`: `tls` is set but no backend uses https://"));
                }
                if t.client_cert_file.is_some() != t.client_key_file.is_some() {
                    errs.push(format!("upstream `{n}`: tls.client_cert_file and tls.client_key_file go together"));
                }
                if t.insecure_skip_verify && t.ca_file.is_some() {
                    errs.push(format!("upstream `{n}`: tls.ca_file is meaningless with insecure_skip_verify"));
                }
                if t.reload_interval < Duration::from_millis(50) {
                    errs.push(format!("upstream `{n}`: tls.reload_interval must be at least 50ms"));
                }
                if let Some(name) = &t.server_name {
                    if validate_host_pattern(name, true).is_err() || name.starts_with("*.") {
                        errs.push(format!("upstream `{n}`: tls.server_name `{name}` is not a valid host name"));
                    }
                }
            }
        }
    }

    fn validate_routes(&self, errs: &mut Vec<String>) {
        let upstream_names: HashSet<&str> = self.upstreams.iter().map(|u| u.name.as_str()).collect();
        let mut ids = HashSet::new();
        for (i, r) in self.routes.iter().enumerate() {
            let id = self.route_id(i);
            if !ids.insert(id.clone()) {
                errs.push(format!("route `{id}`: duplicate name"));
            }
            if !upstream_names.contains(r.upstream.as_str()) {
                errs.push(format!("route `{id}`: unknown upstream `{}`", r.upstream));
            }
            if !r.path_prefix.starts_with('/') {
                errs.push(format!("route `{id}`: path_prefix must start with `/`"));
            }
            if r.redirect_https && r.hosts.is_empty() && r.canonical_host.is_none() {
                errs.push(format!(
                    "route `{id}`: `redirect_https` on a catch-all route (no `hosts`) would reflect arbitrary Host \
                     headers into the redirect (open redirect); set `hosts` or `canonical_host`"
                ));
            }
            if let Some(ch) = &r.canonical_host {
                if ch.starts_with("*.") || validate_host_pattern(ch, self.security.allow_underscores_in_host).is_err() {
                    errs.push(format!("route `{id}`: canonical_host `{ch}` must be a plain host name"));
                }
            }
            for h in &r.hosts {
                if let Err(e) = validate_host_pattern(h, self.security.allow_underscores_in_host) {
                    errs.push(format!("route `{id}`: host `{h}`: {e}"));
                }
            }
            for (k, v) in &r.request_headers {
                if http::HeaderName::from_bytes(k.as_bytes()).is_err() || http::HeaderValue::from_str(v).is_err() {
                    errs.push(format!("route `{id}`: invalid request header `{k}`"));
                }
            }
            if let Some(rl) = &r.rate_limit {
                validate_rate_limit(&format!("route `{id}`"), rl, errs);
            }
            if r.timeout.is_some_and(|t| t.is_zero()) {
                errs.push(format!("route `{id}`: timeout must be >0"));
            }
            if let Some(c) = &r.cors {
                validate_cors(&format!("route `{id}`"), c, errs);
            }
            if let Some(j) = &r.jwt {
                validate_jwt(&format!("route `{id}`"), j, errs);
                // Requests carrying `Authorization` never touch the cache; a token in
                // any other header would, and one holder's response could then be
                // served to another.
                if r.cache.as_ref().is_some_and(|c| c.enabled) && !j.header.eq_ignore_ascii_case("authorization") {
                    errs.push(format!(
                        "route `{id}`: caching a route whose jwt.header is `{}` could share one token holder's \
                         responses with another; use the Authorization header or disable the cache",
                        j.header
                    ));
                }
            }
            if let Some(c) = &r.cache {
                let year = Duration::from_secs(365 * 86_400);
                for (name, v) in [("default_ttl", c.default_ttl), ("max_ttl", c.max_ttl)] {
                    if v.is_some_and(|d| d.is_zero() || d > year) {
                        errs.push(format!("route `{id}`: cache.{name} must be within 1s..=1y"));
                    }
                }
                if c.default_ttl.zip(c.max_ttl).is_some_and(|(d, m)| d > m) {
                    errs.push(format!("route `{id}`: cache.default_ttl exceeds cache.max_ttl"));
                }
                if !(Duration::from_millis(100)..=Duration::from_secs(300)).contains(&c.coalesce_timeout) {
                    errs.push(format!("route `{id}`: cache.coalesce_timeout must be within 100ms..=5m"));
                }
                for (name, v) in
                    [("stale_while_revalidate", c.stale_while_revalidate), ("stale_if_error", c.stale_if_error)]
                {
                    if v.is_some_and(|d| d > Duration::from_secs(86_400)) {
                        errs.push(format!("route `{id}`: cache.{name} must be at most 24h"));
                    }
                }
            }
        }
    }

    fn validate_misc(&self, errs: &mut Vec<String>) {
        if let Some(rl) = &self.rate_limit {
            validate_rate_limit("rate_limit", rl, errs);
        }
        if let Some(addr) = self.admin.addr {
            if !addr.ip().is_loopback() {
                errs.push(format!("admin.addr {addr} must be a loopback address (the admin API is localhost-only)"));
            }
        }
        for (k, v) in &self.security.response_headers {
            if http::HeaderName::from_bytes(k.as_bytes()).is_err() || http::HeaderValue::from_str(v).is_err() {
                errs.push(format!("security.response_headers: invalid header `{k}`"));
            }
        }
        for (i, c) in self.tls.certs.iter().enumerate() {
            for n in &c.server_names {
                if let Err(e) = validate_host_pattern(n, self.security.allow_underscores_in_host) {
                    errs.push(format!("tls.certs[{i}]: server name `{n}`: {e}"));
                }
            }
        }
        if let Some(a) = &self.tls.acme {
            if a.domains.is_empty() {
                errs.push("tls.acme.domains must not be empty".into());
            }
            if a.domains.iter().any(|d| d.starts_with("*.")) {
                errs.push("tls.acme: wildcard domains need DNS-01, which is not supported".into());
            }
        }
        for t in &self.tcp_proxies {
            match self.upstreams.iter().find(|u| u.name == t.upstream) {
                None => errs.push(format!("tcp_proxy {}: unknown upstream `{}`", t.listen, t.upstream)),
                Some(u) if u.backends.iter().any(|b| matches!(b.addr, BackendAddr::Tls { .. })) => errs.push(format!(
                    "tcp_proxy {}: upstream `{}` has https:// backends; L4 proxies relay bytes and do not originate TLS",
                    t.listen, t.upstream
                )),
                Some(_) => {}
            }
            if t.proxy_protocol && self.server.proxy_protocol_trusted.is_empty() {
                errs.push(format!("tcp_proxy {}: proxy_protocol requires server.proxy_protocol_trusted", t.listen));
            }
        }
        let cc = &self.cache;
        if !(1..=256).contains(&cc.shards) {
            errs.push("cache.shards must be within 1..=256".into());
        }
        if cc.max_entry_bytes < 1024 {
            errs.push("cache.max_entry_bytes must be at least 1 KiB".into());
        }
        if cc.shards > 0 && cc.max_bytes / (cc.shards as u64) < cc.max_entry_bytes {
            errs.push(
                "cache.max_bytes / cache.shards must be at least cache.max_entry_bytes (each shard must be able to hold one maximum-size entry)"
                    .into(),
            );
        }
        let c = &self.compression;
        if c.enabled || !c.algorithms.is_empty() {
            let mut seen = HashSet::new();
            if c.enabled && c.algorithms.is_empty() {
                errs.push("compression.algorithms must not be empty when compression is enabled".into());
            }
            if c.algorithms.iter().any(|a| !seen.insert(*a)) {
                errs.push("compression.algorithms lists an encoding twice".into());
            }
        }
        if c.max_concurrent_encoders == 0 {
            errs.push("compression.max_concurrent_encoders must be >= 1".into());
        }
        if !(1024..=1024 * 1024).contains(&c.offload_threshold) {
            errs.push("compression.offload_threshold must be within 1 KiB..=1 MiB".into());
        }
        if c.worker_threads > 256 {
            errs.push("compression.worker_threads must be <= 256".into());
        }
        for ct in &c.content_types {
            let ok = ct.split_once('/').is_some_and(|(t, sub)| {
                !t.is_empty()
                    && !sub.is_empty()
                    && !t.contains('*')
                    && sub.matches('*').count() <= 1
                    && ct.bytes().all(|b| b.is_ascii_alphanumeric() || b"/*+-.".contains(&b))
            });
            if !ok {
                errs.push(format!("compression.content_types: `{ct}` must look like `type/subtype` or `type/*`"));
            }
        }
        if self.telemetry.log_level.trim().is_empty() {
            errs.push("telemetry.log_level must not be empty".into());
        }
    }
}

fn validate_jwt(ctx: &str, j: &JwtConfig, errs: &mut Vec<String>) {
    use JwtAlgorithm::{ES256, HS256, RS256};
    if j.algorithms.is_empty() {
        errs.push(format!("{ctx}: jwt.algorithms must not be empty"));
    }
    let wants_secret = j.algorithms.contains(&HS256);
    let wants_public = j.algorithms.iter().any(|a| matches!(a, RS256 | ES256));
    let has_secret = j.secret_env.is_some() || j.secret_file.is_some();
    let has_public = j.public_key_file.is_some() || j.jwks_file.is_some();
    if j.secret_env.is_some() && j.secret_file.is_some() {
        errs.push(format!("{ctx}: set only one of jwt.secret_env and jwt.secret_file"));
    }
    if wants_secret && !has_secret {
        errs.push(format!("{ctx}: jwt accepts HS256 but has no secret_env / secret_file"));
    }
    if wants_public && !has_public {
        errs.push(format!("{ctx}: jwt accepts RS256/ES256 but has no public_key_file / jwks_file"));
    }
    // Key material that no listed algorithm can use is a configuration mistake
    // (and, for a secret, a tempting leftover): refuse it.
    if has_secret && !wants_secret {
        errs.push(format!("{ctx}: jwt has a secret but HS256 is not in jwt.algorithms"));
    }
    if has_public && !wants_public {
        errs.push(format!("{ctx}: jwt has public keys but neither RS256 nor ES256 is in jwt.algorithms"));
    }
    if http::HeaderName::from_bytes(j.header.as_bytes()).is_err() {
        errs.push(format!("{ctx}: jwt.header `{}` is not a valid header name", j.header));
    }
    if j.scheme.contains(char::is_whitespace) {
        errs.push(format!("{ctx}: jwt.scheme must be a single token (or empty)"));
    }
    if j.leeway > Duration::from_secs(300) {
        errs.push(format!("{ctx}: jwt.leeway must be at most 5m"));
    }
    if j.reload_interval < Duration::from_millis(50) {
        errs.push(format!("{ctx}: jwt.reload_interval must be at least 50ms"));
    }
    for c in &j.forward_claims {
        let ok = !c.is_empty() && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !ok {
            errs.push(format!("{ctx}: jwt.forward_claims entry `{c}` must be letters, digits, `_` or `-`"));
        }
    }
    if j.issuer.as_deref().is_some_and(str::is_empty) || j.audience.iter().any(String::is_empty) {
        errs.push(format!("{ctx}: jwt.issuer / jwt.audience entries must not be empty"));
    }
}

fn validate_cors(ctx: &str, c: &CorsConfig, errs: &mut Vec<String>) {
    if c.allow_origins.is_empty() {
        errs.push(format!("{ctx}: cors.allow_origins must not be empty"));
    }
    for o in &c.allow_origins {
        if !crate::cors::valid_origin_pattern(o) {
            errs.push(format!(
                "{ctx}: cors origin `{o}` must be `*`, `null`, `scheme://host[:port]` or `scheme://*.host[:port]`"
            ));
        }
    }
    if c.allow_credentials && c.allow_origins.iter().any(|o| o == "*") {
        errs.push(format!(
            "{ctx}: cors.allow_credentials cannot be combined with allow_origins = [\"*\"] (browsers refuse it, and it \
             would let any site make credentialed requests); list the origins instead"
        ));
    }
    for m in c.allow_methods.iter().filter(|m| *m != "*") {
        if http::Method::from_bytes(m.as_bytes()).is_err() {
            errs.push(format!("{ctx}: cors method `{m}` is not a valid HTTP method"));
        }
    }
    if c.allow_methods.is_empty() {
        errs.push(format!("{ctx}: cors.allow_methods must not be empty"));
    }
    for h in c.allow_headers.iter().chain(&c.expose_headers).filter(|h| *h != "*") {
        if http::HeaderName::from_bytes(h.as_bytes()).is_err() {
            errs.push(format!("{ctx}: cors header `{h}` is not a valid header name"));
        }
    }
    if c.max_age.is_some_and(|d| d > Duration::from_secs(86_400)) {
        errs.push(format!("{ctx}: cors.max_age must be at most 24h"));
    }
}

fn validate_rate_limit(ctx: &str, rl: &RateLimitConfig, errs: &mut Vec<String>) {
    if rl.enabled && (!rl.requests_per_second.is_finite() || rl.requests_per_second <= 0.0 || rl.burst == 0) {
        errs.push(format!("{ctx}: rate limit needs requests_per_second > 0 and burst >= 1"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [server]
        http_addr = "127.0.0.1:8080"
        [[upstream]]
        name = "app"
        backends = [{ addr = "127.0.0.1:3000" }]
        [[route]]
        upstream = "app"
    "#;

    #[test]
    fn parses_minimal_config() {
        let cfg = Config::from_toml_str(MINIMAL).unwrap();
        assert_eq!(cfg.upstreams.len(), 1);
        assert_eq!(cfg.routes[0].path_prefix, "/");
        assert_eq!(cfg.route_id(0), "route-0");
    }

    #[test]
    fn rejects_unknown_fields() {
        let bad = format!("{MINIMAL}\n[bogus]\nx = 1\n");
        assert!(matches!(Config::from_toml_str(&bad), Err(ConfigError::Parse(_))));
    }

    #[test]
    fn rejects_unknown_upstream_reference() {
        let bad = MINIMAL.replace("upstream = \"app\"\n    ", "upstream = \"nope\"\n    ");
        let err = Config::from_toml_str(&bad).unwrap_err().to_string();
        assert!(err.contains("unknown upstream"), "{err}");
    }

    #[test]
    fn admin_must_be_loopback() {
        let bad = format!("{MINIMAL}\n[admin]\naddr = \"0.0.0.0:9901\"\n");
        let err = Config::from_toml_str(&bad).unwrap_err().to_string();
        assert!(err.contains("loopback"), "{err}");
    }

    #[test]
    fn backend_addr_round_trip() {
        for s in ["127.0.0.1:80", "app.internal:8080", "[::1]:9000", "unix:/run/app.sock"] {
            let a: BackendAddr = s.parse().unwrap();
            assert_eq!(a.to_string(), s);
        }
        assert!("nohost".parse::<BackendAddr>().is_err());
        assert!("host:99999".parse::<BackendAddr>().is_err());
        assert!("bad host:80".parse::<BackendAddr>().is_err());
    }

    #[test]
    fn durations_parse_humantime() {
        let text = format!("{MINIMAL}\n[timeouts]\nheader_read = \"2s\"\nupstream_connect = \"500ms\"\n");
        let cfg = Config::from_toml_str(&text).unwrap();
        assert_eq!(cfg.timeouts.header_read, Duration::from_secs(2));
        assert_eq!(cfg.timeouts.upstream_connect, Duration::from_millis(500));
    }

    #[test]
    fn catch_all_https_redirect_needs_a_canonical_host() {
        // Regression: `redirect_https` on a catch-all route reflected any Host.
        let bad =
            MINIMAL.replace("upstream = \"app\"\n    ", "upstream = \"app\"\n        redirect_https = true\n    ");
        let err = Config::from_toml_str(&bad).unwrap_err().to_string();
        assert!(err.contains("open redirect"), "{err}");
        let ok =
            bad.replace("redirect_https = true", "redirect_https = true\n        canonical_host = \"example.com\"");
        assert!(Config::from_toml_str(&ok).is_ok());
        let with_hosts =
            bad.replace("redirect_https = true", "redirect_https = true\n        hosts = [\"*.example.com\"]");
        assert!(Config::from_toml_str(&with_hosts).is_ok(), "explicit hosts constrain what can be reflected");
        let wildcard =
            bad.replace("redirect_https = true", "redirect_https = true\n        canonical_host = \"*.example.com\"");
        assert!(Config::from_toml_str(&wildcard).is_err());
    }

    #[test]
    fn https_requires_tls_material() {
        let text = MINIMAL.replace("http_addr = \"127.0.0.1:8080\"", "https_addr = \"127.0.0.1:8443\"");
        assert!(Config::from_toml_str(&text).is_err());
        let ok = format!("{text}\n[tls]\nself_signed_fallback = true\n");
        assert!(Config::from_toml_str(&ok).is_ok());
    }

    #[test]
    fn key_source_parsing() {
        assert_eq!("ip".parse::<KeySource>().unwrap(), KeySource::Ip);
        assert_eq!("header:X-Api-Key".parse::<KeySource>().unwrap(), KeySource::Header("x-api-key".into()));
        assert!("cookie:x".parse::<KeySource>().is_err());
    }

    #[test]
    fn config_serde_round_trip_json() {
        let cfg = Config::from_toml_str(MINIMAL).unwrap();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn https_backend_addresses_parse_and_round_trip() {
        let a: BackendAddr = "https://app.internal:8443".parse().unwrap();
        assert_eq!(a, BackendAddr::Tls { host: "app.internal".into(), port: 8443 });
        assert_eq!(a.to_string(), "https://app.internal:8443");
        // Default ports, IPv6, and `http://` normalising to the plain variant.
        assert_eq!("https://app.internal".parse::<BackendAddr>().unwrap().to_string(), "https://app.internal:443");
        assert_eq!("https://[::1]".parse::<BackendAddr>().unwrap().to_string(), "https://[::1]:443");
        assert_eq!("https://[::1]:9443".parse::<BackendAddr>().unwrap().to_string(), "https://[::1]:9443");
        assert_eq!("http://app.internal".parse::<BackendAddr>().unwrap().to_string(), "app.internal:80");
        for bad in ["https://", "https://:443", "https://a/b", "https://a b:1", "https://a:99999", "ftp://a:1", "a"] {
            assert!(bad.parse::<BackendAddr>().is_err(), "{bad}");
        }
        // Serde uses the same text form.
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "\"https://app.internal:8443\"");
        assert_eq!(serde_json::from_str::<BackendAddr>(&json).unwrap(), a);
    }

    #[test]
    fn upstream_tls_and_inflight_validation() {
        let base = |upstream_extra: &str, backend: &str| {
            format!(
                "[server]\nhttp_addr = \"127.0.0.1:8080\"\n[[upstream]]\nname = \"app\"\n{upstream_extra}\n\
                 backends = [{{ addr = \"{backend}\" }}]\n[[route]]\nupstream = \"app\"\n"
            )
        };
        assert!(Config::from_toml_str(&base("", "https://127.0.0.1:8443")).is_ok());
        let err = |text: String| Config::from_toml_str(&text).unwrap_err().to_string();
        // A `tls` table is pointless without an https:// backend.
        assert!(err(base("tls = {}", "127.0.0.1:80")).contains("no backend uses https://"));
        // mTLS needs both halves; skip-verify and a CA are contradictory.
        assert!(err(base("tls = { client_cert_file = \"c.pem\" }", "https://h:1")).contains("go together"));
        assert!(err(base("tls = { insecure_skip_verify = true, ca_file = \"ca.pem\" }", "https://h:1"))
            .contains("meaningless"));
        assert!(err(base("tls = { server_name = \"bad name\" }", "https://h:1")).contains("server_name"));
        // Verification is on unless explicitly disabled.
        let cfg = Config::from_toml_str(&base("tls = { server_name = \"svc.internal\" }", "https://h:1")).unwrap();
        assert!(!cfg.upstreams[0].tls.as_ref().unwrap().insecure_skip_verify);
        // Caps: positive, per upstream or per backend.
        assert!(err(base("max_inflight = 0", "127.0.0.1:80")).contains("max_inflight"));
        assert!(Config::from_toml_str(&base("max_inflight = 10", "127.0.0.1:80")).is_ok());
        let per_backend = base("", "127.0.0.1:80")
            .replace("{ addr = \"127.0.0.1:80\" }", "{ addr = \"127.0.0.1:80\", max_inflight = 0 }");
        assert!(err(per_backend).contains("max_inflight"));
        // validate_files catches missing PEMs.
        let cfg = Config::from_toml_str(&base("tls = { ca_file = \"/nonexistent/ca.pem\" }", "https://h:1")).unwrap();
        assert!(cfg.validate_files().unwrap_err().to_string().contains("/nonexistent/ca.pem"));
        // L4 proxies cannot originate TLS.
        let l4 =
            format!("{}\n[[tcp_proxy]]\nlisten = \"127.0.0.1:9000\"\nupstream = \"app\"\n", base("", "https://h:1"));
        assert!(err(l4).contains("do not originate TLS"));
    }

    #[test]
    fn proxy_protocol_requires_an_explicit_trust_list() {
        let off = MINIMAL.to_owned();
        assert!(!Config::from_toml_str(&off).unwrap().server.proxy_protocol);
        let no_trust = MINIMAL.replace("[server]", "[server]\nproxy_protocol = true");
        let e = Config::from_toml_str(&no_trust).unwrap_err().to_string();
        assert!(e.contains("proxy_protocol_trusted") && e.contains("forge"), "{e}");
        let ok = MINIMAL.replace(
            "[server]",
            "[server]\nproxy_protocol = true\nproxy_protocol_trusted = [\"10.0.0.0/8\", \"::1/128\"]",
        );
        let cfg = Config::from_toml_str(&ok).unwrap();
        assert_eq!(cfg.server.proxy_protocol_trusted.len(), 2);
        // L4 listeners reuse the same trust list.
        let l4 = format!(
            "{MINIMAL}\n[[tcp_proxy]]\nlisten = \"127.0.0.1:9000\"\nupstream = \"app\"\nproxy_protocol = true\n"
        );
        assert!(Config::from_toml_str(&l4).unwrap_err().to_string().contains("proxy_protocol_trusted"));
    }

    #[test]
    fn compression_config_defaults_and_validation() {
        let cfg = Config::from_toml_str(MINIMAL).unwrap();
        assert!(!cfg.compression.enabled, "compression is opt-in");
        assert_eq!(cfg.compression.algorithms[0], CompressionAlgorithm::Zstd);
        let on = format!("{MINIMAL}\n[compression]\nenabled = true\nalgorithms = [\"br\", \"gzip\"]\nmin_size = 256\nlevel = \"fast\"\n");
        let cfg = Config::from_toml_str(&on).unwrap();
        assert_eq!(cfg.compression.algorithms, [CompressionAlgorithm::Brotli, CompressionAlgorithm::Gzip]);
        assert_eq!(cfg.compression.level, CompressionLevel::Fast);
        let err = |extra: &str| {
            Config::from_toml_str(&format!("{MINIMAL}\n[compression]\n{extra}\n")).unwrap_err().to_string()
        };
        assert!(err("enabled = true\nalgorithms = []").contains("must not be empty"));
        assert!(err("algorithms = [\"gzip\", \"gzip\"]").contains("twice"));
        assert!(err("content_types = [\"nonsense\"]").contains("content_types"));
        assert!(err("content_types = [\"*/json\"]").contains("content_types"));
        assert!(Config::from_toml_str(&format!(
            "{MINIMAL}\n[compression]\ncontent_types = [\"application/*+json\", \"text/*\"]\n"
        ))
        .is_ok());
        // Per-route override.
        let route = MINIMAL.replace("upstream = \"app\"\n    ", "upstream = \"app\"\n        compress = true\n    ");
        assert_eq!(Config::from_toml_str(&route).unwrap().routes[0].compress, Some(true));
    }

    #[test]
    fn compression_runtime_limits_have_safe_defaults_and_bounds() {
        let cfg = Config::from_toml_str(MINIMAL).unwrap();
        let c = &cfg.compression;
        assert_eq!((c.max_concurrent_encoders, c.offload_threshold, c.worker_threads), (256, 32 * 1024, 0));
        let ok = format!(
            "{MINIMAL}\n[compression]\nmax_concurrent_encoders = 8\noffload_threshold = 65536\nworker_threads = 4\n"
        );
        let c = Config::from_toml_str(&ok).unwrap().compression;
        assert_eq!((c.max_concurrent_encoders, c.offload_threshold, c.worker_threads), (8, 65_536, 4));
        let err = |extra: &str| {
            Config::from_toml_str(&format!("{MINIMAL}\n[compression]\n{extra}\n")).unwrap_err().to_string()
        };
        assert!(err("max_concurrent_encoders = 0").contains("max_concurrent_encoders"));
        assert!(err("offload_threshold = 10").contains("offload_threshold"));
        assert!(err("offload_threshold = 99999999").contains("offload_threshold"));
        assert!(err("worker_threads = 1000").contains("worker_threads"));
    }

    #[test]
    fn cors_and_traceparent_config_validation() {
        // `[route.cors]` attaches to the `[[route]]` entry MINIMAL ends with.
        let text = |cors: &str| format!("{MINIMAL}\n[route.cors]\n{cors}\n");
        let ok = Config::from_toml_str(&text(
            "allow_origins = [\"https://a.test\", \"https://*.b.test:8443\"]\nmax_age = \"1h\"",
        ));
        let cfg = ok.unwrap();
        let c = cfg.routes[0].cors.as_ref().unwrap();
        assert_eq!(c.allow_methods, ["GET", "HEAD", "POST"], "safe defaults");
        assert!(!c.allow_credentials);
        assert!(!cfg.telemetry.traceparent, "trace propagation is opt-in");
        assert!(
            Config::from_toml_str(&format!("{MINIMAL}\n[telemetry]\ntraceparent = true\n"))
                .unwrap()
                .telemetry
                .traceparent
        );
        let err = |cors: &str| Config::from_toml_str(&text(cors)).unwrap_err().to_string();
        assert!(err("allow_origins = []").contains("must not be empty"));
        assert!(err("allow_origins = [\"a.test\"]").contains("cors origin"));
        assert!(err("allow_origins = [\"https://*\"]").contains("cors origin"));
        assert!(err("allow_origins = [\"*\"]\nallow_credentials = true").contains("allow_credentials"));
        assert!(err("allow_origins = [\"https://a.test\"]\nallow_methods = [\"GE T\"]").contains("method"));
        assert!(err("allow_origins = [\"https://a.test\"]\nallow_headers = [\"bad header\"]").contains("header"));
        assert!(err("allow_origins = [\"https://a.test\"]\nmax_age = \"48h\"").contains("24h"));
        // `*` in methods/headers is allowed, and credentials with an explicit list is fine.
        assert!(Config::from_toml_str(&text("allow_origins = [\"https://a.test\"]\nallow_credentials = true\nallow_methods = [\"*\"]\nallow_headers = [\"*\"]")).is_ok());
    }

    #[test]
    fn dns_config_validation() {
        let base = |extra: &str, backend: &str| {
            format!(
                "[server]\nhttp_addr = \"127.0.0.1:8080\"\n[[upstream]]\nname = \"app\"\n{extra}\nbackends = [{{ addr = \"{backend}\" }}]\n[[route]]\nupstream = \"app\"\n"
            )
        };
        let c = Config::from_toml_str(&base(
            "dns = { refresh_interval = \"10s\", max_addrs = 8, ipv6 = false }",
            "svc.internal:8080",
        ))
        .unwrap();
        let d = c.upstreams[0].dns.as_ref().unwrap();
        assert_eq!((d.refresh_interval, d.max_addrs, d.ipv6), (Duration::from_secs(10), 8, false));
        assert_eq!(DnsConfig::default().refresh_interval, Duration::from_secs(30));
        let err = |extra: &str, backend: &str| Config::from_toml_str(&base(extra, backend)).unwrap_err().to_string();
        assert!(err("dns = {}", "10.0.0.1:80").contains("no backend uses a host name"));
        assert!(err("dns = {}", "unix:/run/a.sock").contains("no backend uses a host name"));
        assert!(err("dns = { refresh_interval = \"100ms\" }", "svc:80").contains("refresh_interval"));
        assert!(err("dns = { max_addrs = 0 }", "svc:80").contains("max_addrs"));
        assert!(err("dns = { max_addrs = 9999 }", "svc:80").contains("max_addrs"));
        assert!(err("dns = { timeout = \"0s\" }", "svc:80").contains("timeout"));
        // Hostname detection.
        assert_eq!("svc.internal:80".parse::<BackendAddr>().unwrap().hostname(), Some("svc.internal"));
        assert_eq!("https://svc:443".parse::<BackendAddr>().unwrap().hostname(), Some("svc"));
        assert_eq!("10.0.0.1:80".parse::<BackendAddr>().unwrap().hostname(), None);
        assert_eq!("[::1]:80".parse::<BackendAddr>().unwrap().hostname(), None);
        assert_eq!("unix:/x".parse::<BackendAddr>().unwrap().hostname(), None);
    }

    #[test]
    fn cache_config_defaults_and_validation() {
        let cfg = Config::from_toml_str(MINIMAL).unwrap();
        assert_eq!((cfg.cache.max_bytes, cfg.cache.max_entry_bytes, cfg.cache.shards), (64 << 20, 1 << 20, 16));
        assert!(cfg.routes[0].cache.is_none(), "caching is opt-in per route");
        let route = |cache: &str| {
            MINIMAL.replace("upstream = \"app\"\n    ", &format!("upstream = \"app\"\n        cache = {cache}\n    "))
        };
        let rc = Config::from_toml_str(&route("{}")).unwrap().routes[0].cache.clone().unwrap();
        assert!(rc.enabled && rc.default_ttl.is_none() && !rc.ignore_query && !rc.allow_cookies, "safe defaults");
        let rc = Config::from_toml_str(&route("{ default_ttl = \"30s\", max_ttl = \"5m\", ignore_query = true }"))
            .unwrap()
            .routes[0]
            .cache
            .clone()
            .unwrap();
        assert_eq!(
            (rc.default_ttl, rc.max_ttl, rc.ignore_query),
            (Some(Duration::from_secs(30)), Some(Duration::from_secs(300)), true)
        );
        let err = |c: &str| Config::from_toml_str(&route(c)).unwrap_err().to_string();
        assert!(err("{ default_ttl = \"0s\" }").contains("default_ttl"));
        assert!(err("{ max_ttl = \"400d\" }").contains("max_ttl"));
        assert!(err("{ default_ttl = \"10m\", max_ttl = \"1m\" }").contains("exceeds"));
        assert!(err("{ nope = 1 }").contains("unknown field"));
        let global = |g: &str| Config::from_toml_str(&format!("{MINIMAL}\n[cache]\n{g}\n")).unwrap_err().to_string();
        assert!(global("shards = 0").contains("shards"));
        assert!(global("shards = 1000").contains("shards"));
        assert!(global("max_entry_bytes = 10").contains("max_entry_bytes"));
        assert!(global("max_bytes = 1000000\nmax_entry_bytes = 900000\nshards = 4").contains("one maximum-size entry"));
        assert!(Config::from_toml_str(&format!(
            "{MINIMAL}\n[cache]\nmax_bytes = 4194304\nmax_entry_bytes = 1048576\nshards = 4\n"
        ))
        .is_ok());
        // A disabled table leaves the route uncached; an enabled one compiles into the route.
        let live = |text: String| {
            let state = crate::SharedState::new(Config::from_toml_str(&text).unwrap()).unwrap();
            let snap = state.load();
            snap.router.find("any", "/").unwrap().cache.clone()
        };
        assert!(live(route("{ enabled = false }")).is_none());
        assert!(live(route("{ default_ttl = \"9s\" }")).is_some_and(|c| c.default_ttl == Some(Duration::from_secs(9))));
    }

    #[test]
    fn ip_lists_parse_globally_and_per_route() {
        let cfg = Config::from_toml_str(MINIMAL).unwrap();
        assert!(cfg.security.ip_allow.is_empty() && cfg.security.ip_deny.is_empty(), "open by default");
        let text = format!("{MINIMAL}\nip_allow = [\"10.0.0.0/8\", \"2001:db8::/32\"]\nip_deny = [\"10.6.0.0/16\"]\n")
            .replace("\n[server]", "\n[server]"); // (route-level keys are appended to the last table)
        let cfg = Config::from_toml_str(&text).unwrap();
        assert_eq!((cfg.routes[0].ip_allow.len(), cfg.routes[0].ip_deny.len()), (2, 1));
        let sec = format!("{MINIMAL}\n[security]\nip_deny = [\"192.0.2.0/24\"]\n");
        assert_eq!(Config::from_toml_str(&sec).unwrap().security.ip_deny.len(), 1);
        // A malformed CIDR is a parse error, not a silently ignored rule.
        assert!(Config::from_toml_str(&format!("{MINIMAL}\n[security]\nip_deny = [\"10.0.0.0/33\"]\n")).is_err());
        assert!(Config::from_toml_str(&format!("{MINIMAL}\n[security]\nip_allow = [\"not-an-ip\"]\n")).is_err());
    }

    #[test]
    fn jwt_config_defaults_and_validation() {
        let text = |jwt: &str| format!("{MINIMAL}\n[route.jwt]\n{jwt}\n");
        let d = JwtConfig::default();
        assert_eq!(d.algorithms, [JwtAlgorithm::RS256, JwtAlgorithm::ES256], "shared secrets are opt-in");
        assert!(d.require_exp && d.required);
        assert_eq!(
            (d.header.as_str(), d.scheme.as_str(), d.leeway),
            ("authorization", "Bearer", Duration::from_secs(30))
        );
        assert!(Config::from_toml_str(MINIMAL).unwrap().routes[0].jwt.is_none(), "off unless configured");

        let ok = Config::from_toml_str(&text(
            "public_key_file = \"k.pem\"\naudience = [\"api\"]\nforward_claims = [\"sub\", \"tenant_id\"]",
        ))
        .unwrap();
        assert_eq!(ok.routes[0].jwt.as_ref().unwrap().audience, ["api"]);
        assert!(Config::from_toml_str(&text("algorithms = [\"HS256\"]\nsecret_env = \"JWT_SECRET\"")).is_ok());
        assert!(Config::from_toml_str(&text(
            "algorithms = [\"HS256\", \"ES256\"]\nsecret_file = \"s\"\njwks_file = \"j.json\""
        ))
        .is_ok());

        let err = |jwt: &str| Config::from_toml_str(&text(jwt)).unwrap_err().to_string();
        assert!(err("").contains("no public_key_file / jwks_file"), "RS256/ES256 need public keys");
        assert!(err("algorithms = [\"HS256\"]").contains("no secret_env / secret_file"));
        assert!(err("algorithms = []").contains("must not be empty"));
        assert!(err("algorithms = [\"none\"]").contains("unknown variant"), "no `none`, ever");
        assert!(err("algorithms = [\"HS384\"]\nsecret_env = \"X\"").contains("unknown variant"));
        // Key material that nothing listed can use is a mistake.
        assert!(err("public_key_file = \"k\"\nsecret_env = \"X\"").contains("HS256 is not in"));
        assert!(
            err("algorithms = [\"HS256\"]\nsecret_env = \"X\"\njwks_file = \"j\"").contains("neither RS256 nor ES256")
        );
        assert!(err("algorithms = [\"HS256\"]\nsecret_env = \"X\"\nsecret_file = \"s\"").contains("only one of"));
        assert!(err("public_key_file = \"k\"\nheader = \"bad header\"").contains("jwt.header"));
        assert!(err("public_key_file = \"k\"\nscheme = \"Bearer token\"").contains("jwt.scheme"));
        assert!(err("public_key_file = \"k\"\nleeway = \"1h\"").contains("leeway"));
        assert!(err("public_key_file = \"k\"\nforward_claims = [\"a b\"]").contains("forward_claims"));
        assert!(err("public_key_file = \"k\"\nissuer = \"\"").contains("must not be empty"));
        assert!(err("public_key_file = \"k\"\nbogus = 1").contains("unknown field"));
        // Files are checked by validate_files.
        let cfg = Config::from_toml_str(&text("public_key_file = \"/nonexistent/k.pem\"")).unwrap();
        assert!(cfg.validate_files().unwrap_err().to_string().contains("/nonexistent/k.pem"));

        // A custom token header plus the cache could share one holder's response with another.
        let cached = |header: &str| {
            format!(
                "{MINIMAL}\ncache = {{}}\n[route.jwt]\npublic_key_file = \"k\"\nheader = \"{header}\"\nscheme = \"\"\n"
            )
        };
        assert!(Config::from_toml_str(&cached("x-api-token"))
            .unwrap_err()
            .to_string()
            .contains("share one token holder"));
        assert!(Config::from_toml_str(&cached("Authorization")).is_ok(), "Authorization requests never use the cache");
    }
}
