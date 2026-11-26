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
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            nosniff: true,
            response_headers: BTreeMap::new(),
            hide_server_header: false,
            allow_underscores_in_host: false,
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
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self { log_level: "info".to_owned(), log_format: LogFormat::Json, access_log: true, metrics_addr: None }
    }
}

/// Where a backend lives.
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
    /// A Unix domain socket (`unix:/path/to.sock`).
    Unix(PathBuf),
}

impl BackendAddr {
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
        let (host, port) =
            s.rsplit_once(':').ok_or_else(|| format!("backend `{s}` must be host:port or unix:/path"))?;
        let port: u16 = port.parse().map_err(|_| format!("backend `{s}` has an invalid port"))?;
        let bare = Self::connect_host(host);
        let ok = !bare.is_empty()
            && (host.starts_with('[') == host.ends_with(']'))
            && bare.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
        if !ok {
            return Err(format!("backend `{s}` has an invalid host"));
        }
        Ok(Self::Tcp { host: host.to_owned(), port })
    }
}

impl fmt::Display for BackendAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp { host, port } => write!(f, "{host}:{port}"),
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
        let upstream_names: HashSet<&str> = self.upstreams.iter().map(|u| u.name.as_str()).collect();
        for t in &self.tcp_proxies {
            if !upstream_names.contains(t.upstream.as_str()) {
                errs.push(format!("tcp_proxy {}: unknown upstream `{}`", t.listen, t.upstream));
            }
        }
        if self.telemetry.log_level.trim().is_empty() {
            errs.push("telemetry.log_level must not be empty".into());
        }
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
}
