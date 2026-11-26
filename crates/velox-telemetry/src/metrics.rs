//! The Prometheus registry and typed helpers around it.

use crate::TelemetryError;
use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};
use std::sync::OnceLock;
use velox_core::Snapshot;

/// The client-facing protocol a request or connection used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// HTTP/1.0 or HTTP/1.1.
    H1,
    /// HTTP/2.
    H2,
    /// HTTP/3 over QUIC.
    H3,
}

impl Protocol {
    /// Dense index (0..3) for lookup tables.
    pub const fn index(self) -> usize {
        match self {
            Self::H1 => 0,
            Self::H2 => 1,
            Self::H3 => 2,
        }
    }

    /// The metric label value (`h1`, `h2`, `h3`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::H1 => "h1",
            Self::H2 => "h2",
            Self::H3 => "h3",
        }
    }
}

/// All Velox metrics, backed by a private [`Registry`].
#[derive(Debug)]
pub struct Metrics {
    registry: Registry,
    requests_total: IntCounterVec,
    /// `request_duration` children, resolved once per protocol.
    duration_by_protocol: [Histogram; 3],
    /// `requests_total` children, resolved lazily per `(protocol, status)`.
    status_counters: Box<[OnceLock<IntCounter>]>,
    upstream_responses: IntCounterVec,
    upstream_duration: HistogramVec,
    active_connections: IntGaugeVec,
    connections_total: IntCounterVec,
    tls_handshake_errors: IntCounterVec,
    rate_limited: IntCounterVec,
    rejected_requests: IntCounterVec,
    config_reloads: IntCounterVec,
    backend_healthy: IntGaugeVec,
    backend_active: IntGaugeVec,
    backend_ejected: IntGaugeVec,
    backend_ejections: IntCounterVec,
    config_generation: IntGauge,
    h3_enabled: IntGauge,
    connections_rejected: IntCounter,
    upstream_saturated: IntCounterVec,
    upstream_tls_errors: IntCounterVec,
    proxy_protocol_errors: IntCounterVec,
    compression_responses: IntCounterVec,
    compression_bytes: IntCounterVec,
}

/// Status codes 100..=599 get a cached counter slot.
const STATUS_BASE: usize = 100;
const STATUS_SLOTS: usize = 500;

const LATENCY_BUCKETS: [f64; 14] =
    [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

fn counter(r: &Registry, name: &str, help: &str, labels: &[&str]) -> Result<IntCounterVec, prometheus::Error> {
    let c = IntCounterVec::new(Opts::new(name, help), labels)?;
    r.register(Box::new(c.clone()))?;
    Ok(c)
}

fn gauge_vec(r: &Registry, name: &str, help: &str, labels: &[&str]) -> Result<IntGaugeVec, prometheus::Error> {
    let g = IntGaugeVec::new(Opts::new(name, help), labels)?;
    r.register(Box::new(g.clone()))?;
    Ok(g)
}

fn histogram(r: &Registry, name: &str, help: &str, labels: &[&str]) -> Result<HistogramVec, prometheus::Error> {
    let h = HistogramVec::new(HistogramOpts::new(name, help).buckets(LATENCY_BUCKETS.to_vec()), labels)?;
    r.register(Box::new(h.clone()))?;
    Ok(h)
}

impl Metrics {
    /// Create and register every metric.
    pub fn new() -> Result<Self, TelemetryError> {
        let r = Registry::new_custom(Some("velox".to_owned()), None)?;
        let config_generation = IntGauge::new("config_generation", "Generation of the live configuration snapshot")?;
        r.register(Box::new(config_generation.clone()))?;
        let h3_enabled = IntGauge::new("h3_enabled", "1 when the HTTP/3 listener is running")?;
        r.register(Box::new(h3_enabled.clone()))?;
        let connections_rejected = IntCounter::new(
            "connections_rejected_total",
            "Connections refused by the global or per-IP connection limit",
        )?;
        r.register(Box::new(connections_rejected.clone()))?;
        let request_duration = histogram(
            &r,
            "http_request_duration_seconds",
            "Time from request received to response headers ready",
            &["protocol"],
        )?;
        let duration_by_protocol =
            [Protocol::H1, Protocol::H2, Protocol::H3].map(|p| request_duration.with_label_values(&[p.as_str()]));
        Ok(Self {
            duration_by_protocol,
            status_counters: (0..3 * STATUS_SLOTS).map(|_| OnceLock::new()).collect(),
            requests_total: counter(
                &r,
                "http_requests_total",
                "Client requests by protocol and status",
                &["protocol", "status"],
            )?,
            upstream_responses: counter(
                &r,
                "upstream_responses_total",
                "Upstream responses by pool and status code (`error` = no response)",
                &["upstream", "code"],
            )?,
            upstream_duration: histogram(
                &r,
                "upstream_request_duration_seconds",
                "Time to upstream response headers",
                &["upstream"],
            )?,
            active_connections: gauge_vec(&r, "active_connections", "Open client connections", &["protocol"])?,
            connections_total: counter(&r, "connections_total", "Accepted client connections", &["protocol"])?,
            tls_handshake_errors: counter(
                &r,
                "tls_handshake_errors_total",
                "Failed TLS/QUIC handshakes",
                &["transport", "reason"],
            )?,
            rate_limited: counter(&r, "rate_limited_total", "Requests answered 429", &["route"])?,
            rejected_requests: counter(
                &r,
                "rejected_requests_total",
                "Requests rejected by strict parsing",
                &["reason"],
            )?,
            config_reloads: counter(&r, "config_reloads_total", "Configuration reload attempts", &["result"])?,
            backend_healthy: gauge_vec(
                &r,
                "upstream_backend_healthy",
                "1 if the backend is eligible for traffic",
                &["upstream", "backend"],
            )?,
            backend_active: gauge_vec(
                &r,
                "upstream_backend_active_requests",
                "In-flight requests per backend",
                &["upstream", "backend"],
            )?,
            backend_ejected: gauge_vec(
                &r,
                "upstream_backend_ejected",
                "1 while a backend is passively ejected",
                &["upstream", "backend"],
            )?,
            backend_ejections: counter(
                &r,
                "upstream_backend_ejections_total",
                "Passive ejections",
                &["upstream", "backend"],
            )?,
            upstream_saturated: counter(
                &r,
                "upstream_saturated_total",
                "Requests refused (503) because every eligible backend was at its max_inflight cap",
                &["upstream"],
            )?,
            upstream_tls_errors: counter(
                &r,
                "upstream_tls_errors_total",
                "Failed TLS handshakes to https:// backends",
                &["upstream", "reason"],
            )?,
            proxy_protocol_errors: counter(
                &r,
                "proxy_protocol_errors_total",
                "Connections refused on a PROXY-protocol listener",
                &["reason"],
            )?,
            compression_responses: counter(
                &r,
                "compression_responses_total",
                "Responses compressed, by content-coding",
                &["encoding"],
            )?,
            compression_bytes: counter(
                &r,
                "compression_bytes_total",
                "Body bytes through the compressor (`in` = uncompressed, `out` = compressed)",
                &["encoding", "direction"],
            )?,
            config_generation,
            h3_enabled,
            connections_rejected,
            registry: r,
        })
    }

    /// Record a finished client request.
    ///
    /// Hot path: the histogram child is pre-resolved and the status counter is
    /// cached after its first use, so steady-state cost is two atomic ops, with
    /// no label hashing and no allocation.
    pub fn observe_request(&self, protocol: Protocol, status: u16, seconds: f64) {
        self.duration_by_protocol[protocol.index()].observe(seconds);
        match usize::from(status).checked_sub(STATUS_BASE).filter(|i| *i < STATUS_SLOTS) {
            Some(i) => self.status_counters[protocol.index() * STATUS_SLOTS + i]
                .get_or_init(|| {
                    let label = itoa_status(status);
                    self.requests_total.with_label_values(&[protocol.as_str(), label.as_str()])
                })
                .inc(),
            None => {
                let label = itoa_status(status);
                self.requests_total.with_label_values(&[protocol.as_str(), label.as_str()]).inc();
            }
        }
    }

    /// Record an upstream attempt (`status` is `None` when no response arrived).
    pub fn observe_upstream(&self, upstream: &str, status: Option<u16>, seconds: f64) {
        match status {
            Some(s) => {
                let buf = itoa_status(s);
                self.upstream_responses.with_label_values(&[upstream, buf.as_str()]).inc();
            }
            None => self.upstream_responses.with_label_values(&[upstream, "error"]).inc(),
        }
        self.upstream_duration.with_label_values(&[upstream]).observe(seconds);
    }

    /// Track an open client connection until the guard drops.
    pub fn connection_opened(&self, protocol: Protocol) -> ConnectionGuard {
        self.connections_total.with_label_values(&[protocol.as_str()]).inc();
        let gauge = self.active_connections.with_label_values(&[protocol.as_str()]);
        gauge.inc();
        ConnectionGuard { gauge }
    }

    /// Count a refused connection (limit exceeded).
    pub fn connection_rejected(&self) {
        self.connections_rejected.inc();
    }

    /// Count a failed handshake.
    pub fn tls_handshake_error(&self, transport: &str, reason: &str) {
        self.tls_handshake_errors.with_label_values(&[transport, reason]).inc();
    }

    /// Count a request refused because every eligible backend was at its cap.
    pub fn upstream_saturated(&self, upstream: &str) {
        self.upstream_saturated.with_label_values(&[upstream]).inc();
    }

    /// Count a failed TLS handshake to a backend.
    pub fn upstream_tls_error(&self, upstream: &str, reason: &str) {
        self.upstream_tls_errors.with_label_values(&[upstream, reason]).inc();
    }

    /// Count a connection refused by PROXY-protocol handling.
    pub fn proxy_protocol_error(&self, reason: &str) {
        self.proxy_protocol_errors.with_label_values(&[reason]).inc();
    }

    /// Record a finished compressed response.
    pub fn compressed(&self, encoding: &str, bytes_in: u64, bytes_out: u64) {
        self.compression_responses.with_label_values(&[encoding]).inc();
        self.compression_bytes.with_label_values(&[encoding, "in"]).inc_by(bytes_in);
        self.compression_bytes.with_label_values(&[encoding, "out"]).inc_by(bytes_out);
    }

    /// Count a 429.
    pub fn rate_limited(&self, route: &str) {
        self.rate_limited.with_label_values(&[route]).inc();
    }

    /// Count a request rejected by strict parsing.
    pub fn rejected(&self, reason: &str) {
        self.rejected_requests.with_label_values(&[reason]).inc();
    }

    /// Count a reload attempt (`ok` / `error`).
    pub fn config_reload(&self, ok: bool) {
        self.config_reloads.with_label_values(&[if ok { "ok" } else { "error" }]).inc();
    }

    /// Count a passive ejection.
    pub fn backend_ejected(&self, upstream: &str, backend: &str) {
        self.backend_ejections.with_label_values(&[upstream, backend]).inc();
    }

    /// Mark whether the HTTP/3 endpoint is up.
    pub fn set_h3_enabled(&self, on: bool) {
        self.h3_enabled.set(i64::from(on));
    }

    /// Refresh the gauges that mirror live backend state from `snapshot`.
    pub fn collect_snapshot(&self, snapshot: &Snapshot) {
        self.backend_healthy.reset();
        self.backend_active.reset();
        self.backend_ejected.reset();
        self.config_generation.set(i64::try_from(snapshot.generation).unwrap_or(i64::MAX));
        for group in snapshot.upstreams.values() {
            for b in &group.backends {
                let labels = [&*group.name, &*b.name];
                self.backend_healthy.with_label_values(&labels).set(i64::from(b.is_available()));
                self.backend_active.with_label_values(&labels).set(i64::try_from(b.active()).unwrap_or(i64::MAX));
                self.backend_ejected.with_label_values(&labels).set(i64::from(b.ejected_for_ms() > 0));
            }
        }
    }

    /// Render the Prometheus text exposition format.
    pub fn render(&self) -> Result<String, TelemetryError> {
        let mut out = Vec::with_capacity(8 * 1024);
        TextEncoder::new().encode(&self.registry.gather(), &mut out)?;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}

/// Keeps `velox_active_connections` accurate; decrements on drop.
#[derive(Debug)]
pub struct ConnectionGuard {
    gauge: IntGauge,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.gauge.dec();
    }
}

/// A tiny stack string for status codes (avoids a heap allocation per request).
struct StatusStr {
    buf: [u8; 5],
    len: usize,
}

impl StatusStr {
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or("0")
    }
}

fn itoa_status(mut n: u16) -> StatusStr {
    let mut tmp = [0u8; 5];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = b'0' + u8::try_from(n % 10).unwrap_or(0);
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let len = tmp.len() - i;
    let mut buf = [0u8; 5];
    buf[..len].copy_from_slice(&tmp[i..]);
    StatusStr { buf, len }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velox_core::{Config, SharedState};

    #[test]
    fn status_formatting() {
        for n in [0u16, 7, 99, 200, 404, 503, 65535] {
            assert_eq!(itoa_status(n).as_str(), n.to_string());
        }
    }

    #[test]
    fn renders_standard_velox_metrics() {
        let m = Metrics::new().unwrap();
        m.observe_request(Protocol::H3, 200, 0.003);
        m.observe_request(Protocol::H1, 502, 0.5);
        m.observe_upstream("app", Some(200), 0.002);
        m.observe_upstream("app", None, 0.2);
        m.rate_limited("route-0");
        m.rejected("cl-te-conflict");
        m.config_reload(true);
        m.tls_handshake_error("tcp", "bad_certificate");
        m.backend_ejected("app", "127.0.0.1:1");
        m.set_h3_enabled(true);
        let text = m.render().unwrap();
        for needle in [
            "velox_http_requests_total{protocol=\"h3\",status=\"200\"} 1",
            "velox_http_requests_total{protocol=\"h1\",status=\"502\"} 1",
            "velox_http_request_duration_seconds_bucket{protocol=\"h3\",le=\"0.005\"} 1",
            "velox_upstream_responses_total{code=\"error\",upstream=\"app\"} 1",
            "velox_rate_limited_total{route=\"route-0\"} 1",
            "velox_rejected_requests_total{reason=\"cl-te-conflict\"} 1",
            "velox_config_reloads_total{result=\"ok\"} 1",
            "velox_tls_handshake_errors_total{reason=\"bad_certificate\",transport=\"tcp\"} 1",
            "velox_h3_enabled 1",
        ] {
            assert!(text.contains(needle), "missing `{needle}` in:\n{text}");
        }
    }

    #[test]
    fn cached_request_counters_are_exact_and_cover_unusual_statuses() {
        let m = Metrics::new().unwrap();
        for _ in 0..1000 {
            m.observe_request(Protocol::H2, 204, 0.001);
        }
        m.observe_request(Protocol::H1, 204, 0.001);
        m.observe_request(Protocol::H3, 599, 0.001);
        m.observe_request(Protocol::H3, 100, 0.001);
        m.observe_request(Protocol::H1, 99, 0.001); // outside the cached range
        m.observe_request(Protocol::H1, 600, 0.001);
        let t = m.render().unwrap();
        for needle in [
            "velox_http_requests_total{protocol=\"h2\",status=\"204\"} 1000",
            "velox_http_requests_total{protocol=\"h1\",status=\"204\"} 1",
            "velox_http_requests_total{protocol=\"h3\",status=\"599\"} 1",
            "velox_http_requests_total{protocol=\"h3\",status=\"100\"} 1",
            "velox_http_requests_total{protocol=\"h1\",status=\"99\"} 1",
            "velox_http_requests_total{protocol=\"h1\",status=\"600\"} 1",
            "velox_http_request_duration_seconds_count{protocol=\"h2\"} 1000",
        ] {
            assert!(t.contains(needle), "missing `{needle}`:\n{t}");
        }
    }

    #[test]
    fn connection_guard_tracks_gauge() {
        let m = Metrics::new().unwrap();
        let g1 = m.connection_opened(Protocol::H2);
        let g2 = m.connection_opened(Protocol::H2);
        assert!(m.render().unwrap().contains("velox_active_connections{protocol=\"h2\"} 2"));
        drop(g1);
        drop(g2);
        assert!(m.render().unwrap().contains("velox_active_connections{protocol=\"h2\"} 0"));
    }

    #[test]
    fn snapshot_gauges_reflect_backend_state() {
        let cfg = Config::from_toml_str(
            r#"
            [server]
            http_addr = "127.0.0.1:1"
            [[upstream]]
            name = "app"
            backends = [{ addr = "127.0.0.1:1" }, { addr = "127.0.0.1:2" }]
        "#,
        )
        .unwrap();
        let state = SharedState::new(cfg).unwrap();
        let snap = state.load();
        snap.upstreams["app"].backends[1].set_draining(true);
        let m = Metrics::new().unwrap();
        m.collect_snapshot(&snap);
        let text = m.render().unwrap();
        assert!(text.contains("velox_upstream_backend_healthy{backend=\"127.0.0.1:1\",upstream=\"app\"} 1"));
        assert!(text.contains("velox_upstream_backend_healthy{backend=\"127.0.0.1:2\",upstream=\"app\"} 0"));
        assert!(text.contains("velox_config_generation 1"));
    }

    #[test]
    fn init_logging_is_idempotent() {
        let cfg = velox_core::config::TelemetryConfig::default();
        crate::init_logging(&cfg).unwrap();
        crate::init_logging(&cfg).unwrap();
    }
}
