//! Per-route CORS policy (the <https://fetch.spec.whatwg.org/#http-cors-protocol>
//! server side), enforced at the edge.
//!
//! * **Preflight** (`OPTIONS` + `Origin` + `Access-Control-Request-Method`) is
//!   answered by Velox itself and never reaches the backend. A disallowed
//!   origin, method or header gets `403` with no `Access-Control-*` headers.
//! * **Actual requests** are proxied as usual; on the way back any
//!   `Access-Control-*` headers the backend set are *replaced* by the edge
//!   policy, so one policy governs every response — including Velox's own error
//!   responses, which would otherwise surface in a browser as an opaque CORS
//!   failure instead of the real `502`/`429`.
//! * `Vary: Origin` is added whenever the answer depends on the request's
//!   `Origin` (always, except for a credential-less `*`), so caches stay correct.
//!
//! Matching is exact on the serialized origin (`scheme://host[:port]`, ASCII
//! case-insensitive), or `scheme://*.example.com[:port]` for subdomains (at least
//! one extra label; `*.example.com` never matches `example.com` itself nor
//! `evilexample.com`). `Access-Control-Allow-Origin: *` is never combined with
//! credentials (rejected at configuration time).

use crate::config::CorsConfig;
use http::header::{HeaderName, HeaderValue, VARY};
use http::{HeaderMap, Method};

/// `Access-Control-Allow-Origin`.
pub const ALLOW_ORIGIN: HeaderName = HeaderName::from_static("access-control-allow-origin");
/// `Access-Control-Allow-Methods`.
pub const ALLOW_METHODS: HeaderName = HeaderName::from_static("access-control-allow-methods");
/// `Access-Control-Allow-Headers`.
pub const ALLOW_HEADERS: HeaderName = HeaderName::from_static("access-control-allow-headers");
/// `Access-Control-Allow-Credentials`.
pub const ALLOW_CREDENTIALS: HeaderName = HeaderName::from_static("access-control-allow-credentials");
/// `Access-Control-Expose-Headers`.
pub const EXPOSE_HEADERS: HeaderName = HeaderName::from_static("access-control-expose-headers");
/// `Access-Control-Max-Age`.
pub const MAX_AGE: HeaderName = HeaderName::from_static("access-control-max-age");
/// `Access-Control-Request-Method` (preflight).
pub const REQUEST_METHOD: HeaderName = HeaderName::from_static("access-control-request-method");
/// `Access-Control-Request-Headers` (preflight).
pub const REQUEST_HEADERS: HeaderName = HeaderName::from_static("access-control-request-headers");
/// `Origin`.
pub const ORIGIN: HeaderName = HeaderName::from_static("origin");

#[derive(Debug, Clone, PartialEq, Eq)]
enum OriginRule {
    /// `*`
    Any,
    /// A full serialized origin, lowercased.
    Exact(String),
    /// `scheme://*.suffix[:port]` → scheme prefix `scheme://`, suffix `.suffix[:port]`.
    Subdomain { scheme: String, suffix: String },
}

/// Why a preflight was refused (for logs and metrics; never sent to the client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// The `Origin` is not allowed.
    Origin,
    /// `Access-Control-Request-Method` is not allowed.
    Method,
    /// A requested header is not allowed.
    Header,
    /// The preflight itself is malformed.
    Malformed,
}

impl Denied {
    /// A low-cardinality label.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Origin => "origin",
            Self::Method => "method",
            Self::Header => "header",
            Self::Malformed => "malformed",
        }
    }
}

/// A compiled CORS policy.
#[derive(Debug, Clone)]
pub struct CorsPolicy {
    origins: Vec<OriginRule>,
    any_origin: bool,
    any_method: bool,
    methods: Vec<Method>,
    methods_header: HeaderValue,
    any_header: bool,
    headers: Vec<HeaderName>,
    headers_header: Option<HeaderValue>,
    expose: Option<HeaderValue>,
    credentials: bool,
    max_age: Option<HeaderValue>,
}

fn parse_origin_rule(s: &str) -> Option<OriginRule> {
    if s == "*" {
        return Some(OriginRule::Any);
    }
    if s == "null" {
        return Some(OriginRule::Exact("null".to_owned()));
    }
    let (scheme, rest) = s.split_once("://")?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https")
        || rest.is_empty()
        || rest.contains(['/', '?', '#', '@', ' '])
    {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();
    let rest = rest.to_ascii_lowercase();
    match rest.strip_prefix("*.") {
        Some(suffix) if !suffix.is_empty() && !suffix.starts_with('.') && !suffix.contains('*') => {
            Some(OriginRule::Subdomain { scheme: format!("{scheme}://"), suffix: format!(".{suffix}") })
        }
        Some(_) => None,
        None if rest.contains('*') => None,
        None => Some(OriginRule::Exact(format!("{scheme}://{rest}"))),
    }
}

/// Is `s` an acceptable `allow_origins` entry? (Used by config validation.)
pub fn valid_origin_pattern(s: &str) -> bool {
    parse_origin_rule(s).is_some()
}

fn join_values<'a>(items: impl Iterator<Item = &'a str>) -> Option<HeaderValue> {
    let joined = items.collect::<Vec<_>>().join(", ");
    (!joined.is_empty()).then(|| HeaderValue::from_str(&joined).ok()).flatten()
}

impl CorsPolicy {
    /// Compile a validated [`CorsConfig`]. Returns `None` if it is malformed
    /// (validation rejects those, so this is a defensive check).
    pub fn new(cfg: &CorsConfig) -> Option<Self> {
        let origins: Vec<OriginRule> = cfg.allow_origins.iter().map(|o| parse_origin_rule(o)).collect::<Option<_>>()?;
        let any_origin = origins.contains(&OriginRule::Any);
        if origins.is_empty() || (any_origin && cfg.allow_credentials) {
            return None;
        }
        let any_method = cfg.allow_methods.iter().any(|m| m == "*");
        let methods: Vec<Method> = if any_method {
            Vec::new()
        } else {
            cfg.allow_methods.iter().map(|m| Method::from_bytes(m.as_bytes()).ok()).collect::<Option<_>>()?
        };
        let any_header = cfg.allow_headers.iter().any(|h| h == "*");
        let headers: Vec<HeaderName> = if any_header {
            Vec::new()
        } else {
            cfg.allow_headers.iter().map(|h| HeaderName::from_bytes(h.as_bytes()).ok()).collect::<Option<_>>()?
        };
        let expose: Vec<HeaderName> =
            cfg.expose_headers.iter().map(|h| HeaderName::from_bytes(h.as_bytes()).ok()).collect::<Option<_>>()?;
        Some(Self {
            origins,
            any_origin,
            any_method,
            methods_header: if any_method {
                HeaderValue::from_static("*")
            } else {
                join_values(methods.iter().map(Method::as_str))?
            },
            methods,
            any_header,
            headers_header: join_values(headers.iter().map(HeaderName::as_str)),
            headers,
            expose: join_values(expose.iter().map(HeaderName::as_str)),
            credentials: cfg.allow_credentials,
            max_age: cfg.max_age.map(|d| HeaderValue::from(d.as_secs())),
        })
    }

    /// Does the answer depend on the request's `Origin`?
    fn varies_on_origin(&self) -> bool {
        !(self.any_origin && !self.credentials)
    }

    /// The `Access-Control-Allow-Origin` value for `origin`, if it is allowed.
    fn allow_origin_value(&self, origin: &HeaderValue) -> Option<HeaderValue> {
        let o = origin.to_str().ok()?.to_ascii_lowercase();
        let allowed = self.origins.iter().any(|rule| match rule {
            OriginRule::Any => true,
            OriginRule::Exact(e) => *e == o,
            OriginRule::Subdomain { scheme, suffix } => {
                // `scheme://` + one or more labels + `.suffix[:port]`
                o.strip_prefix(scheme.as_str())
                    .and_then(|host_port| host_port.strip_suffix(suffix.as_str()))
                    .is_some_and(|labels| {
                        !labels.is_empty()
                            && !labels.starts_with('.')
                            && !labels.ends_with('.')
                            && !labels.contains("..")
                            && labels.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
                    })
            }
        });
        if !allowed {
            return None;
        }
        if self.any_origin && !self.credentials {
            Some(HeaderValue::from_static("*"))
        } else {
            Some(origin.clone()) // echo the exact, validated value
        }
    }

    fn add_vary(&self, headers: &mut HeaderMap, names: &[&'static str]) {
        for name in names {
            let covered = headers
                .get_all(VARY)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .any(|v| v.split(',').any(|t| t.trim() == "*" || t.trim().eq_ignore_ascii_case(name)));
            if !covered {
                headers.append(VARY, HeaderValue::from_static(name));
            }
        }
    }

    /// Evaluate a preflight. On success returns the headers of the `204`
    /// answer; on refusal the reason.
    pub fn preflight(
        &self,
        origin: &HeaderValue,
        request_method: &HeaderValue,
        request_headers: Option<&HeaderValue>,
    ) -> Result<HeaderMap, Denied> {
        let allow_origin = self.allow_origin_value(origin).ok_or(Denied::Origin)?;
        let method = request_method.to_str().map_err(|_| Denied::Malformed)?;
        let method = Method::from_bytes(method.as_bytes()).map_err(|_| Denied::Malformed)?;
        if !self.any_method && !self.methods.contains(&method) {
            return Err(Denied::Method);
        }
        let mut out = HeaderMap::new();
        out.insert(ALLOW_ORIGIN, allow_origin);
        // With credentials a literal `*` is not a wildcard, so name the method.
        out.insert(
            ALLOW_METHODS,
            if self.any_method && self.credentials { request_method.clone() } else { self.methods_header.clone() },
        );
        let requested = match request_headers {
            None => Vec::new(),
            Some(v) => {
                let text = v.to_str().map_err(|_| Denied::Malformed)?;
                let mut names = Vec::new();
                for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()).take(64) {
                    names.push(HeaderName::from_bytes(part.as_bytes()).map_err(|_| Denied::Malformed)?);
                }
                names
            }
        };
        if !self.any_header && requested.iter().any(|h| !self.headers.contains(h)) {
            return Err(Denied::Header);
        }
        if self.any_header {
            // Reflect exactly what was asked for (works with credentials too).
            if let Some(v) = request_headers {
                out.insert(ALLOW_HEADERS, v.clone());
            }
        } else if let Some(v) = &self.headers_header {
            out.insert(ALLOW_HEADERS, v.clone());
        }
        if self.credentials {
            out.insert(ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
        }
        if let Some(age) = &self.max_age {
            out.insert(MAX_AGE, age.clone());
        }
        self.add_vary(&mut out, &["Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"]);
        Ok(out)
    }

    /// Apply the policy to a response travelling back to the client: replace
    /// whatever `Access-Control-*` the backend set, then (if the request's
    /// origin is allowed) add the edge's.
    pub fn apply_response(&self, origin: Option<&HeaderValue>, headers: &mut HeaderMap) {
        for name in [ALLOW_ORIGIN, ALLOW_METHODS, ALLOW_HEADERS, ALLOW_CREDENTIALS, EXPOSE_HEADERS, MAX_AGE] {
            headers.remove(name);
        }
        if self.varies_on_origin() {
            self.add_vary(headers, &["Origin"]);
        }
        let allow = origin.and_then(|o| self.allow_origin_value(o));
        // A credential-less wildcard answers every request, even without `Origin`.
        let allow = allow.or_else(|| (self.any_origin && !self.credentials).then(|| HeaderValue::from_static("*")));
        let Some(allow) = allow else { return };
        headers.insert(ALLOW_ORIGIN, allow);
        if self.credentials {
            headers.insert(ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
        }
        if let Some(expose) = &self.expose {
            headers.insert(EXPOSE_HEADERS, expose.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cfg(origins: &[&str]) -> CorsConfig {
        CorsConfig {
            allow_origins: origins.iter().map(|s| (*s).to_owned()).collect(),
            allow_methods: vec!["GET".into(), "POST".into(), "PUT".into()],
            allow_headers: vec!["content-type".into(), "authorization".into()],
            expose_headers: vec!["x-request-id".into()],
            allow_credentials: false,
            max_age: Some(Duration::from_secs(600)),
        }
    }

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    fn policy(c: &CorsConfig) -> CorsPolicy {
        CorsPolicy::new(c).unwrap()
    }

    #[test]
    fn origin_matching_is_exact_and_subdomain_wildcards_need_a_real_label() {
        let p = policy(&cfg(&["https://app.example.com", "https://*.cdn.example.com", "http://localhost:3000"]));
        let ok = |o: &str| p.allow_origin_value(&hv(o)).is_some();
        assert!(ok("https://app.example.com"));
        assert!(ok("HTTPS://APP.EXAMPLE.COM"), "scheme and host are case-insensitive");
        assert!(ok("http://localhost:3000"));
        assert!(ok("https://a.cdn.example.com"));
        assert!(ok("https://a.b.cdn.example.com"), "nested subdomains match");
        for bad in [
            "http://app.example.com",            // scheme
            "https://app.example.com:8443",      // port
            "https://app.example.com.evil.test", // suffix attack
            "https://evilapp.example.com",
            "https://cdn.example.com",        // the bare domain is not a subdomain
            "https://.cdn.example.com",       // empty label
            "https://evilcdn.example.com",    // no dot boundary
            "https://a.cdn.example.com:8443", // port not in the rule
            "http://a.cdn.example.com",
            "null",
            "",
            "https://app.example.com/",
            "https://app.example.com@evil.test",
        ] {
            assert!(!ok(bad), "{bad:?} must not match");
        }
        // The echoed value is the request's own (validated) origin.
        assert_eq!(p.allow_origin_value(&hv("https://a.cdn.example.com")).unwrap(), "https://a.cdn.example.com");
    }

    #[test]
    fn wildcard_origin_yields_star_without_credentials_and_is_refused_with_them() {
        let p = policy(&cfg(&["*"]));
        assert_eq!(p.allow_origin_value(&hv("https://anything.test")).unwrap(), "*");
        let mut c = cfg(&["*"]);
        c.allow_credentials = true;
        assert!(CorsPolicy::new(&c).is_none(), "`*` with credentials is forbidden by the Fetch standard");
        // A specific list with credentials echoes the origin.
        let mut c = cfg(&["https://a.test"]);
        c.allow_credentials = true;
        let p = policy(&c);
        assert_eq!(p.allow_origin_value(&hv("https://a.test")).unwrap(), "https://a.test");
        let h = p.preflight(&hv("https://a.test"), &hv("GET"), None).unwrap();
        assert_eq!(h[ALLOW_CREDENTIALS], "true");
    }

    #[test]
    fn preflight_success_headers() {
        let p = policy(&cfg(&["https://app.example.com"]));
        let h =
            p.preflight(&hv("https://app.example.com"), &hv("PUT"), Some(&hv("Content-Type, Authorization"))).unwrap();
        assert_eq!(h[ALLOW_ORIGIN], "https://app.example.com");
        assert_eq!(h[ALLOW_METHODS], "GET, POST, PUT");
        assert_eq!(h[ALLOW_HEADERS], "content-type, authorization");
        assert_eq!(h[MAX_AGE], "600");
        assert!(!h.contains_key(ALLOW_CREDENTIALS));
        let vary: Vec<_> = h.get_all(VARY).iter().map(|v| v.to_str().unwrap().to_owned()).collect();
        assert_eq!(vary, ["Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"]);
        // No requested headers is fine.
        assert!(p.preflight(&hv("https://app.example.com"), &hv("GET"), None).is_ok());
    }

    #[test]
    fn preflight_refusals_name_the_reason() {
        let p = policy(&cfg(&["https://app.example.com"]));
        let o = hv("https://app.example.com");
        assert_eq!(p.preflight(&hv("https://evil.test"), &hv("GET"), None).unwrap_err(), Denied::Origin);
        assert_eq!(p.preflight(&o, &hv("DELETE"), None).unwrap_err(), Denied::Method);
        assert_eq!(p.preflight(&o, &hv("get"), None).unwrap_err(), Denied::Method, "methods are case-sensitive");
        assert_eq!(p.preflight(&o, &hv("GET"), Some(&hv("x-secret"))).unwrap_err(), Denied::Header);
        assert_eq!(p.preflight(&o, &hv("GET"), Some(&hv("content-type, x-secret"))).unwrap_err(), Denied::Header);
        assert_eq!(p.preflight(&o, &hv("G E T"), None).unwrap_err(), Denied::Malformed);
        assert_eq!(p.preflight(&o, &hv("GET"), Some(&hv("bad header!"))).unwrap_err(), Denied::Malformed);
        assert_eq!(Denied::Header.reason(), "header");
    }

    #[test]
    fn wildcard_methods_and_headers_reflect_the_request() {
        let mut c = cfg(&["https://a.test"]);
        c.allow_methods = vec!["*".into()];
        c.allow_headers = vec!["*".into()];
        let p = policy(&c);
        let h = p.preflight(&hv("https://a.test"), &hv("PATCH"), Some(&hv("x-custom, x-other"))).unwrap();
        assert_eq!(h[ALLOW_METHODS], "*");
        assert_eq!(h[ALLOW_HEADERS], "x-custom, x-other");
        // With credentials `*` is not a wildcard: the concrete method is named.
        c.allow_credentials = true;
        let h = policy(&c).preflight(&hv("https://a.test"), &hv("PATCH"), None).unwrap();
        assert_eq!(h[ALLOW_METHODS], "PATCH");
    }

    #[test]
    fn responses_get_the_edge_policy_and_lose_the_backends() {
        let p = policy(&cfg(&["https://app.example.com"]));
        let mut h = HeaderMap::new();
        h.insert(ALLOW_ORIGIN, hv("*"));
        h.insert(ALLOW_CREDENTIALS, hv("true"));
        h.insert(EXPOSE_HEADERS, hv("x-backend"));
        h.insert(VARY, hv("Accept-Language"));
        p.apply_response(Some(&hv("https://app.example.com")), &mut h);
        assert_eq!(h[ALLOW_ORIGIN], "https://app.example.com");
        assert!(!h.contains_key(ALLOW_CREDENTIALS), "the backend's credentials claim is gone");
        assert_eq!(h[EXPOSE_HEADERS], "x-request-id");
        let vary: Vec<_> = h.get_all(VARY).iter().map(|v| v.to_str().unwrap()).collect();
        assert_eq!(vary, ["Accept-Language", "Origin"]);

        // A disallowed origin: the backend's headers are stripped and nothing is added.
        let mut h = HeaderMap::new();
        h.insert(ALLOW_ORIGIN, hv("https://evil.test"));
        p.apply_response(Some(&hv("https://evil.test")), &mut h);
        assert!(!h.contains_key(ALLOW_ORIGIN));
        assert_eq!(h[VARY], "Origin");
        // No Origin header: nothing to add, still varies.
        let mut h = HeaderMap::new();
        p.apply_response(None, &mut h);
        assert!(!h.contains_key(ALLOW_ORIGIN));
        assert_eq!(h[VARY], "Origin");
    }

    #[test]
    fn credentialless_wildcard_needs_no_vary_and_answers_everyone() {
        let p = policy(&cfg(&["*"]));
        let mut h = HeaderMap::new();
        p.apply_response(Some(&hv("https://a.test")), &mut h);
        assert_eq!(h[ALLOW_ORIGIN], "*");
        assert!(!h.contains_key(VARY));
        let mut h = HeaderMap::new();
        p.apply_response(None, &mut h);
        assert_eq!(h[ALLOW_ORIGIN], "*");
    }

    #[test]
    fn origin_rule_syntax() {
        for good in ["*", "null", "https://a.test", "http://a.test:8080", "https://*.a.test", "HTTPS://A.TEST"] {
            assert!(valid_origin_pattern(good), "{good}");
        }
        for bad in [
            "",
            "a.test",
            "ftp://a.test",
            "https://",
            "https://a.test/",
            "https://*",
            "https://*.",
            "https://a*.test",
            "https://*.*.test",
            "https://a.test?x",
            "https://u@a.test",
            "*.a.test",
        ] {
            assert!(!valid_origin_pattern(bad), "{bad}");
        }
    }
}
