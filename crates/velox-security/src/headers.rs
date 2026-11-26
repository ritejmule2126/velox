//! Response header policy: HSTS, `nosniff`, operator-defined extras.

use http::header::{HeaderMap, HeaderName, HeaderValue, SERVER, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS};
use velox_core::Config;

/// Pre-compiled response-header rules (built once per configuration).
#[derive(Debug, Clone, Default)]
pub struct ResponsePolicy {
    hsts: Option<HeaderValue>,
    nosniff: bool,
    hide_server: bool,
    extra: Vec<(HeaderName, HeaderValue)>,
}

impl ResponsePolicy {
    /// Compile the policy from `cfg`.
    pub fn from_config(cfg: &Config) -> Self {
        let hsts = cfg.tls.hsts.enabled.then(|| {
            let mut v = format!("max-age={}", cfg.tls.hsts.max_age);
            if cfg.tls.hsts.include_subdomains {
                v.push_str("; includeSubDomains");
            }
            if cfg.tls.hsts.preload {
                v.push_str("; preload");
            }
            HeaderValue::from_str(&v).ok()
        });
        let extra = cfg
            .security
            .response_headers
            .iter()
            .filter_map(|(k, v)| Some((HeaderName::from_bytes(k.as_bytes()).ok()?, HeaderValue::from_str(v).ok()?)))
            .collect();
        Self {
            hsts: hsts.flatten(),
            nosniff: cfg.security.nosniff,
            hide_server: cfg.security.hide_server_header,
            extra,
        }
    }

    /// Apply the policy. HSTS is only ever sent over TLS (RFC 6797 §7.2).
    /// Upstream-provided values always win over defaults.
    pub fn apply(&self, headers: &mut HeaderMap, is_tls: bool) {
        if self.hide_server {
            headers.remove(SERVER);
        }
        if is_tls {
            if let Some(h) = &self.hsts {
                headers.entry(STRICT_TRANSPORT_SECURITY).or_insert_with(|| h.clone());
            }
        }
        if self.nosniff {
            headers.entry(X_CONTENT_TYPE_OPTIONS).or_insert(HeaderValue::from_static("nosniff"));
        }
        for (k, v) in &self.extra {
            headers.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(extra: &str) -> Config {
        Config::from_toml_str(&format!(
            "[server]\nhttp_addr = \"127.0.0.1:1\"\n[[upstream]]\nname=\"a\"\nbackends=[{{addr=\"127.0.0.1:2\"}}]\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn hsts_only_on_tls_and_upstream_values_win() {
        let p =
            ResponsePolicy::from_config(&cfg("[tls.hsts]\nmax_age = 100\ninclude_subdomains = true\npreload = true\n"));
        let mut h = HeaderMap::new();
        p.apply(&mut h, false);
        assert!(!h.contains_key(STRICT_TRANSPORT_SECURITY));
        assert_eq!(h[X_CONTENT_TYPE_OPTIONS], "nosniff");
        p.apply(&mut h, true);
        assert_eq!(h[STRICT_TRANSPORT_SECURITY], "max-age=100; includeSubDomains; preload");

        let mut h = HeaderMap::new();
        h.insert(STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=1"));
        p.apply(&mut h, true);
        assert_eq!(h[STRICT_TRANSPORT_SECURITY], "max-age=1");
    }

    #[test]
    fn extras_and_server_hiding() {
        let p = ResponsePolicy::from_config(&cfg(
            "[security]\nhide_server_header = true\n[security.response_headers]\nreferrer-policy = \"no-referrer\"\n",
        ));
        let mut h = HeaderMap::new();
        h.insert(SERVER, HeaderValue::from_static("secret/1.0"));
        p.apply(&mut h, false);
        assert!(!h.contains_key(SERVER));
        assert_eq!(h["referrer-policy"], "no-referrer");
    }

    #[test]
    fn hsts_can_be_disabled() {
        let p = ResponsePolicy::from_config(&cfg("[tls.hsts]\nenabled = false\n"));
        let mut h = HeaderMap::new();
        p.apply(&mut h, true);
        assert!(!h.contains_key(STRICT_TRANSPORT_SECURITY));
    }
}
