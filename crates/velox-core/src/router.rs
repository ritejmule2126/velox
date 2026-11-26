//! Host + path-prefix routing over an immutable table.

use crate::config::{RateLimitConfig, RouteConfig};
use crate::upstream::UpstreamGroup;
use http::{HeaderName, HeaderValue};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// A compiled route.
#[derive(Debug)]
pub struct Route {
    /// Stable identifier (metric/log label).
    pub id: Arc<str>,
    /// Normalised path prefix without trailing slash (`""` = root).
    pub prefix: String,
    /// Strip the prefix before forwarding.
    pub strip_prefix: bool,
    /// Redirect plain HTTP to HTTPS.
    pub redirect_https: bool,
    /// Fixed host for the HTTPS redirect (instead of reflecting `Host`).
    pub canonical_host: Option<Arc<str>>,
    /// Effective rate-limit policy (route override or global default).
    pub rate_limit: Option<RateLimitConfig>,
    /// Headers set on the upstream request.
    pub request_headers: Vec<(HeaderName, HeaderValue)>,
    /// Per-route override of the upstream response timeout.
    pub timeout: Option<Duration>,
    /// Target pool.
    pub upstream: Arc<UpstreamGroup>,
}

impl Route {
    /// Compile `cfg`, resolving the upstream and the effective rate limit.
    pub fn compile(
        id: String,
        cfg: &RouteConfig,
        global_rl: Option<&RateLimitConfig>,
        upstream: Arc<UpstreamGroup>,
    ) -> Self {
        let prefix = cfg.path_prefix.trim_end_matches('/').to_owned();
        let rate_limit = cfg.rate_limit.as_ref().or(global_rl).filter(|r| r.enabled).cloned();
        let request_headers = cfg
            .request_headers
            .iter()
            .filter_map(|(k, v)| Some((HeaderName::from_bytes(k.as_bytes()).ok()?, HeaderValue::from_str(v).ok()?)))
            .collect();
        Self {
            id: Arc::from(id),
            prefix,
            strip_prefix: cfg.strip_prefix,
            redirect_https: cfg.redirect_https,
            canonical_host: cfg.canonical_host.as_deref().map(Arc::from),
            rate_limit,
            request_headers,
            timeout: cfg.timeout,
            upstream,
        }
    }

    /// Does `path` fall under this route's prefix (on a segment boundary)?
    pub fn matches_path(&self, path: &str) -> bool {
        if self.prefix.is_empty() {
            return true;
        }
        path.starts_with(&self.prefix)
            && (path.len() == self.prefix.len() || path.as_bytes().get(self.prefix.len()) == Some(&b'/'))
    }

    /// The path to forward (applies `strip_prefix`).
    pub fn rewrite_path<'a>(&self, path: &'a str) -> &'a str {
        if self.strip_prefix && !self.prefix.is_empty() {
            let rest = &path[self.prefix.len().min(path.len())..];
            if rest.is_empty() {
                "/"
            } else {
                rest
            }
        } else {
            path
        }
    }
}

/// Immutable routing table: exact hosts, then wildcards, then catch-all.
#[derive(Debug, Default)]
pub struct Router {
    exact: HashMap<String, Vec<Arc<Route>>>,
    wildcard: Vec<(String, Vec<Arc<Route>>)>,
    any: Vec<Arc<Route>>,
    count: usize,
}

fn sort_group(group: &mut [Arc<Route>]) {
    // Longest prefix first; stable sort keeps configuration order on ties.
    group.sort_by_key(|r| std::cmp::Reverse(r.prefix.len()));
}

impl Router {
    /// Build a router from `(hosts, route)` pairs given in config order.
    pub fn build(entries: Vec<(Vec<String>, Arc<Route>)>) -> Self {
        let mut exact: HashMap<String, Vec<Arc<Route>>> = HashMap::new();
        let mut wild: HashMap<String, Vec<Arc<Route>>> = HashMap::new();
        let mut any = Vec::new();
        let count = entries.len();
        for (hosts, route) in entries {
            if hosts.is_empty() {
                any.push(route);
                continue;
            }
            for h in hosts {
                let h = h.to_ascii_lowercase();
                match h.strip_prefix("*.") {
                    Some(suffix) => wild.entry(suffix.to_owned()).or_default().push(Arc::clone(&route)),
                    None => exact.entry(h).or_default().push(Arc::clone(&route)),
                }
            }
        }
        exact.values_mut().for_each(|g| sort_group(g));
        let mut wildcard: Vec<_> = wild.into_iter().collect();
        wildcard.iter_mut().for_each(|(_, g)| sort_group(g));
        wildcard.sort_by_key(|(s, _)| std::cmp::Reverse(s.len()));
        sort_group(&mut any);
        Self { exact, wildcard, any, count }
    }

    /// Number of routes.
    pub fn len(&self) -> usize {
        self.count
    }

    /// `true` if there are no routes.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Find the route for `host` (already stripped of its port) and `path`.
    ///
    /// Precedence: exact host → longest matching wildcard → any host; within a
    /// group the longest matching path prefix wins.
    pub fn find(&self, host: &str, path: &str) -> Option<&Arc<Route>> {
        let mut buf = [0u8; 256];
        let host_lc: &str = if host.len() <= buf.len() {
            let dst = &mut buf[..host.len()];
            dst.copy_from_slice(host.as_bytes());
            dst.make_ascii_lowercase();
            std::str::from_utf8(dst).unwrap_or("")
        } else {
            ""
        };
        if let Some(group) = self.exact.get(host_lc) {
            if let Some(r) = group.iter().find(|r| r.matches_path(path)) {
                return Some(r);
            }
        }
        for (suffix, group) in &self.wildcard {
            let is_sub = host_lc.len() > suffix.len() + 1
                && host_lc.ends_with(suffix.as_str())
                && host_lc.as_bytes()[host_lc.len() - suffix.len() - 1] == b'.';
            if is_sub {
                if let Some(r) = group.iter().find(|r| r.matches_path(path)) {
                    return Some(r);
                }
            }
        }
        self.any.iter().find(|r| r.matches_path(path))
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::state::SharedState;

    fn state(extra: &str) -> std::sync::Arc<SharedState> {
        let text = format!(
            r#"
            [server]
            http_addr = "127.0.0.1:8080"
            [[upstream]]
            name = "a"
            backends = [{{ addr = "127.0.0.1:1" }}]
            [[upstream]]
            name = "b"
            backends = [{{ addr = "127.0.0.1:2" }}]
            [[upstream]]
            name = "c"
            backends = [{{ addr = "127.0.0.1:3" }}]
            {extra}
        "#
        );
        SharedState::new(Config::from_toml_str(&text).unwrap()).unwrap()
    }

    fn pick(s: &SharedState, host: &str, path: &str) -> Option<String> {
        s.load().router.find(host, path).map(|r| r.upstream.name.to_string())
    }

    #[test]
    fn precedence_exact_wildcard_any_and_longest_prefix() {
        let s = state(
            r#"
            [[route]]
            upstream = "c"
            [[route]]
            hosts = ["*.example.com"]
            upstream = "b"
            [[route]]
            hosts = ["api.example.com"]
            upstream = "a"
            [[route]]
            hosts = ["api.example.com"]
            path_prefix = "/v2"
            upstream = "c"
            [[route]]
            hosts = ["*.example.com"]
            path_prefix = "/static"
            upstream = "a"
        "#,
        );
        assert_eq!(pick(&s, "api.example.com", "/v1/x").as_deref(), Some("a"));
        assert_eq!(pick(&s, "API.Example.COM", "/v2/x").as_deref(), Some("c"));
        assert_eq!(pick(&s, "www.example.com", "/").as_deref(), Some("b"));
        assert_eq!(pick(&s, "www.example.com", "/static/a.css").as_deref(), Some("a"));
        assert_eq!(pick(&s, "example.com", "/").as_deref(), Some("c"), "wildcard must not match apex");
        assert_eq!(pick(&s, "other.org", "/").as_deref(), Some("c"));
    }

    #[test]
    fn prefix_matches_on_segment_boundary_only() {
        let s = state(
            r#"
            [[route]]
            path_prefix = "/api"
            upstream = "a"
        "#,
        );
        assert!(pick(&s, "h", "/api").is_some());
        assert!(pick(&s, "h", "/api/x").is_some());
        assert!(pick(&s, "h", "/apix").is_none());
        assert!(pick(&s, "h", "/").is_none());
    }

    #[test]
    fn strip_prefix_rewrites() {
        let s = state(
            r#"
            [[route]]
            path_prefix = "/api"
            strip_prefix = true
            upstream = "a"
        "#,
        );
        let snap = s.load();
        let r = snap.router.find("h", "/api/users").unwrap();
        assert_eq!(r.rewrite_path("/api/users"), "/users");
        assert_eq!(r.rewrite_path("/api"), "/");
    }

    #[test]
    fn effective_rate_limit_resolution() {
        let s = state(
            r#"
            [rate_limit]
            requests_per_second = 5.0
            burst = 10
            [[route]]
            hosts = ["a.test"]
            upstream = "a"
            [[route]]
            hosts = ["b.test"]
            upstream = "a"
            rate_limit = { enabled = false }
            [[route]]
            hosts = ["c.test"]
            upstream = "a"
            rate_limit = { requests_per_second = 1.0, burst = 2 }
        "#,
        );
        let snap = s.load();
        assert_eq!(snap.router.find("a.test", "/").unwrap().rate_limit.as_ref().unwrap().burst, 10);
        assert!(snap.router.find("b.test", "/").unwrap().rate_limit.is_none());
        assert_eq!(snap.router.find("c.test", "/").unwrap().rate_limit.as_ref().unwrap().burst, 2);
    }
}
