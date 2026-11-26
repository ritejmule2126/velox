//! `velox doctor`: pre-flight checks before putting an instance into production.
//!
//! Every check reports one of four states — `ok`, `warn` (works, but a known
//! operational risk), `fail` (will not work / will fall over under the load the
//! configuration allows) or `skip` (not applicable on this system) — plus a
//! plain-language detail and, where there is one, the command that fixes it.
//! Warnings never fail the run unless `--strict` is given.
//!
//! The host is reached only through the [`Host`] trait, so each threshold and
//! each platform branch is tested with a simulated machine.

use serde::Serialize;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use velox_core::config::BackendAddr;
use velox_core::Config;

/// QUIC wants large socket buffers; quic-go and Cloudflare both document ~7 MiB.
pub const QUIC_BUFFER_TARGET: u64 = 7_340_032;
/// Descriptors needed beyond the connections themselves (listeners, logs, pools, DNS, health checks).
pub const FD_HEADROOM: u64 = 512;

/// The result of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Fine.
    Ok,
    /// Works, but is a known operational risk.
    Warn,
    /// Broken, or will break under the configured load.
    Fail,
    /// Not applicable here.
    Skip,
}

impl Status {
    fn tag(self) -> &'static str {
        match self {
            Self::Ok => " OK ",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }
}

/// One finding.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Short identifier (`fd-limit`, `tls-expiry`, …).
    pub name: String,
    /// Outcome.
    pub status: Status,
    /// What was found.
    pub detail: String,
    /// How to fix it, when there is a standard fix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// A resource limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// No limit.
    Unlimited,
    /// At most this many.
    Finite(u64),
}

/// What `doctor` needs to know about the machine it runs on.
pub trait Host {
    /// `linux`, `macos`, …
    fn os(&self) -> &str;
    /// Soft and hard open-files limits of this process's environment.
    fn fd_limits(&self) -> Option<(Limit, Limit)>;
    /// A kernel parameter, e.g. `net.core.rmem_max`.
    fn sysctl(&self, name: &str) -> Option<u64>;
    /// Available CPU parallelism.
    fn cpus(&self) -> usize;
    /// Seconds since the Unix epoch.
    fn now_unix(&self) -> i64;
    /// Can this TCP address be bound right now?
    fn probe_tcp(&self, addr: SocketAddr) -> std::io::Result<()>;
    /// Can this UDP address be bound right now?
    fn probe_udp(&self, addr: SocketAddr) -> std::io::Result<()>;
}

/// The real machine.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealHost;

fn parse_limit(s: &str) -> Option<Limit> {
    let s = s.trim();
    if s == "unlimited" {
        Some(Limit::Unlimited)
    } else {
        s.parse().ok().map(Limit::Finite)
    }
}

impl Host for RealHost {
    fn os(&self) -> &str {
        std::env::consts::OS
    }

    fn fd_limits(&self) -> Option<(Limit, Limit)> {
        // A child shell inherits exactly the limits this process runs under.
        let out = std::process::Command::new("sh").args(["-c", "ulimit -Sn; ulimit -Hn"]).output().ok()?;
        let text = String::from_utf8(out.stdout).ok()?;
        let mut lines = text.lines();
        Some((parse_limit(lines.next()?)?, parse_limit(lines.next()?)?))
    }

    fn sysctl(&self, name: &str) -> Option<u64> {
        let path = format!("/proc/sys/{}", name.replace('.', "/"));
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    fn cpus(&self) -> usize {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    }

    fn now_unix(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }

    fn probe_tcp(&self, addr: SocketAddr) -> std::io::Result<()> {
        std::net::TcpListener::bind(addr).map(drop)
    }

    fn probe_udp(&self, addr: SocketAddr) -> std::io::Result<()> {
        std::net::UdpSocket::bind(addr).map(drop)
    }
}

/// What to check and how strictly.
#[derive(Debug, Clone)]
pub struct Options {
    /// Warn when a certificate expires within this many days.
    pub warn_days: i64,
    /// Also try a TCP connection to every backend.
    pub check_backends: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { warn_days: 14, check_backends: false }
    }
}

/// Everything found.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// The findings, in the order they were made.
    pub checks: Vec<Check>,
}

impl Report {
    fn push(&mut self, name: &str, status: Status, detail: impl Into<String>, hint: Option<&str>) {
        self.checks.push(Check { name: name.to_owned(), status, detail: detail.into(), hint: hint.map(str::to_owned) });
    }

    /// How many checks have `status`.
    pub fn count(&self, status: Status) -> usize {
        self.checks.iter().filter(|c| c.status == status).count()
    }

    /// The process exit code: `1` if anything failed (or warned, with `strict`).
    pub fn exit_code(&self, strict: bool) -> i32 {
        i32::from(self.count(Status::Fail) > 0 || (strict && self.count(Status::Warn) > 0))
    }

    /// Human-readable output.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        for c in &self.checks {
            out.push_str(&format!("[{}] {:<14} {}\n", c.status.tag(), c.name, c.detail));
            if let Some(h) = &c.hint {
                out.push_str(&format!("       {:<14} fix: {h}\n", ""));
            }
        }
        out.push_str(&format!(
            "\n{} ok, {} warning(s), {} failure(s), {} skipped\n",
            self.count(Status::Ok),
            self.count(Status::Warn),
            self.count(Status::Fail),
            self.count(Status::Skip)
        ));
        out
    }

    /// Machine-readable output.
    pub fn render_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_owned())
    }
}

fn describe_days(days: i64) -> String {
    match days {
        d if d < 0 => format!("expired {} day(s) ago", -d),
        0 => "expires today".to_owned(),
        d => format!("{d} day(s) left"),
    }
}

/// Run every check against the configuration at `path`.
pub async fn run(path: &Path, host: &dyn Host, opts: &Options) -> Report {
    let mut r = Report { checks: Vec::new() };

    // ---- the configuration itself (everything else depends on it) ----
    let cfg = match load_config(path) {
        Ok(c) => {
            r.push("config", Status::Ok, format!("{} parses and validates", path.display()), None);
            c
        }
        Err(e) => {
            r.push("config", Status::Fail, e, Some("run `velox validate` for the full list of problems"));
            r.push("system", Status::Skip, "system checks need a valid configuration", None);
            return r;
        }
    };

    r.push(
        "allocator",
        Status::Ok,
        if cfg!(feature = "mimalloc") {
            "mimalloc (compiled in)"
        } else {
            "the system allocator (built without the `mimalloc` feature)"
        },
        None,
    );
    check_fd_limit(&mut r, &cfg, host);
    check_kernel(&mut r, &cfg, host);
    check_workers(&mut r, &cfg, host);
    check_certificates(&mut r, &cfg, host, opts);
    check_listeners(&mut r, &cfg, host);
    if opts.check_backends {
        check_backends(&mut r, &cfg).await;
    }
    r
}

fn load_config(path: &Path) -> Result<Config, String> {
    let cfg = Config::load(path).map_err(|e| e.to_string())?;
    cfg.validate_files().map_err(|e| e.to_string())?;
    velox_security::jwt::check_config(&cfg)?;
    if let Some(ca) = &cfg.tls.client_ca_file {
        velox_security::client_cert::ClientAuth::check(ca).map_err(|e| e.to_string())?;
    }
    Ok(cfg)
}

fn check_fd_limit(r: &mut Report, cfg: &Config, host: &dyn Host) {
    let max = u64::try_from(cfg.limits.max_connections).unwrap_or(u64::MAX);
    let Some((soft, hard)) = host.fd_limits() else {
        r.push("fd-limit", Status::Skip, "could not read the open-files limit", None);
        return;
    };
    if max == 0 {
        r.push(
            "fd-limit",
            Status::Warn,
            "limits.max_connections = 0 (unlimited): descriptors cannot be sized, so the process will hit its limit under a connection flood",
            Some("set limits.max_connections to what the host can carry"),
        );
        return;
    }
    // Each client connection can hold a pooled upstream connection too.
    let need = max.saturating_mul(2).saturating_add(FD_HEADROOM);
    let Limit::Finite(have) = soft else {
        r.push("fd-limit", Status::Ok, format!("unlimited (needs about {need} for max_connections = {max})"), None);
        return;
    };
    let hint = match hard {
        Limit::Unlimited => format!("ulimit -n {need}   # or LimitNOFILE={need} in the systemd unit"),
        Limit::Finite(h) if h >= need => format!("ulimit -n {need}   # (hard limit is {h})"),
        Limit::Finite(h) => format!("raise the hard limit (currently {h}): LimitNOFILE={need} in the systemd unit or `--ulimit nofile={need}` for Docker"),
    };
    if have >= need {
        r.push(
            "fd-limit",
            Status::Ok,
            format!("{have} descriptors (needs about {need} for max_connections = {max})"),
            None,
        );
    } else if have >= max.saturating_add(FD_HEADROOM) {
        r.push(
            "fd-limit",
            Status::Warn,
            format!("{have} descriptors covers {max} clients but not their upstream connections (about {need} wanted)"),
            Some(&hint),
        );
    } else {
        r.push(
            "fd-limit",
            Status::Fail,
            format!("{have} descriptors cannot serve limits.max_connections = {max} (about {need} needed): accepting would fail with EMFILE"),
            Some(&hint),
        );
    }
}

fn check_kernel(r: &mut Report, cfg: &Config, host: &dyn Host) {
    let linux = host.os() == "linux";
    // HTTP/3 socket buffers.
    let h3 = cfg.server.h3 && cfg.server.https_addr.is_some();
    if !h3 {
        r.push("udp-buffers", Status::Skip, "HTTP/3 is not enabled", None);
    } else if !linux {
        r.push(
            "udp-buffers",
            Status::Skip,
            format!("kernel buffer limits are checked on Linux only (this is {})", host.os()),
            None,
        );
    } else {
        let (rmem, wmem) = (host.sysctl("net.core.rmem_max"), host.sysctl("net.core.wmem_max"));
        match (rmem, wmem) {
            (Some(rm), Some(wm)) if rm >= QUIC_BUFFER_TARGET && wm >= QUIC_BUFFER_TARGET => {
                r.push("udp-buffers", Status::Ok, format!("net.core.rmem_max = {rm}, wmem_max = {wm}"), None);
            }
            (Some(rm), Some(wm)) => r.push(
                "udp-buffers",
                Status::Warn,
                format!(
                    "net.core.rmem_max = {rm}, wmem_max = {wm}: QUIC wants at least {QUIC_BUFFER_TARGET}; HTTP/3 will drop packets and stall under load"
                ),
                Some("sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000   # persist in /etc/sysctl.d/"),
            ),
            _ => r.push("udp-buffers", Status::Skip, "could not read net.core.rmem_max / wmem_max", None),
        }
    }
    // Accept backlog.
    if linux {
        match host.sysctl("net.core.somaxconn") {
            Some(max) if u64::try_from(cfg.server.backlog).unwrap_or(0) > max => r.push(
                "backlog",
                Status::Warn,
                format!(
                    "server.backlog = {} but net.core.somaxconn = {max}: the kernel silently clamps it",
                    cfg.server.backlog
                ),
                Some(&format!("sysctl -w net.core.somaxconn={}", cfg.server.backlog)),
            ),
            Some(max) => r.push(
                "backlog",
                Status::Ok,
                format!("server.backlog = {} (net.core.somaxconn = {max})", cfg.server.backlog),
                None,
            ),
            None => r.push("backlog", Status::Skip, "could not read net.core.somaxconn", None),
        }
    } else {
        r.push("backlog", Status::Skip, format!("somaxconn is checked on Linux only (this is {})", host.os()), None);
    }
}

fn check_workers(r: &mut Report, cfg: &Config, host: &dyn Host) {
    let (workers, cpus) = (cfg.server.accept_workers, host.cpus());
    if workers > cpus {
        r.push(
            "accept-workers",
            Status::Warn,
            format!("server.accept_workers = {workers} but only {cpus} CPU(s) are available"),
            Some(&format!("accept_workers = {cpus}")),
        );
    } else if workers > 1 && !cfg.server.reuse_port {
        r.push(
            "accept-workers",
            Status::Warn,
            format!("server.accept_workers = {workers} with reuse_port = false: the workers share one listener and contend on its accept queue"),
            Some("reuse_port = true gives each worker its own SO_REUSEPORT socket"),
        );
    } else if workers > 1 {
        r.push("accept-workers", Status::Ok, format!("{workers} accept workers on {cpus} CPU(s), SO_REUSEPORT"), None);
    } else {
        r.push(
            "accept-workers",
            Status::Ok,
            format!("1 accept worker on {cpus} CPU(s) (raise server.accept_workers with reuse_port = true if one accept loop saturates a core)"),
            None,
        );
    }
}

fn expiry_check(
    r: &mut Report,
    name: &str,
    what: &str,
    not_after: Result<i64, String>,
    host: &dyn Host,
    opts: &Options,
) {
    match not_after {
        Err(e) => r.push(name, Status::Fail, format!("{what}: {e}"), None),
        Ok(t) => {
            // Floor division, so "23 hours left" is 0 days, not "expired".
            let days = (t - host.now_unix()).div_euclid(86_400);
            let status = if days < 0 {
                Status::Fail
            } else if days < opts.warn_days {
                Status::Warn
            } else {
                Status::Ok
            };
            let hint = (status != Status::Ok).then_some("renew or rotate the certificate (and reload: `velox reload`)");
            r.push(name, status, format!("{what}: {}", describe_days(days)), hint);
        }
    }
}

fn check_certificates(r: &mut Report, cfg: &Config, host: &dyn Host, opts: &Options) {
    use velox_security::tls::{bundle_earliest_not_after, leaf_not_after};
    let before = r.checks.len();
    for c in &cfg.tls.certs {
        let what = format!("{}", c.cert_file.display());
        expiry_check(r, "tls-expiry", &what, leaf_not_after(&c.cert_file).map_err(|e| e.to_string()), host, opts);
    }
    if cfg.tls.certs.is_empty() && cfg.tls.self_signed_fallback {
        r.push(
            "tls-expiry",
            Status::Warn,
            "no certificates configured: clients will get a throwaway self-signed certificate (tls.self_signed_fallback)",
            Some("configure [[tls.certs]] or [tls.acme] for production"),
        );
    }
    if let Some(ca) = &cfg.tls.client_ca_file {
        expiry_check(
            r,
            "client-ca",
            &ca.display().to_string(),
            bundle_earliest_not_after(ca).map_err(|e| e.to_string()),
            host,
            opts,
        );
    }
    for u in &cfg.upstreams {
        let Some(t) = &u.tls else { continue };
        if let Some(cert) = &t.client_cert_file {
            let what = format!("upstream `{}` client certificate {}", u.name, cert.display());
            expiry_check(r, "upstream-mtls", &what, leaf_not_after(cert).map_err(|e| e.to_string()), host, opts);
        }
        if let Some(ca) = &t.ca_file {
            let what = format!("upstream `{}` CA bundle {}", u.name, ca.display());
            expiry_check(r, "upstream-ca", &what, bundle_earliest_not_after(ca).map_err(|e| e.to_string()), host, opts);
        }
    }
    if r.checks.len() == before {
        let why = if cfg.server.https_addr.is_some() {
            "certificates are issued dynamically (ACME)"
        } else {
            "no TLS configured"
        };
        r.push("tls-expiry", Status::Skip, why, None);
    }
}

fn check_listeners(r: &mut Report, cfg: &Config, host: &dyn Host) {
    let mut probes: Vec<(String, SocketAddr, bool)> = Vec::new();
    let s = &cfg.server;
    let mut tcp = |what: &str, a: Option<SocketAddr>| {
        if let Some(a) = a.filter(|a| a.port() != 0) {
            probes.push((what.to_owned(), a, false));
        }
    };
    tcp("http", s.http_addr);
    tcp("https", s.https_addr);
    tcp("admin", cfg.admin.addr);
    tcp("metrics", cfg.telemetry.metrics_addr);
    for t in &cfg.tcp_proxies {
        tcp("tcp_proxy", Some(t.listen));
    }
    if s.h3 {
        if let Some(a) = s.h3_addr.or(s.https_addr).filter(|a| a.port() != 0) {
            probes.push(("h3 (udp)".to_owned(), a, true));
        }
    }
    if probes.is_empty() {
        r.push("listeners", Status::Skip, "every listener uses an OS-assigned port", None);
        return;
    }
    for (what, addr, udp) in probes {
        let result = if udp { host.probe_udp(addr) } else { host.probe_tcp(addr) };
        match result {
            Ok(()) => r.push("listeners", Status::Ok, format!("{what} {addr} is free"), None),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => r.push(
                "listeners",
                Status::Warn,
                format!("{what} {addr} is already in use (is another velox, or something else, running?)"),
                None,
            ),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => r.push(
                "listeners",
                Status::Fail,
                format!("{what} {addr}: permission denied (privileged port)"),
                Some("run with CAP_NET_BIND_SERVICE (setcap 'cap_net_bind_service=+ep' velox) or listen on a port above 1024"),
            ),
            Err(e) => r.push("listeners", Status::Fail, format!("{what} {addr}: {e}"), None),
        }
    }
}

async fn check_backends(r: &mut Report, cfg: &Config) {
    for u in &cfg.upstreams {
        for b in &u.backends {
            let addr = match &b.addr {
                BackendAddr::Tls { host, port } => BackendAddr::Tcp { host: host.clone(), port: *port },
                other => other.clone(),
            };
            let name = format!("{} ({})", b.addr, u.name);
            match velox_proxy::upstream::connect_backend(&addr, Duration::from_secs(2), true).await {
                Ok(_) => r.push("backends", Status::Ok, format!("{name} accepts connections"), None),
                Err(e) => r.push(
                    "backends",
                    Status::Warn,
                    format!("{name}: {e}"),
                    Some("a backend that is down at launch is fine if health checks will bring it in; check the address otherwise"),
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::ErrorKind;

    /// A simulated machine.
    struct Fake {
        os: &'static str,
        fds: Option<(Limit, Limit)>,
        sysctls: HashMap<&'static str, u64>,
        cpus: usize,
        now: i64,
        busy_tcp: Vec<u16>,
        denied_tcp: Vec<u16>,
        busy_udp: Vec<u16>,
    }

    impl Fake {
        fn linux() -> Self {
            Self {
                os: "linux",
                fds: Some((Limit::Finite(1_048_576), Limit::Finite(1_048_576))),
                sysctls: HashMap::from([
                    ("net.core.rmem_max", 8_000_000),
                    ("net.core.wmem_max", 8_000_000),
                    ("net.core.somaxconn", 4096),
                ]),
                cpus: 8,
                now: 1_800_000_000,
                busy_tcp: vec![],
                denied_tcp: vec![],
                busy_udp: vec![],
            }
        }
    }

    impl Host for Fake {
        fn os(&self) -> &str {
            self.os
        }
        fn fd_limits(&self) -> Option<(Limit, Limit)> {
            self.fds
        }
        fn sysctl(&self, name: &str) -> Option<u64> {
            self.sysctls.get(name).copied()
        }
        fn cpus(&self) -> usize {
            self.cpus
        }
        fn now_unix(&self) -> i64 {
            self.now
        }
        fn probe_tcp(&self, a: SocketAddr) -> std::io::Result<()> {
            if self.denied_tcp.contains(&a.port()) {
                Err(ErrorKind::PermissionDenied.into())
            } else if self.busy_tcp.contains(&a.port()) {
                Err(ErrorKind::AddrInUse.into())
            } else {
                Ok(())
            }
        }
        fn probe_udp(&self, a: SocketAddr) -> std::io::Result<()> {
            if self.busy_udp.contains(&a.port()) {
                Err(ErrorKind::AddrInUse.into())
            } else {
                Ok(())
            }
        }
    }

    fn config(dir: &Path, extra_server: &str, extra: &str) -> std::path::PathBuf {
        let path = dir.join("velox.toml");
        std::fs::write(
            &path,
            format!(
                "[server]\nhttp_addr = \"127.0.0.1:18080\"\nhttps_addr = \"127.0.0.1:18443\"\n{extra_server}\n\
                 [tls]\nself_signed_fallback = true\n[admin]\naddr = \"127.0.0.1:18901\"\n\
                 [[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"127.0.0.1:19\" }}]\n[[route]]\nupstream = \"app\"\n{extra}\n"
            ),
        )
        .unwrap();
        path
    }

    async fn report(host: &Fake, extra_server: &str, extra: &str) -> Report {
        let dir = tempfile::tempdir().unwrap();
        run(&config(dir.path(), extra_server, extra), host, &Options::default()).await
    }

    fn find<'a>(r: &'a Report, name: &str) -> Vec<&'a Check> {
        r.checks.iter().filter(|c| c.name == name).collect()
    }

    fn status(r: &Report, name: &str) -> Status {
        find(r, name).first().unwrap_or_else(|| panic!("no `{name}` check in {r:?}")).status
    }

    #[tokio::test]
    async fn a_well_provisioned_linux_host_passes() {
        let r = report(&Fake::linux(), "", "").await;
        for name in ["config", "fd-limit", "udp-buffers", "backlog", "accept-workers"] {
            assert_eq!(status(&r, name), Status::Ok, "{name}: {}", r.render_text());
        }
        // The default self-signed fallback is called out, but is only a warning.
        assert_eq!(status(&r, "tls-expiry"), Status::Warn);
        assert_eq!(r.exit_code(false), 0);
        assert_eq!(r.exit_code(true), 1, "--strict turns warnings into a failing exit");
    }

    #[tokio::test]
    async fn the_descriptor_limit_is_judged_against_max_connections() {
        let with = |soft: Limit, hard: Limit| Fake { fds: Some((soft, hard)), ..Fake::linux() };
        let cfg = "\n[limits]\nmax_connections = 10000\n";
        // Plenty (client + upstream sockets + headroom).
        assert_eq!(
            status(&report(&with(Limit::Finite(30_000), Limit::Finite(30_000)), "", cfg).await, "fd-limit"),
            Status::Ok
        );
        assert_eq!(status(&report(&with(Limit::Unlimited, Limit::Unlimited), "", cfg).await, "fd-limit"), Status::Ok);
        // Enough for the clients, not for their upstream connections.
        let r = report(&with(Limit::Finite(12_000), Limit::Finite(1_048_576)), "", cfg).await;
        let c = &find(&r, "fd-limit")[0];
        assert_eq!(c.status, Status::Warn, "{}", r.render_text());
        assert!(c.hint.as_deref().unwrap().contains("ulimit -n 20512"), "{:?}", c.hint);
        // Not even enough to accept the configured connections.
        let r = report(&with(Limit::Finite(1024), Limit::Finite(4096)), "", cfg).await;
        let c = &find(&r, "fd-limit")[0];
        assert_eq!(c.status, Status::Fail, "{}", r.render_text());
        assert!(c.detail.contains("EMFILE") && c.hint.as_deref().unwrap().contains("hard limit"), "{c:?}");
        assert_eq!(r.exit_code(false), 1);
        // Unlimited connections cannot be sized.
        let r = report(&Fake::linux(), "", "\n[limits]\nmax_connections = 0\n").await;
        assert_eq!(status(&r, "fd-limit"), Status::Warn);
        // Unreadable limits are skipped, not guessed.
        let r = report(&Fake { fds: None, ..Fake::linux() }, "", "").await;
        assert_eq!(status(&r, "fd-limit"), Status::Skip);
    }

    #[tokio::test]
    async fn quic_buffers_and_the_accept_backlog_are_checked_on_linux_only() {
        let small = |rmem: u64, wmem: u64| Fake {
            sysctls: HashMap::from([
                ("net.core.rmem_max", rmem),
                ("net.core.wmem_max", wmem),
                ("net.core.somaxconn", 128),
            ]),
            ..Fake::linux()
        };
        // The kernel default (212992) is far below what QUIC needs.
        let r = report(&small(212_992, 212_992), "", "").await;
        let c = &find(&r, "udp-buffers")[0];
        assert_eq!(c.status, Status::Warn);
        assert!(c.hint.as_deref().unwrap().contains("net.core.rmem_max=7500000"), "{c:?}");
        // Either buffer being small is enough.
        assert_eq!(status(&report(&small(8_000_000, 212_992), "", "").await, "udp-buffers"), Status::Warn);
        assert_eq!(
            status(&report(&small(QUIC_BUFFER_TARGET, QUIC_BUFFER_TARGET), "", "").await, "udp-buffers"),
            Status::Ok
        );
        // backlog (default 1024) above somaxconn is silently clamped.
        let r = report(&small(8_000_000, 8_000_000), "", "").await;
        assert_eq!(status(&r, "backlog"), Status::Warn);
        assert!(find(&r, "backlog")[0].detail.contains("clamps"));
        // Not Linux: nothing to read, so skip instead of guessing.
        let mac = Fake { os: "macos", sysctls: HashMap::new(), ..Fake::linux() };
        let r = report(&mac, "", "").await;
        assert_eq!(status(&r, "udp-buffers"), Status::Skip);
        assert_eq!(status(&r, "backlog"), Status::Skip);
        assert!(find(&r, "udp-buffers")[0].detail.contains("macos"));
        // HTTP/3 off: the UDP buffers do not matter.
        let r = report(&small(1, 1), "h3 = false", "").await;
        assert_eq!(status(&r, "udp-buffers"), Status::Skip);
    }

    #[tokio::test]
    async fn accept_worker_sizing() {
        let r = report(&Fake { cpus: 4, ..Fake::linux() }, "accept_workers = 16", "").await;
        assert_eq!(status(&r, "accept-workers"), Status::Warn);
        assert!(find(&r, "accept-workers")[0].hint.as_deref().unwrap().contains("accept_workers = 4"));
        let r = report(&Fake::linux(), "accept_workers = 4\nreuse_port = false", "").await;
        assert_eq!(status(&r, "accept-workers"), Status::Warn);
        assert!(find(&r, "accept-workers")[0].detail.contains("contend"));
        assert_eq!(status(&report(&Fake::linux(), "accept_workers = 4", "").await, "accept-workers"), Status::Ok);
    }

    #[tokio::test]
    async fn listeners_that_are_taken_or_privileged_are_reported() {
        let r = report(&Fake { busy_tcp: vec![18080], busy_udp: vec![18443], ..Fake::linux() }, "", "").await;
        let listeners = find(&r, "listeners");
        assert_eq!(listeners.len(), 4, "http, https, admin and h3: {}", r.render_text());
        assert_eq!(listeners.iter().filter(|c| c.status == Status::Warn).count(), 2, "{}", r.render_text());
        assert!(listeners.iter().any(|c| c.detail.contains("h3 (udp)") && c.detail.contains("already in use")));
        let r = report(&Fake { denied_tcp: vec![18080], ..Fake::linux() }, "", "").await;
        let denied = find(&r, "listeners").into_iter().find(|c| c.status == Status::Fail).unwrap();
        assert!(denied.hint.as_deref().unwrap().contains("CAP_NET_BIND_SERVICE"), "{denied:?}");
        assert_eq!(r.exit_code(false), 1);
    }

    #[tokio::test]
    async fn certificate_expiry_warns_early_and_fails_when_lapsed() {
        let dir = tempfile::tempdir().unwrap();
        let cert = |name: &str, days: i64| {
            let mut p = rcgen::CertificateParams::new(vec!["a.test".into()]).unwrap();
            let now = time::OffsetDateTime::now_utc();
            p.not_before = now - time::Duration::days(60);
            p.not_after = now + time::Duration::days(days);
            let key = rcgen::KeyPair::generate().unwrap();
            let c = p.self_signed(&key).unwrap();
            let (cp, kp) = (dir.path().join(format!("{name}.crt")), dir.path().join(format!("{name}.key")));
            std::fs::write(&cp, c.pem()).unwrap();
            std::fs::write(&kp, key.serialize_pem()).unwrap();
            (cp, kp)
        };
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let host = Fake { now, ..Fake::linux() };
        for (days, want) in [(90, Status::Ok), (10, Status::Warn), (-3, Status::Fail)] {
            let (c, k) = cert(&format!("c{days}"), days);
            let path = dir.path().join(format!("v{days}.toml"));
            std::fs::write(
                &path,
                format!(
                    "[server]\nhttps_addr = \"127.0.0.1:18443\"\nh3 = false\n[[tls.certs]]\ncert_file = \"{}\"\nkey_file = \"{}\"\n\
                     [[upstream]]\nname = \"a\"\nbackends = [{{ addr = \"127.0.0.1:19\" }}]\n[[route]]\nupstream = \"a\"\n",
                    c.display(),
                    k.display()
                ),
            )
            .unwrap();
            let r = run(&path, &host, &Options::default()).await;
            let check = &find(&r, "tls-expiry")[0];
            assert_eq!(check.status, want, "{days} days: {check:?}");
            assert!(check.detail.contains(&c.display().to_string()), "{check:?}");
            if want == Status::Fail {
                assert!(check.detail.contains("expired"), "{check:?}");
                assert_eq!(r.exit_code(false), 1);
            }
            // The warning threshold is configurable.
            let strict = run(&path, &host, &Options { warn_days: 100, ..Options::default() }).await;
            if want == Status::Ok {
                assert_eq!(find(&strict, "tls-expiry")[0].status, Status::Warn, "90 days is under a 100-day threshold");
            }
        }
    }

    #[tokio::test]
    async fn a_broken_configuration_fails_fast_and_skips_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "[server]\nhttp_addr = \"127.0.0.1:1\"\n[[route]]\nupstream = \"missing\"\n").unwrap();
        let r = run(&bad, &Fake::linux(), &Options::default()).await;
        assert_eq!(status(&r, "config"), Status::Fail);
        assert!(find(&r, "config")[0].detail.contains("unknown upstream"), "{}", r.render_text());
        assert_eq!(status(&r, "system"), Status::Skip);
        assert_eq!(r.checks.len(), 2);
        assert_eq!(r.exit_code(false), 1);
        // A missing file is a failure with the path in it.
        let r = run(&dir.path().join("nope.toml"), &Fake::linux(), &Options::default()).await;
        assert_eq!(status(&r, "config"), Status::Fail);
        // Unusable key material is a configuration failure too.
        let jwt = dir.path().join("jwt.toml");
        std::fs::write(&jwt, "[server]\nhttp_addr = \"127.0.0.1:1\"\n[[upstream]]\nname=\"a\"\nbackends=[{addr=\"127.0.0.1:2\"}]\n[[route]]\nupstream=\"a\"\n[route.jwt]\nsecret_file = \"/nonexistent\"\nalgorithms = [\"HS256\"]\n").unwrap();
        assert_eq!(status(&run(&jwt, &Fake::linux(), &Options::default()).await, "config"), Status::Fail);
    }

    #[tokio::test]
    async fn backends_are_probed_only_on_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up = listener.local_addr().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.toml");
        std::fs::write(
            &path,
            format!(
                "[server]\nhttp_addr = \"127.0.0.1:0\"\n[[upstream]]\nname = \"a\"\nbackends = [{{ addr = \"{up}\" }}, {{ addr = \"127.0.0.1:1\" }}]\n\
                 [[route]]\nupstream = \"a\"\n"
            ),
        )
        .unwrap();
        let off = run(&path, &Fake::linux(), &Options::default()).await;
        assert!(find(&off, "backends").is_empty());
        let on = run(&path, &Fake::linux(), &Options { check_backends: true, ..Options::default() }).await;
        let b = find(&on, "backends");
        assert_eq!((b[0].status, b[1].status), (Status::Ok, Status::Warn), "{}", on.render_text());
        assert_eq!(on.exit_code(false), 0, "an unreachable backend is a warning: health checks may bring it in");
    }

    #[test]
    fn output_formats() {
        let mut r = Report { checks: vec![] };
        r.push("fd-limit", Status::Fail, "too few", Some("ulimit -n 99999"));
        r.push("config", Status::Ok, "fine", None);
        let text = r.render_text();
        assert!(
            text.contains("[FAIL] fd-limit") && text.contains("fix: ulimit -n 99999") && text.contains("[ OK ] config"),
            "{text}"
        );
        assert!(text.contains("1 ok, 0 warning(s), 1 failure(s), 0 skipped"));
        let json: serde_json::Value = serde_json::from_str(&r.render_json()).unwrap();
        assert_eq!(json["checks"][0]["status"], "fail");
        assert_eq!(json["checks"][0]["hint"], "ulimit -n 99999");
        assert!(json["checks"][1].get("hint").is_none());
        assert_eq!(parse_limit("unlimited"), Some(Limit::Unlimited));
        assert_eq!(parse_limit("1024\n"), Some(Limit::Finite(1024)));
        assert_eq!(parse_limit("garbage"), None);
    }

    #[tokio::test]
    async fn the_real_host_reports_plausible_facts() {
        let h = RealHost;
        assert!(h.cpus() >= 1);
        assert!(h.now_unix() > 1_700_000_000);
        assert!(!h.os().is_empty());
        if let Some((soft, hard)) = h.fd_limits() {
            if let (Limit::Finite(s), Limit::Finite(hd)) = (soft, hard) {
                assert!(s <= hd && s >= 16, "soft {s} hard {hd}");
            }
        }
        // An address we just bound is busy; a fresh one is free.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        assert!(h.probe_tcp(addr).is_err(), "bound by us");
        drop(l);
        assert!(h.probe_tcp(addr).is_ok());
    }
}
