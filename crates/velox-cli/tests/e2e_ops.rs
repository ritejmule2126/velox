//! Operational behaviour: failover, health recovery, live reconfiguration
//! under load, and signal handling of the real `velox` binary.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use support::*;
use velox_cli::App;
use velox_core::Config;

fn named(name: &'static str) -> Handler {
    handler(move |req| async move {
        if req.uri().path() == "/slow" {
            tokio::time::sleep(Duration::from_millis(600)).await;
        }
        text(name)
    })
}

async fn start_plain(toml: &str, path: Option<std::path::PathBuf>) -> App {
    App::start(Config::from_toml_str(toml).unwrap(), path).await.unwrap()
}

#[tokio::test]
async fn failover_then_active_health_check_recovery() {
    let a = Mock::start(named("A")).await;
    let b = Mock::start(named("B")).await;
    let a_addr = a.addr;
    let toml = format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\n[admin]\naddr = \"127.0.0.1:0\"\n\
         [[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"{a_addr}\" }}, {{ addr = \"{}\" }}]\n\
         [upstream.health]\nkind = \"http\"\npath = \"/health\"\ninterval = \"100ms\"\ntimeout = \"300ms\"\njitter = 0.1\nhealthy_threshold = 2\nunhealthy_threshold = 2\n\
         [[route]]\nupstream = \"app\"\n",
        b.addr
    );
    let app = start_plain(&toml, None).await;
    let (http, admin_addr) = (app.running.http_addr.unwrap(), app.admin_addr.unwrap());

    // Both serve while healthy.
    let mut seen = std::collections::HashSet::new();
    for _ in 0..20 {
        seen.insert(plain(http, "/", "").await.2);
    }
    assert_eq!(seen.len(), 2, "round-robin reaches both: {seen:?}");

    // Backend A dies: not one client-visible failure, even before health checks notice.
    a.stop();
    tokio::time::sleep(Duration::from_millis(30)).await;
    for i in 0..30 {
        let (status, _, body) = plain(http, "/", "").await;
        assert_eq!((status, body.as_str()), (200, "B"), "request {i} during failover");
    }
    // Active checks then mark it unhealthy; the admin API reflects it.
    eventually(5, "backend A marked unhealthy", || async {
        let (_, v) = admin(admin_addr, "GET", "/admin/v1/upstreams/app", None).await;
        v["backends"][0]["healthy"] == json!(false)
    })
    .await;
    let (_, v) = admin(admin_addr, "GET", "/admin/v1/upstreams/app", None).await;
    assert_eq!(v["backends"][0]["available"], json!(false));
    assert!(
        app.metrics.render().unwrap().contains("velox_upstream_backend_ejections_total"),
        "passive ejection was recorded"
    );

    // A comes back on the same address: health check restores it, traffic returns.
    let a2 = Mock::start_on(a_addr, named("A")).await;
    eventually(5, "backend A healthy again", || async {
        let (_, v) = admin(admin_addr, "GET", "/admin/v1/upstreams/app", None).await;
        v["backends"][0]["healthy"] == json!(true)
    })
    .await;
    let mut seen = std::collections::HashSet::new();
    for _ in 0..20 {
        seen.insert(plain(http, "/", "").await.2);
    }
    assert!(seen.contains("A") && seen.contains("B"), "traffic returned to A: {seen:?}");
    assert!(a2.hits() > 0);
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn passive_outlier_ejection_then_admin_reset() {
    let bad = Mock::start(handler(|_| async {
        let mut r = text("down");
        *r.status_mut() = http::StatusCode::BAD_GATEWAY;
        r
    }))
    .await;
    let good = Mock::start(named("good")).await;
    let toml = format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\n[admin]\naddr = \"127.0.0.1:0\"\n\
         [[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"{}\" }}, {{ addr = \"{}\" }}]\n\
         [upstream.outlier]\nconsecutive_failures = 3\nbase_ejection_time = \"60s\"\n\
         [[route]]\nupstream = \"app\"\n",
        bad.addr, good.addr
    );
    let app = start_plain(&toml, None).await;
    let (http, admin_addr) = (app.running.http_addr.unwrap(), app.admin_addr.unwrap());
    for _ in 0..30 {
        let _ = plain(http, "/", "").await;
    }
    assert!(bad.hits() <= 4, "ejected after 3 failures, saw {}", bad.hits());
    let (_, v) = admin(admin_addr, "GET", "/admin/v1/upstreams/app", None).await;
    assert!(v["backends"][0]["ejected_for_ms"].as_u64().unwrap() > 50_000, "{v}");
    for _ in 0..10 {
        assert_eq!(plain(http, "/", "").await.2, "good");
    }
    // Operator override.
    let (s, _) = admin(
        admin_addr,
        "POST",
        &format!("/admin/v1/upstreams/app/backends/{}/reset", bad.addr.to_string().replace(':', "%3A")),
        None,
    )
    .await;
    assert_eq!(s, 200);
    let before = bad.hits();
    for _ in 0..4 {
        let _ = plain(http, "/", "").await;
    }
    assert!(bad.hits() > before, "reset puts the backend back in rotation");
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn zero_downtime_reconfiguration_under_load() {
    let blue = Mock::start(named("blue")).await;
    let green = Mock::start(named("green")).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("velox.toml");
    let config = |target: &str, burst: u32| {
        format!(
            "[server]\nhttp_addr = \"127.0.0.1:0\"\n[admin]\naddr = \"127.0.0.1:0\"\n\
             [rate_limit]\nrequests_per_second = 100000.0\nburst = {burst}\n\
             [[upstream]]\nname = \"blue\"\nbackends = [{{ addr = \"{}\" }}]\n\
             [[upstream]]\nname = \"green\"\nbackends = [{{ addr = \"{}\" }}]\n\
             [[route]]\nname = \"main\"\nupstream = \"{target}\"\n",
            blue.addr, green.addr
        )
    };
    std::fs::write(&cfg_path, config("blue", 1_000_000)).unwrap();
    let app = start_plain(&std::fs::read_to_string(&cfg_path).unwrap(), Some(cfg_path.clone())).await;
    let (http, admin_addr) = (app.running.http_addr.unwrap(), app.admin_addr.unwrap());

    // Keep-alive load generators: each owns ONE TCP connection for the whole test.
    let stop = Arc::new(AtomicBool::new(false));
    let (ok, failed) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let mut loaders = Vec::new();
    for _ in 0..8 {
        let (stop, ok, failed) = (Arc::clone(&stop), Arc::clone(&ok), Arc::clone(&failed));
        loaders.push(tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(http).await.unwrap();
            let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
            tokio::spawn(conn);
            let mut count = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let req =
                    Request::builder().uri("/").header("host", "example.test").body(Full::new(Bytes::new())).unwrap();
                let res = async {
                    send.ready().await.ok()?;
                    let resp = send.send_request(req).await.ok()?;
                    let status = resp.status();
                    resp.into_body().collect().await.ok()?;
                    Some(status)
                }
                .await;
                match res {
                    Some(s) if s.is_success() => {
                        ok.fetch_add(1, Ordering::Relaxed);
                        count += 1;
                    }
                    _ => {
                        failed.fetch_add(1, Ordering::Relaxed);
                        return count;
                    }
                }
            }
            count
        }));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(green.hits() == 0 && blue.hits() > 0);

    // An in-flight slow request straddles the cut-over and must finish on the OLD upstream.
    let slow = tokio::spawn(async move { plain(http, "/slow", "").await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 1) Admin API: point the route at green.
    let (s, _) = admin(admin_addr, "PUT", "/admin/v1/routes/main", Some(json!({ "upstream": "green" }))).await;
    assert_eq!(s, 200);
    tokio::time::sleep(Duration::from_millis(250)).await;
    let green_after_api = green.hits();
    assert!(green_after_api > 0, "traffic moved to green");
    let slow = slow.await.unwrap();
    assert_eq!((slow.0, slow.2.as_str()), (200, "blue"), "in-flight request completed on the old config");

    // 2) Admin API: add/replace an upstream's backends live.
    let (s, _) = admin(
        admin_addr,
        "PUT",
        "/admin/v1/upstreams/green",
        Some(json!({ "name": "green", "algorithm": "least_conn", "backends": [{ "addr": green.addr.to_string(), "weight": 2 }] })),
    )
    .await;
    assert_eq!(s, 200);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 3) Edit the file and reload through the API (what `velox reload` does).
    std::fs::write(&cfg_path, config("blue", 500_000)).unwrap();
    let (s, v) = admin(admin_addr, "POST", "/admin/v1/reload", None).await;
    assert_eq!(s, 200, "{v}");
    let blue_before = blue.hits();
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(blue.hits() > blue_before, "file reload moved traffic back to blue");

    // 4) A broken file is rejected and the live config keeps serving.
    std::fs::write(&cfg_path, "[server]\nhttp_addr = \"127.0.0.1:0\"\n[[route]]\nupstream = \"nope\"\n").unwrap();
    let (s, v) = admin(admin_addr, "POST", "/admin/v1/reload", None).await;
    assert_eq!(s, 422, "{v}");
    tokio::time::sleep(Duration::from_millis(150)).await;

    stop.store(true, Ordering::Relaxed);
    let mut per_conn = Vec::new();
    for l in loaders {
        per_conn.push(l.await.unwrap());
    }
    assert_eq!(failed.load(Ordering::Relaxed), 0, "no request may fail during reconfiguration");
    assert!(ok.load(Ordering::Relaxed) > 400, "load actually ran: {}", ok.load(Ordering::Relaxed));
    assert!(per_conn.iter().all(|&n| n > 20), "each keep-alive connection survived every swap: {per_conn:?}");
    let m = app.metrics.render().unwrap();
    assert!(m.contains("velox_config_reloads_total{result=\"ok\"}"), "{m}");
    assert!(m.contains("velox_config_reloads_total{result=\"error\"} 1"), "{m}");
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn consistent_hashing_pins_clients_and_survives_a_backend_drain() {
    let backends = [Mock::start(named("n0")).await, Mock::start(named("n1")).await, Mock::start(named("n2")).await];
    let list: Vec<String> = backends.iter().map(|b| format!("{{ addr = \"{}\" }}", b.addr)).collect();
    let toml = format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\n[admin]\naddr = \"127.0.0.1:0\"\n\
         [[upstream]]\nname = \"app\"\nalgorithm = \"consistent_hash\"\nhash_on = \"header:x-user\"\nbackends = [{}]\n\
         [[route]]\nupstream = \"app\"\n",
        list.join(",")
    );
    let app = start_plain(&toml, None).await;
    let (http, admin_addr) = (app.running.http_addr.unwrap(), app.admin_addr.unwrap());
    let mut pin = std::collections::HashMap::new();
    for u in 0..30 {
        let first = plain(http, "/", &format!("X-User: user-{u}\r\n")).await.2;
        for _ in 0..3 {
            assert_eq!(plain(http, "/", &format!("X-User: user-{u}\r\n")).await.2, first, "user-{u} must stick");
        }
        pin.insert(u, first);
    }
    assert_eq!(pin.values().collect::<std::collections::HashSet<_>>().len(), 3, "keys spread over all nodes");
    // Drain n1: its users move, everybody else stays put.
    let enc = backends[1].addr.to_string().replace(':', "%3A");
    assert_eq!(admin(admin_addr, "POST", &format!("/admin/v1/upstreams/app/backends/{enc}/drain"), None).await.0, 200);
    for u in 0..30 {
        let now = plain(http, "/", &format!("X-User: user-{u}\r\n")).await.2;
        assert_ne!(now, "n1");
        if pin[&u] != "n1" {
            assert_eq!(now, pin[&u], "user-{u} must not move");
        }
    }
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn l4_tcp_proxy_balances_raw_connections() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut echo_addrs = Vec::new();
    for tag in *b"AB" {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        echo_addrs.push(l.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 {
                            return;
                        }
                        let mut out = vec![tag];
                        out.extend_from_slice(&buf[..n]);
                        if s.write_all(&out).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
    }
    let listen = format!("127.0.0.1:{}", free_port());
    let toml = format!(
        "[admin]\naddr = \"127.0.0.1:0\"\n[[upstream]]\nname = \"tcp\"\nbackends = [{{ addr = \"{}\" }}, {{ addr = \"{}\" }}]\n\
         [[tcp_proxy]]\nlisten = \"{listen}\"\nupstream = \"tcp\"\nidle_timeout = \"400ms\"\n",
        echo_addrs[0], echo_addrs[1]
    );
    let app = start_plain(&toml, None).await;
    let addr = app.running.tcp_proxy_addrs[0];
    let mut tags = std::collections::HashSet::new();
    for _ in 0..6 {
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 5];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[1..], b"ping");
        tags.insert(got[0]);
    }
    assert_eq!(tags.len(), 2, "both L4 backends used");
    // Idle connections are reaped.
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    c.write_all(b"x").await.unwrap();
    let mut two = [0u8; 2];
    c.read_exact(&mut two).await.unwrap();
    let n =
        tokio::time::timeout(Duration::from_secs(3), c.read(&mut two)).await.expect("idle conn closed").unwrap_or(0);
    assert_eq!(n, 0);
    assert!(app.shutdown().await);
}

// ---------------- the real binary ----------------

struct Daemon {
    child: Child,
    dir: tempfile::TempDir,
}

impl Daemon {
    fn spawn(config: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("velox.toml"), config).unwrap();
        let log = std::fs::File::create(dir.path().join("velox.log")).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_velox"))
            .args(["start", "-c"])
            .arg(dir.path().join("velox.toml"))
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        Self { child, dir }
    }

    fn config_path(&self) -> std::path::PathBuf {
        self.dir.path().join("velox.toml")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("velox.log")).unwrap_or_default()
    }

    fn signal(&self, sig: &str) {
        let st = Command::new("kill").arg(format!("-{sig}")).arg(self.child.id().to_string()).status().unwrap();
        assert!(st.success());
    }

    async fn wait_exit(&mut self, secs: u64) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            if let Some(st) = self.child.try_wait().unwrap() {
                return st;
            }
            assert!(Instant::now() < deadline, "process did not exit; log:\n{}", self.log());
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn daemon_config(http: u16, admin: u16, upstream: SocketAddr) -> String {
    format!(
        "[server]\nhttp_addr = \"127.0.0.1:{http}\"\ndrain_timeout = \"8s\"\n[admin]\naddr = \"127.0.0.1:{admin}\"\n\
         [telemetry]\naccess_log = true\nlog_format = \"json\"\n\
         [[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"{upstream}\" }}]\n[[route]]\nupstream = \"app\"\n"
    )
}

async fn wait_ready(admin: SocketAddr, d: &mut Daemon) {
    for _ in 0..200 {
        if let Some(st) = d.child.try_wait().unwrap() {
            panic!("velox exited early ({st}); log:\n{}", d.log());
        }
        if tokio::net::TcpStream::connect(admin).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("velox did not become ready; log:\n{}", d.log());
}

#[tokio::test]
async fn sigterm_drains_in_flight_requests_then_exits_cleanly() {
    let backend = Mock::start(named("drained-ok")).await;
    let (http_p, admin_p) = (free_port(), free_port());
    let (http, admin_addr): (SocketAddr, SocketAddr) =
        (format!("127.0.0.1:{http_p}").parse().unwrap(), format!("127.0.0.1:{admin_p}").parse().unwrap());
    let mut d = Daemon::spawn(&daemon_config(http_p, admin_p, backend.addr));
    wait_ready(admin_addr, &mut d).await;
    assert_eq!(plain(http, "/", "").await.2, "drained-ok");

    let inflight = tokio::spawn(async move { plain(http, "/slow", "").await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    let t0 = Instant::now();
    d.signal("TERM");
    let reply = inflight.await.unwrap();
    assert_eq!((reply.0, reply.2.as_str()), (200, "drained-ok"), "in-flight request must complete; log:\n{}", d.log());
    let status = d.wait_exit(10).await;
    assert!(status.success(), "clean exit expected, got {status}; log:\n{}", d.log());
    assert!(t0.elapsed() >= Duration::from_millis(300), "exit waited for the request");
    assert!(tokio::net::TcpStream::connect(http).await.is_err(), "listener closed");
    let log = d.log();
    assert!(log.contains("shutdown complete"), "{log}");
    // Structured JSON access log with request ids.
    let access: Vec<serde_json::Value> = log
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["target"] == "velox::access")
        .collect();
    assert!(access.len() >= 2, "access log lines missing:\n{log}");
    let first = &access[0];
    assert_eq!(first["status"], 200);
    assert_eq!(first["protocol"], "h1");
    assert_eq!(first["method"], "GET");
    assert_eq!(first["request_id"].as_str().unwrap().len(), 32);
    assert!(first["duration_ms"].is_number());
}

#[tokio::test]
async fn sigint_also_shuts_down_cleanly() {
    let backend = Mock::start(named("x")).await;
    let (http_p, admin_p) = (free_port(), free_port());
    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_p}").parse().unwrap();
    let mut d = Daemon::spawn(&daemon_config(http_p, admin_p, backend.addr));
    wait_ready(admin_addr, &mut d).await;
    d.signal("INT");
    assert!(d.wait_exit(10).await.success(), "{}", d.log());
}

#[tokio::test]
async fn sighup_and_cli_reload_apply_new_config_and_reject_bad_config() {
    let a = Mock::start(named("A")).await;
    let b = Mock::start(named("B")).await;
    let (http_p, admin_p) = (free_port(), free_port());
    let (http, admin_addr): (SocketAddr, SocketAddr) =
        (format!("127.0.0.1:{http_p}").parse().unwrap(), format!("127.0.0.1:{admin_p}").parse().unwrap());
    let mut d = Daemon::spawn(&daemon_config(http_p, admin_p, a.addr));
    wait_ready(admin_addr, &mut d).await;
    assert_eq!(plain(http, "/", "").await.2, "A");

    // SIGHUP
    std::fs::write(d.config_path(), daemon_config(http_p, admin_p, b.addr)).unwrap();
    d.signal("HUP");
    eventually(5, "SIGHUP reload to take effect", || async { plain(http, "/", "").await.2 == "B" }).await;

    // `velox reload` (CLI → admin API)
    std::fs::write(d.config_path(), daemon_config(http_p, admin_p, a.addr)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_velox")).args(["reload", "-c"]).arg(d.config_path()).output().unwrap();
    assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("reloaded"));
    assert_eq!(plain(http, "/", "").await.2, "A");

    // A broken file: CLI reports failure, traffic keeps flowing on the old config.
    std::fs::write(d.config_path(), "[server]\nhttp_addr = \"127.0.0.1:1\"\n[[route]]\nupstream = \"ghost\"\n")
        .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_velox")).args(["reload", "-c"]).arg(d.config_path()).output().unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unknown upstream"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    d.signal("HUP");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(plain(http, "/", "").await.2, "A");
    assert!(d.child.try_wait().unwrap().is_none(), "process must survive a bad reload");
    let (_, metrics) = plain_get_metrics(admin_addr).await;
    assert!(metrics.contains("velox_config_reloads_total{result=\"error\"}"), "{metrics}");
    d.signal("TERM");
    assert!(d.wait_exit(10).await.success());
}

async fn plain_get_metrics(admin: SocketAddr) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(admin).await.unwrap();
    s.write_all(format!("GET /metrics HTTP/1.1\r\nHost: {admin}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    let status = out.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    (status, out)
}

#[test]
fn validate_and_version_commands() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.toml");
    std::fs::write(&good, daemon_config(1, 2, "127.0.0.1:3".parse().unwrap())).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_velox")).args(["validate", "-c"]).arg(&good).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("OK"));

    let bad = dir.path().join("bad.toml");
    std::fs::write(
        &bad,
        "[server]\nhttp_addr = \"127.0.0.1:1\"\n[[route]]\nupstream = \"ghost\"\n[admin]\naddr = \"0.0.0.0:9\"\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_velox")).args(["validate", "-c"]).arg(&bad).output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unknown upstream") && err.contains("loopback"), "all problems are reported at once: {err}");

    let out = Command::new(env!("CARGO_BIN_EXE_velox")).arg("version").output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("velox 0."));

    let missing =
        Command::new(env!("CARGO_BIN_EXE_velox")).args(["validate", "-c", "/nonexistent/velox.toml"]).output().unwrap();
    assert!(!missing.status.success());
}
