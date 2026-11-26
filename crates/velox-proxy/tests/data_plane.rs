//! Data-plane tests over real sockets (plain HTTP/1.1). TLS, HTTP/2 and
//! HTTP/3 are covered by the workspace end-to-end suite in `velox-cli`.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use velox_core::{Config, SharedState};
use velox_proxy::{Proxy, Shutdown};
use velox_security::ChallengeStore;
use velox_telemetry::Metrics;

type Handler = Arc<dyn Fn(Request<Incoming>) -> Response<Full<Bytes>> + Send + Sync>;

/// A mock HTTP/1.1 backend; returns its address and a hit counter.
async fn backend(handler: Handler) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits2 = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let handler = Arc::clone(&handler);
            let hits = Arc::clone(&hits2);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let handler = Arc::clone(&handler);
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, Infallible>(handler(req))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
        }
    });
    (addr, hits)
}

/// A backend that answers after `delay` (async, so it never blocks the runtime).
async fn slow_backend(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let svc = service_fn(move |_req: Request<Incoming>| async move {
                    tokio::time::sleep(delay).await;
                    Ok::<_, Infallible>(text("slow-but-complete"))
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
        }
    });
    addr
}

fn text(body: &str) -> Response<Full<Bytes>> {
    Response::new(Full::new(Bytes::from(body.to_owned())))
}

fn echo_headers() -> Handler {
    Arc::new(|req| {
        let mut out = format!("{} {}\n", req.method(), req.uri());
        for (k, v) in req.headers() {
            out.push_str(&format!("{}: {}\n", k, v.to_str().unwrap_or("?")));
        }
        text(&out)
    })
}

struct Harness {
    addr: SocketAddr,
    proxy: Arc<Proxy>,
    running: velox_proxy::Running,
}

async fn start(toml: &str) -> Harness {
    let cfg = Config::from_toml_str(toml).unwrap();
    let state = SharedState::new(cfg).unwrap();
    let proxy =
        Proxy::new(state, Arc::new(Metrics::new().unwrap()), Arc::new(ChallengeStore::default()), Shutdown::new());
    let running = velox_proxy::start(Arc::clone(&proxy), None).await.unwrap();
    Harness { addr: running.http_addr.unwrap(), proxy, running }
}

/// Send raw bytes, read until the server closes or `wait` passes.
async fn raw(addr: SocketAddr, request: &[u8], wait: Duration) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(request).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(wait, async {
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    String::from_utf8_lossy(&out).into_owned()
}

fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n").into_bytes()
}

fn status(resp: &str) -> u16 {
    resp.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn body(resp: &str) -> &str {
    resp.split_once("\r\n\r\n").map_or("", |(_, b)| b)
}

fn base(extra: &str, backends: &[SocketAddr]) -> String {
    let list: Vec<String> = backends.iter().map(|a| format!("{{ addr = \"{a}\" }}")).collect();
    format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\ndrain_timeout = \"1s\"\n[admin]\n[[upstream]]\nname = \"app\"\nbackends = [{}]\n[[route]]\nupstream = \"app\"\n{extra}",
        list.join(",")
    )
}

#[tokio::test]
async fn proxies_and_rewrites_headers() {
    let (b, _) = backend(echo_headers()).await;
    let h = start(&base("", &[b])).await;
    let req = b"GET /a/b?x=1 HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive, X-Secret\r\nX-Secret: s\r\nX-Forwarded-For: 6.6.6.6\r\nX-Request-Id: trace-42\r\nKeep-Alive: timeout=5\r\n\r\n";
    let r = raw(h.addr, &[&req[..], b""].concat(), Duration::from_millis(400)).await;
    assert_eq!(status(&r), 200, "{r}");
    let b = body(&r).to_ascii_lowercase();
    assert!(b.contains("get /a/b?x=1"), "{b}");
    assert!(b.contains("x-forwarded-for: 127.0.0.1"), "spoofed XFF must be replaced: {b}");
    assert!(!b.contains("6.6.6.6"), "{b}");
    assert!(b.contains("x-request-id: trace-42"), "{b}");
    assert!(b.contains("x-real-ip: 127.0.0.1"), "{b}");
    assert!(b.contains("forwarded: for=127.0.0.1;proto=http;host=\"example.test\""), "{b}");
    assert!(!b.contains("x-secret"), "Connection-nominated headers are hop-by-hop: {b}");
    assert!(!b.contains("keep-alive: timeout"), "{b}");
    assert!(r.to_ascii_lowercase().contains("x-request-id: trace-42"), "id echoed to client: {r}");
    assert!(r.to_ascii_lowercase().contains("x-content-type-options: nosniff"), "{r}");
    h.running.shutdown().await;
}

#[tokio::test]
async fn unknown_route_is_404_and_bad_host_is_400() {
    let (b, hits) = backend(echo_headers()).await;
    let toml = format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\n[[upstream]]\nname=\"app\"\nbackends=[{{addr=\"{b}\"}}]\n[[route]]\nhosts=[\"only.test\"]\nupstream=\"app\"\n"
    );
    let h = start(&toml).await;
    let r = raw(h.addr, &get("/"), Duration::from_millis(300)).await;
    assert_eq!(status(&r), 404, "{r}");
    let r =
        raw(h.addr, b"GET / HTTP/1.1\r\nHost: bad host\r\nConnection: close\r\n\r\n", Duration::from_millis(300)).await;
    assert_eq!(status(&r), 400, "{r}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    h.running.shutdown().await;
}

#[tokio::test]
async fn smuggling_attempts_never_reach_the_backend() {
    let (b, hits) = backend(echo_headers()).await;
    let h = start(&base("", &[b])).await;
    let attacks: Vec<(&str, Vec<u8>)> = vec![
        ("CL.TE", b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG".to_vec()),
        ("TE.CL", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n12\r\nGPOST / HTTP/1.1\r\n\r\n0\r\n\r\n".to_vec()),
        ("TE.TE", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\nContent-Length: 4\r\n\r\nabcd".to_vec()),
        ("dup CL", b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 5\r\n\r\nabcde".to_vec()),
        ("obs-fold", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:\r\n chunked\r\n\r\n0\r\n\r\n".to_vec()),
        ("bare LF", b"GET / HTTP/1.1\nHost: a\n\n".to_vec()),
        ("NUL", b"GET / HTTP/1.1\r\nHost: a\r\nX: a\0b\r\n\r\n".to_vec()),
        ("dup Host", b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n".to_vec()),
        ("underscore TE", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer_Encoding: chunked\r\nContent-Length: 0\r\n\r\n".to_vec()),
        ("absolute-form", b"GET http://evil/ HTTP/1.1\r\nHost: a\r\n\r\n".to_vec()),
        ("CONNECT", b"CONNECT evil:443 HTTP/1.1\r\nHost: evil:443\r\n\r\n".to_vec()),
    ];
    for (name, req) in attacks {
        let r = raw(h.addr, &req, Duration::from_millis(500)).await;
        let code = status(&r);
        assert!((400..500).contains(&code) || code == 501, "{name}: expected rejection, got {r:?}");
        assert!(r.to_ascii_lowercase().contains("connection: close"), "{name}: connection must be closed: {r}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no attack may reach the backend");
    // …and a clean request on a fresh connection still works.
    let r = raw(h.addr, &get("/ok"), Duration::from_millis(400)).await;
    assert_eq!(status(&r), 200);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let metrics = h.proxy.metrics().render().unwrap();
    assert!(metrics.contains("velox_rejected_requests_total{reason=\"cl-te-conflict\"}"), "{metrics}");
    h.running.shutdown().await;
}

#[tokio::test]
async fn smuggled_second_request_in_same_packet_is_not_forwarded() {
    let (b, hits) = backend(echo_headers()).await;
    let h = start(&base("", &[b])).await;
    let req = b"GET /one HTTP/1.1\r\nHost: a\r\n\r\nGET /two HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n";
    let r = raw(h.addr, req, Duration::from_millis(500)).await;
    assert_eq!(status(&r), 400, "a poisoned pipeline is refused as a whole: {r}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing from the poisoned chunk may reach the backend");
    // The same two requests, each sent cleanly, are fine.
    assert_eq!(status(&raw(h.addr, &get("/one"), Duration::from_millis(400)).await), 200);
    h.running.shutdown().await;
}

#[tokio::test]
async fn round_robin_spreads_load_and_failover_hides_a_dead_backend() {
    let (b1, h1) = backend(Arc::new(|_| text("one"))).await;
    let (b2, h2) = backend(Arc::new(|_| text("two"))).await;
    let h = start(&base("", &[b1, b2])).await;
    for _ in 0..20 {
        assert_eq!(status(&raw(h.addr, &get("/"), Duration::from_millis(300)).await), 200);
    }
    assert_eq!((h1.load(Ordering::SeqCst), h2.load(Ordering::SeqCst)), (10, 10));
    h.running.shutdown().await;

    // One backend is a closed port: every request must still succeed.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let (live, hits) = backend(Arc::new(|_| text("alive"))).await;
    let h = start(&base("", &[dead, live])).await;
    for i in 0..30 {
        let r = raw(h.addr, &get("/"), Duration::from_millis(500)).await;
        assert_eq!(status(&r), 200, "request {i}: {r}");
        assert_eq!(body(&r).trim(), "alive");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 30);
    h.running.shutdown().await;
}

#[tokio::test]
async fn passive_outlier_detection_ejects_a_failing_backend() {
    let (bad, bad_hits) = backend(Arc::new(|_| {
        let mut r = text("down");
        *r.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
        r
    }))
    .await;
    let (good, _) = backend(Arc::new(|_| text("ok"))).await;
    let cfg = base("", &[bad, good]).replace(
        "[[route]]",
        "[upstream.outlier]\nconsecutive_failures = 3\nbase_ejection_time = \"60s\"\nmax_ejection_percent = 50\n[[route]]",
    );
    let h = start(&cfg).await;
    for _ in 0..40 {
        let _ = raw(h.addr, &get("/"), Duration::from_millis(300)).await;
    }
    let seen_by_bad = bad_hits.load(Ordering::SeqCst);
    assert!(seen_by_bad <= 4, "backend should be ejected after 3 failures, saw {seen_by_bad} hits");
    let snap = h.proxy.state().load();
    assert!(!snap.upstreams["app"].backends[0].is_available());
    let m = h.proxy.metrics().render().unwrap();
    assert!(m.contains("velox_upstream_backend_ejections_total"), "{m}");
    h.running.shutdown().await;
}

#[tokio::test]
async fn rate_limit_returns_429_with_retry_after() {
    let (b, _) = backend(Arc::new(|_| text("ok"))).await;
    let h =
        start(&base("", &[b]).replace("[admin]", "[rate_limit]\nrequests_per_second = 1.0\nburst = 3\n[admin]")).await;
    let mut codes = Vec::new();
    let mut limited = String::new();
    for _ in 0..6 {
        let r = raw(h.addr, &get("/"), Duration::from_millis(300)).await;
        if status(&r) == 429 {
            limited = r.clone();
        }
        codes.push(status(&r));
    }
    assert_eq!(&codes[..3], &[200, 200, 200], "{codes:?}");
    assert!(codes[3..].iter().all(|&c| c == 429), "{codes:?}");
    assert!(limited.to_ascii_lowercase().contains("retry-after: "), "{limited}");
    h.running.shutdown().await;
}

#[tokio::test]
async fn request_body_limits_and_strip_prefix_and_https_redirect() {
    let (b, hits) = backend(echo_headers()).await;
    let toml = format!(
        "[server]\nhttp_addr=\"127.0.0.1:0\"\n[limits]\nmax_request_body_bytes = 10\n[[upstream]]\nname=\"app\"\nbackends=[{{addr=\"{b}\"}}]\n\
         [[route]]\nhosts=[\"redir.test\"]\nupstream=\"app\"\nredirect_https=true\n\
         [[route]]\npath_prefix=\"/api\"\nstrip_prefix=true\nupstream=\"app\"\n"
    );
    let h = start(&toml).await;
    // declared too large → 413 before touching the backend
    let r = raw(
        h.addr,
        b"POST /api/x HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\nConnection: close\r\n\r\n01234567890",
        Duration::from_millis(400),
    )
    .await;
    assert_eq!(status(&r), 413, "{r}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "declared-oversize bodies never reach the backend");
    // chunked (unknown length) exceeding the cap mid-stream → 413 as well
    let r = raw(h.addr, b"POST /api/x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\n012345\r\n6\r\n678901\r\n0\r\n\r\n", Duration::from_millis(600)).await;
    assert_eq!(status(&r), 413, "{r}");
    // (A streamed upload may legitimately have started reaching the backend
    // before the cap tripped; the client-visible contract is the 413.)
    // within the cap passes; prefix stripped
    let r = raw(
        h.addr,
        b"POST /api/users?q=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        Duration::from_millis(400),
    )
    .await;
    assert_eq!(status(&r), 200, "{r}");
    assert!(body(&r).starts_with("POST /users?q=1"), "{r}");
    // https redirect
    let r = raw(
        h.addr,
        b"GET /p?q=1 HTTP/1.1\r\nHost: redir.test\r\nConnection: close\r\n\r\n",
        Duration::from_millis(300),
    )
    .await;
    assert_eq!(status(&r), 308, "{r}");
    assert!(r.to_ascii_lowercase().contains("location: https://redir.test/p?q=1"), "{r}");
    h.running.shutdown().await;
}

#[tokio::test]
async fn websocket_upgrade_is_tunnelled_bidirectionally() {
    // Raw TCP backend: completes the upgrade then echoes bytes.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
                assert!(text.contains("upgrade: websocket"), "{text}");
                assert!(text.contains("connection: upgrade"), "{text}");
                let _ = s
                    .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: abc\r\n\r\n")
                    .await;
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            let _ = s.write_all(&buf[..n]).await;
                        }
                    }
                }
            });
        }
    });
    let h = start(&base("", &[b]).replace("[admin]", "[server_tmp]\n[admin]").replace("[server_tmp]\n", "")).await;
    let mut c = TcpStream::connect(h.addr).await.unwrap();
    c.write_all(b"GET /chat HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Version: 13\r\n\r\n").await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf)).await.unwrap().unwrap();
        assert_ne!(n, 0, "closed before 101: {}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&buf[..n]);
    }
    let head = String::from_utf8_lossy(&got).to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 101"), "{head}");
    assert!(head.contains("sec-websocket-accept: abc"), "{head}");
    // Tunnel carries arbitrary (non-HTTP) bytes both ways.
    let payload: &[u8] = b"\x81\x05hello\r\n\r\n\0\0";
    c.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(2), c.read_exact(&mut echoed)).await.unwrap().unwrap();
    assert_eq!(echoed, payload);
    h.running.shutdown().await;
}

#[tokio::test]
async fn graceful_shutdown_lets_in_flight_requests_finish() {
    let b = slow_backend(Duration::from_millis(700)).await;
    let h = start(&base("", &[b])).await;
    let addr = h.addr;
    let inflight = tokio::spawn(async move { raw(addr, &get("/"), Duration::from_secs(5)).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let t0 = std::time::Instant::now();
    let clean = h.running.shutdown().await;
    let r = inflight.await.unwrap();
    assert!(clean, "drain must complete cleanly");
    assert_eq!(status(&r), 200, "in-flight request must be answered: {r}");
    assert!(r.contains("slow-but-complete"));
    assert!(t0.elapsed() >= Duration::from_millis(300), "shutdown waited for the request");
    assert!(TcpStream::connect(addr).await.is_err(), "listener must be closed after shutdown");
}

#[tokio::test]
async fn slow_headers_are_cut_off_and_idle_connections_expire() {
    let (b, hits) = backend(echo_headers()).await;
    let toml =
        base("", &[b]).replace("[admin]", "[timeouts]\nheader_read = \"400ms\"\nidle_keepalive = \"500ms\"\n[admin]");
    let h = start(&toml).await;
    // Slowloris: never finishes the head.
    let mut c = TcpStream::connect(h.addr).await.unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nX-Slow: ").await.unwrap();
    let mut buf = [0u8; 64];
    let n =
        tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf)).await.expect("server must close").unwrap_or(0);
    assert_eq!(n, 0, "slowloris connection is closed without a response");
    // Idle keep-alive connection is reaped.
    let mut c = TcpStream::connect(h.addr).await.unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
    let mut got = vec![0u8; 8192];
    let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut got)).await.unwrap().unwrap();
    assert!(String::from_utf8_lossy(&got[..n]).starts_with("HTTP/1.1 200"));
    let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut got))
        .await
        .expect("idle conn must be closed")
        .unwrap_or(0);
    assert_eq!(n, 0);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    h.running.shutdown().await;
}

#[tokio::test]
async fn per_ip_connection_limit_refuses_excess_connections() {
    let (b, _) = backend(echo_headers()).await;
    let toml = base("", &[b]).replace("[admin]", "[limits]\nmax_connections_per_ip = 2\n[admin]");
    let h = start(&toml).await;
    let c1 = TcpStream::connect(h.addr).await.unwrap();
    let c2 = TcpStream::connect(h.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut c3 = TcpStream::connect(h.addr).await.unwrap();
    let _ = c3.write_all(&get("/")).await;
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), c3.read(&mut buf)).await.unwrap().unwrap_or(0);
    assert_eq!(n, 0, "third connection from the same IP is dropped");
    drop((c1, c2));
    h.running.shutdown().await;
}

#[tokio::test]
async fn unix_socket_upstream_and_upstream_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("app.sock");
    let ul = tokio::net::UnixListener::bind(&sock).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = ul.accept().await else { return };
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async { Ok::<_, Infallible>(text("via-unix")) });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(s), svc).await;
            });
        }
    });
    let toml = format!(
        "[server]\nhttp_addr=\"127.0.0.1:0\"\n[[upstream]]\nname=\"u\"\nbackends=[{{addr=\"unix:{}\"}}]\n[[route]]\nupstream=\"u\"\n",
        sock.display()
    );
    let h = start(&toml).await;
    let r = raw(h.addr, &get("/"), Duration::from_millis(500)).await;
    assert_eq!(status(&r), 200, "{r}");
    assert_eq!(body(&r).trim(), "via-unix");
    h.running.shutdown().await;

    // A backend that never answers → 504 within the configured timeout.
    let hang = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hang_addr = hang.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = hang.accept().await {
            held.push(s);
        }
    });
    let toml = base("", &[hang_addr]).replace("[admin]", "[timeouts]\nupstream_response = \"300ms\"\n[admin]");
    let h = start(&toml).await;
    let t0 = std::time::Instant::now();
    let r = raw(h.addr, &get("/"), Duration::from_secs(3)).await;
    assert_eq!(status(&r), 504, "{r}");
    assert!(t0.elapsed() < Duration::from_secs(2));
    h.running.shutdown().await;
}

// ---------------- hardening regressions ----------------

/// A backend that accepts connections and never answers.
async fn black_hole() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            held.push(s);
        }
    });
    addr
}

async fn refused_port() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap()
}

#[tokio::test]
async fn all_retry_attempts_share_one_deadline() {
    // Regression: each attempt got a fresh `upstream_response` timeout, so
    // `retries = 2` turned 600 ms into 3 × 600 ms for a client waiting on hung backends.
    let hung = [black_hole().await, black_hole().await, black_hole().await];
    let toml = base("", &hung)
        .replace("name = \"app\"\n", "name = \"app\"\nretries = 2\n")
        .replace("[admin]", "[timeouts]\nupstream_response = \"600ms\"\n[admin]");
    let h = start(&toml).await;
    let t0 = std::time::Instant::now();
    let r = raw(h.addr, &get("/"), Duration::from_secs(5)).await;
    let took = t0.elapsed();
    assert_eq!(status(&r), 504, "{r}");
    assert!(took >= Duration::from_millis(550), "the budget is honoured, not undercut: {took:?}");
    assert!(took < Duration::from_millis(1100), "total time is bounded by ONE timeout, not three: {took:?}");
    h.running.shutdown().await;
}

#[tokio::test]
async fn retries_still_fail_over_quickly_on_connect_errors_within_the_budget() {
    let (live, hits) = backend(Arc::new(|_| text("third-time-lucky"))).await;
    let backends = [refused_port().await, refused_port().await, live];
    let toml = base("", &backends)
        .replace("name = \"app\"\n", "name = \"app\"\nretries = 2\n")
        .replace("[admin]", "[timeouts]\nupstream_response = \"2s\"\n[admin]");
    let h = start(&toml).await;
    for i in 0..9 {
        let t0 = std::time::Instant::now();
        let r = raw(h.addr, &get("/"), Duration::from_secs(3)).await;
        assert_eq!(status(&r), 200, "request {i}: {r}");
        assert!(t0.elapsed() < Duration::from_millis(700), "connect failures retry immediately: {:?}", t0.elapsed());
    }
    assert_eq!(hits.load(Ordering::SeqCst), 9);
    h.running.shutdown().await;
}

fn redirect_config(route: &str) -> String {
    format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\n[[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"127.0.0.1:9\" }}]\n{route}"
    )
}

#[tokio::test]
async fn https_redirect_never_reflects_the_host_header_of_a_catch_all_route() {
    // The config itself must refuse the open-redirect shape…
    let bad = redirect_config("[[route]]\nupstream = \"app\"\nredirect_https = true\n");
    let err = Config::from_toml_str(&bad).unwrap_err().to_string();
    assert!(err.contains("open redirect"), "{err}");

    // …and with a canonical host, attacker-chosen Host values are ignored.
    let ok = redirect_config(
        "[[route]]\nupstream = \"app\"\nredirect_https = true\ncanonical_host = \"secure.example.test\"\n",
    );
    let h = start(&ok).await;
    for host in ["evil.example", "secure.example.test", "attacker.test:1234"] {
        let r = raw(
            h.addr,
            format!("GET /p?q=1 HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
            Duration::from_millis(400),
        )
        .await;
        assert_eq!(status(&r), 308, "{host}: {r}");
        assert!(
            r.to_ascii_lowercase().contains("location: https://secure.example.test/p?q=1\r\n"),
            "{host}: Location must use the canonical host: {r}"
        );
        assert!(!r.to_ascii_lowercase().contains("evil.example") && !r.to_ascii_lowercase().contains("attacker"));
    }
    h.running.shutdown().await;
}

#[tokio::test]
async fn https_redirect_edge_cases_http10_without_host_and_options_star() {
    // HTTP/1.0 without Host: a canonical route can still redirect safely…
    let ok = redirect_config(
        "[[route]]\nupstream = \"app\"\nredirect_https = true\ncanonical_host = \"secure.example.test\"\n",
    );
    let h = start(&ok).await;
    let r = raw(h.addr, b"GET /legacy HTTP/1.0\r\n\r\n", Duration::from_millis(400)).await;
    assert_eq!(status(&r), 308, "{r}");
    assert!(r.to_ascii_lowercase().contains("location: https://secure.example.test/legacy\r\n"), "{r}");
    // …and `OPTIONS *` is normalised to `/` instead of `https://host*`.
    let r = raw(
        h.addr,
        b"OPTIONS * HTTP/1.1\r\nHost: whatever.test\r\nConnection: close\r\n\r\n",
        Duration::from_millis(400),
    )
    .await;
    assert_eq!(status(&r), 308, "{r}");
    assert!(r.to_ascii_lowercase().contains("location: https://secure.example.test/\r\n"), "{r}");
    h.running.shutdown().await;

    // A host-scoped redirect route cannot match a Host-less request at all: 404, never a redirect.
    let scoped =
        redirect_config("[[route]]\nhosts = [\"app.example.test\"]\nupstream = \"app\"\nredirect_https = true\n");
    let h = start(&scoped).await;
    let r = raw(h.addr, b"GET / HTTP/1.0\r\n\r\n", Duration::from_millis(400)).await;
    assert_eq!(status(&r), 404, "{r}");
    assert!(!r.to_ascii_lowercase().contains("location:"));
    // Host-scoped routes redirect to the (already matched) host.
    let r = raw(
        h.addr,
        b"GET /x HTTP/1.1\r\nHost: APP.example.test:8080\r\nConnection: close\r\n\r\n",
        Duration::from_millis(400),
    )
    .await;
    assert_eq!(status(&r), 308, "{r}");
    assert!(
        r.to_ascii_lowercase().contains("location: https://app.example.test/x")
            || r.to_ascii_lowercase().contains("location: https://app.example.test/x\r\n"),
        "{r}"
    );
    h.running.shutdown().await;
}

#[tokio::test]
async fn underscore_hosts_are_rejected_unless_the_operator_opts_in() {
    let (b, hits) = backend(echo_headers()).await;
    let req = b"GET / HTTP/1.1\r\nHost: my_service\r\nConnection: close\r\n\r\n";
    let strict = start(&base("", &[b])).await;
    let r = raw(strict.addr, req, Duration::from_millis(400)).await;
    assert_eq!(status(&r), 400, "{r}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    strict.running.shutdown().await;

    let lenient =
        start(&base("", &[b]).replace("[admin]", "[security]\nallow_underscores_in_host = true\n[admin]")).await;
    let r = raw(lenient.addr, req, Duration::from_millis(400)).await;
    assert_eq!(status(&r), 200, "{r}");
    // Opting in relaxes only `_`; everything else about Host stays strict.
    let r = raw(
        lenient.addr,
        b"GET / HTTP/1.1\r\nHost: bad host_x\r\nConnection: close\r\n\r\n",
        Duration::from_millis(400),
    )
    .await;
    assert_eq!(status(&r), 400, "{r}");
    lenient.running.shutdown().await;
}

#[tokio::test]
async fn https_redirect_is_skipped_for_a_trusted_proxy_that_already_terminated_tls() {
    let (b, hits) = backend(echo_headers()).await;
    let cfg = format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\n[security]\ntrusted_proxies = [\"127.0.0.0/8\"]\n\
         [[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"{b}\" }}]\n\
         [[route]]\nupstream = \"app\"\nredirect_https = true\ncanonical_host = \"secure.example.test\"\n"
    );
    let h = start(&cfg).await;
    let send = |extra: &'static str| {
        let req = format!("GET /p HTTP/1.1\r\nHost: secure.example.test\r\n{extra}Connection: close\r\n\r\n");
        let addr = h.addr;
        async move { raw(addr, req.as_bytes(), Duration::from_millis(500)).await }
    };

    // Every spelling of "the client used HTTPS" from a trusted peer: served, not redirected,
    // and the backend is told the *original* scheme so it cannot start a loop of its own.
    for extra in [
        "X-Forwarded-Proto: https\r\n",
        "X-Forwarded-Proto: HTTPS\r\n",
        "X-Forwarded-Proto: https, http\r\n",
        "Forwarded: for=1.2.3.4;proto=https\r\n",
        "Forwarded: for=1.2.3.4;proto=\"https\";host=a.test\r\n",
    ] {
        let r = send(extra).await;
        assert_eq!(status(&r), 200, "{extra:?}: {r}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 5);
    let r = send("Forwarded: for=1.2.3.4;proto=https\r\n").await.to_ascii_lowercase();
    assert!(r.contains("x-forwarded-proto: https\r\n") || r.contains("x-forwarded-proto: https\n"), "{r}");

    // Anything else still redirects: plain, http, junk, or a non-https first hop.
    for extra in [
        "",
        "X-Forwarded-Proto: http\r\n",
        "X-Forwarded-Proto: gopher\r\n",
        "X-Forwarded-Proto: http, https\r\n",
        "Forwarded: for=1.2.3.4;proto=http\r\n",
    ] {
        let r = send(extra).await;
        assert_eq!(status(&r), 308, "{extra:?}: {r}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 6, "redirected requests never reach the backend");
    h.running.shutdown().await;
}

#[tokio::test]
async fn https_redirect_ignores_forwarded_proto_from_untrusted_peers() {
    // No `trusted_proxies`: a client claiming "https" must not dodge the redirect.
    let (b, hits) = backend(echo_headers()).await;
    let cfg = format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\n[[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"{b}\" }}]\n\
         [[route]]\nupstream = \"app\"\nredirect_https = true\ncanonical_host = \"secure.example.test\"\n"
    );
    let h = start(&cfg).await;
    for extra in ["X-Forwarded-Proto: https\r\n", "Forwarded: proto=https\r\n"] {
        let req = format!("GET / HTTP/1.1\r\nHost: secure.example.test\r\n{extra}Connection: close\r\n\r\n");
        let r = raw(h.addr, req.as_bytes(), Duration::from_millis(500)).await;
        assert_eq!(status(&r), 308, "{extra:?}: {r}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    h.running.shutdown().await;
}

// ---------------- max_inflight circuit breaker ----------------

/// A backend that holds every request until `release` is notified.
async fn gated_backend() -> (SocketAddr, Arc<tokio::sync::Notify>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let release = Arc::new(tokio::sync::Notify::new());
    let arrived = Arc::new(AtomicUsize::new(0));
    let (rel, arr) = (Arc::clone(&release), Arc::clone(&arrived));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let (rel, arr) = (Arc::clone(&rel), Arc::clone(&arr));
            tokio::spawn(async move {
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let (rel, arr) = (Arc::clone(&rel), Arc::clone(&arr));
                    async move {
                        arr.fetch_add(1, Ordering::SeqCst);
                        rel.notified().await;
                        Ok::<_, Infallible>(text("done"))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
        }
    });
    (addr, release, arrived)
}

async fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn max_inflight_sheds_load_with_503_instead_of_queueing() {
    let (b, release, arrived) = gated_backend().await;
    let cfg = base("", &[b]).replace("[[upstream]]\n", "[[upstream]]\nmax_inflight = 2\nretries = 0\n");
    let h = start(&cfg).await;

    // Two requests fill the backend…
    let held: Vec<_> = (0..2)
        .map(|_| {
            let addr = h.addr;
            tokio::spawn(async move { raw(addr, &get("/slow"), Duration::from_secs(5)).await })
        })
        .collect();
    wait_for("both requests to reach the backend", || arrived.load(Ordering::SeqCst) == 2).await;

    // …so the next ones are refused immediately, without ever touching it.
    for i in 0..5 {
        let t0 = std::time::Instant::now();
        let r = raw(h.addr, &get("/shed"), Duration::from_secs(2)).await;
        assert_eq!(status(&r), 503, "request {i}: {r}");
        assert!(r.to_ascii_lowercase().contains("retry-after: 1"), "{r}");
        assert!(body(&r).contains("overloaded"), "{r}");
        assert!(t0.elapsed() < Duration::from_millis(500), "shed fast, not queued: {:?}", t0.elapsed());
    }
    assert_eq!(arrived.load(Ordering::SeqCst), 2, "refused requests never reached the backend");
    let metrics = h.proxy.metrics().render().unwrap();
    assert!(metrics.contains("velox_upstream_saturated_total{upstream=\"app\"} 5"), "{metrics}");

    // Capacity returns the moment in-flight requests finish.
    release.notify_waiters();
    for j in held {
        assert_eq!(status(&j.await.unwrap()), 200);
    }
    let again = tokio::spawn({
        let addr = h.addr;
        async move { raw(addr, &get("/after"), Duration::from_secs(5)).await }
    });
    wait_for("the next request to be admitted", || arrived.load(Ordering::SeqCst) == 3).await;
    release.notify_waiters();
    assert_eq!(status(&again.await.unwrap()), 200);
    h.running.shutdown().await;
}

#[tokio::test]
async fn saturated_backends_are_skipped_in_favour_of_free_ones_and_per_backend_caps_override() {
    let (full, release_full, arrived_full) = gated_backend().await;
    let (b2, _) = backend(echo_headers()).await;
    // `full` is capped at 1 (per-backend), the upstream default is generous.
    let cfg = format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\ndrain_timeout = \"1s\"\n[admin]\n[[upstream]]\nname = \"app\"\n\
         max_inflight = 100\nretries = 0\nbackends = [{{ addr = \"{full}\", max_inflight = 1 }}, {{ addr = \"{b2}\" }}]\n\
         [[route]]\nupstream = \"app\"\n"
    );
    let h = start(&cfg).await;
    // Pin one request on the capped backend (round-robin may land on either, so
    // keep sending until the gated one has it).
    let mut held = Vec::new();
    while arrived_full.load(Ordering::SeqCst) == 0 {
        let addr = h.addr;
        held.push(tokio::spawn(async move { raw(addr, &get("/pin"), Duration::from_secs(5)).await }));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Now every request must be served by the free backend: none fail, none queue.
    for i in 0..20 {
        let r = raw(h.addr, &get("/x"), Duration::from_secs(2)).await;
        assert_eq!(status(&r), 200, "request {i}: {r}");
        assert!(r.contains("GET /x"), "served by the echo backend: {r}");
    }
    assert_eq!(arrived_full.load(Ordering::SeqCst), 1, "the capped backend received nothing further");
    release_full.notify_waiters();
    for j in held {
        let _ = j.await;
    }
    h.running.shutdown().await;
}

#[tokio::test]
async fn an_outage_is_not_reported_as_saturation() {
    let (b, _) = backend(echo_headers()).await;
    let cfg = base("", &[b]).replace("[[upstream]]\n", "[[upstream]]\nmax_inflight = 5\n");
    let h = start(&cfg).await;
    let group = h.proxy.state().load().upstreams["app"].clone();
    group.backends[0].set_healthy(false);
    let r = raw(h.addr, &get("/"), Duration::from_secs(2)).await;
    assert_eq!(status(&r), 503);
    assert!(body(&r).contains("no healthy upstream"), "{r}");
    assert!(
        !h.proxy.metrics().render().unwrap().contains("velox_upstream_saturated_total{"),
        "not counted as saturation"
    );
    h.running.shutdown().await;
}

// ---------------- PROXY protocol ----------------

use velox_proxy::proxy_protocol::{encode_v1, encode_v2, encode_v2_local};

fn pp_config(backend: SocketAddr, extra_server: &str, extra: &str) -> String {
    base(extra, &[backend]).replace(
        "[server]\n",
        &format!("[server]\nproxy_protocol = true\nproxy_protocol_trusted = [\"127.0.0.0/8\"]\n{extra_server}"),
    )
}

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[tokio::test]
async fn proxy_protocol_v1_and_v2_supply_the_real_client_address() {
    let (b, hits) = backend(echo_headers()).await;
    let h = start(&pp_config(b, "", "")).await;
    let server = sa("10.0.0.1:80");
    for (label, header, expect) in [
        ("v2 ipv4", encode_v2(sa("203.0.113.7:51000"), server, &[]), "203.0.113.7"),
        ("v2 ipv6", encode_v2(sa("[2001:db8::42]:51000"), sa("[2001:db8::1]:80"), &[]), "2001:db8::42"),
        ("v2 + NLB-style TLVs", encode_v2(sa("198.51.100.9:1"), server, &[0xEA, 0, 4, 1, 2, 3, 4]), "198.51.100.9"),
        ("v1", encode_v1(sa("192.0.2.55:4000"), server), "192.0.2.55"),
    ] {
        let mut req = header;
        req.extend_from_slice(&get("/who"));
        let r = raw(h.addr, &req, Duration::from_secs(2)).await;
        assert_eq!(status(&r), 200, "{label}: {r}");
        let b = body(&r).to_ascii_lowercase();
        assert!(b.contains(&format!("x-real-ip: {expect}")), "{label}: {b}");
        assert!(b.contains(&format!("x-forwarded-for: {expect}")), "{label}: {b}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 4);

    // The header may arrive in its own segment, ahead of the request.
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    s.set_nodelay(true).unwrap();
    s.write_all(&encode_v2(sa("203.0.113.99:1"), server, &[])).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    s.write_all(&get("/split")).await.unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_string(&mut out)).await;
    assert!(body(&out).to_ascii_lowercase().contains("x-real-ip: 203.0.113.99"), "{out}");

    // LOCAL (the load balancer's own health probe) uses the TCP peer.
    let mut req = encode_v2_local();
    req.extend_from_slice(&get("/health"));
    let r = raw(h.addr, &req, Duration::from_secs(2)).await;
    assert!(body(&r).to_ascii_lowercase().contains("x-real-ip: 127.0.0.1"), "{r}");
    h.running.shutdown().await;
}

#[tokio::test]
async fn proxy_protocol_listeners_never_interpret_unframed_bytes_as_http() {
    let (b, hits) = backend(echo_headers()).await;
    let h = start(&pp_config(b, "", "")).await;
    // No header at all.
    let r = raw(h.addr, &get("/"), Duration::from_secs(1)).await;
    assert!(r.is_empty(), "plain HTTP on a PROXY listener is dropped silently: {r:?}");
    // Truncated / malformed headers.
    for bad in [&b"PROXY TCP4 1.2.3.4 5.6.7.8 80\r\n"[..], b"PROXY nonsense\r\n", b"\r\n\r\n\0\r\nQUIT\n\x11\x11\0\0"] {
        let mut req = bad.to_vec();
        req.extend_from_slice(&get("/"));
        let r = raw(h.addr, &req, Duration::from_secs(1)).await;
        assert!(r.is_empty(), "{bad:?} → {r:?}");
    }
    // A header that never finishes is cut off by the header timeout.
    let slow = pp_config(b, "", "") + "\n[timeouts]\nheader_read = \"300ms\"\n";
    let h2 = start(&slow).await;
    let t0 = std::time::Instant::now();
    let r = raw(h2.addr, b"PROXY TCP4 1.2.3.4", Duration::from_secs(5)).await;
    assert!(r.is_empty() && t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing ever reached the backend");
    let m = h.proxy.metrics().render().unwrap();
    assert!(m.contains("velox_proxy_protocol_errors_total{reason=\"invalid\"} 4"), "{m}");
    assert!(h2.proxy.metrics().render().unwrap().contains("reason=\"timeout\""));
    h.running.shutdown().await;
    h2.running.shutdown().await;
}

#[tokio::test]
async fn only_trusted_peers_may_send_a_proxy_header() {
    let (b, hits) = backend(echo_headers()).await;
    // 127.0.0.1 (the test client) is NOT in the trust list.
    let cfg = pp_config(b, "", "").replace("127.0.0.0/8", "10.0.0.0/8");
    let h = start(&cfg).await;
    let mut req = encode_v2(sa("1.2.3.4:5"), sa("10.0.0.1:80"), &[]);
    req.extend_from_slice(&get("/forged"));
    let r = raw(h.addr, &req, Duration::from_secs(1)).await;
    assert!(r.is_empty(), "an untrusted peer cannot choose its own address: {r:?}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert!(h
        .proxy
        .metrics()
        .render()
        .unwrap()
        .contains("velox_proxy_protocol_errors_total{reason=\"untrusted_peer\"} 1"));
    h.running.shutdown().await;
}

#[tokio::test]
async fn the_proxy_header_client_is_untrusted_so_its_forwarding_headers_are_discarded() {
    let (b, _) = backend(echo_headers()).await;
    let h = start(&pp_config(b, "", "")).await;
    // The real client (from the header) claims, in HTTP, to be someone else.
    let mut req = encode_v2(sa("203.0.113.7:1"), sa("10.0.0.1:80"), &[]);
    req.extend_from_slice(
        b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 9.9.9.9\r\nX-Real-IP: 8.8.8.8\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n",
    );
    let r = raw(h.addr, &req, Duration::from_secs(2)).await;
    let b = body(&r).to_ascii_lowercase();
    assert!(b.contains("x-forwarded-for: 203.0.113.7\n") && !b.contains("9.9.9.9"), "{b}");
    assert!(b.contains("x-real-ip: 203.0.113.7\n") && !b.contains("8.8.8.8"), "{b}");
    assert!(b.contains("x-forwarded-proto: http\n"), "{b}");
    h.running.shutdown().await;

    // If the operator lists the real client's network as a trusted proxy, its
    // chain *is* honoured (e.g. a CDN in front of the NLB).
    let (b, _) = backend(echo_headers()).await;
    let cfg = pp_config(b, "", "").replace("[admin]", "[security]\ntrusted_proxies = [\"203.0.113.0/24\"]\n[admin]");
    let h = start(&cfg).await;
    let mut req = encode_v2(sa("203.0.113.7:1"), sa("10.0.0.1:80"), &[]);
    req.extend_from_slice(
        b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 9.9.9.9\r\nConnection: close\r\n\r\n",
    );
    let r = raw(h.addr, &req, Duration::from_secs(2)).await;
    assert!(body(&r).to_ascii_lowercase().contains("x-real-ip: 9.9.9.9"), "{r}");
    h.running.shutdown().await;
}

#[tokio::test]
async fn connection_limits_apply_per_real_client_not_per_load_balancer() {
    let (b, _) = backend(echo_headers()).await;
    let cfg = pp_config(b, "", "").replace("[admin]", "[limits]\nmax_connections_per_ip = 1\n[admin]");
    let h = start(&cfg).await;
    let open = |client: &'static str| {
        let addr = h.addr;
        async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(&encode_v2(sa(client), sa("10.0.0.1:80"), &[])).await.unwrap();
            // Keep the connection open and idle; learn whether the proxy kept it.
            tokio::time::sleep(Duration::from_millis(150)).await;
            s
        }
    };
    // Different real clients share the load balancer's 127.0.0.1 without hitting its cap…
    let (mut a, mut b2) = (open("203.0.113.1:1").await, open("203.0.113.2:1").await);
    // …but a second connection from the *same* real client is refused.
    let mut dup = open("203.0.113.1:2").await;
    for (s, label, alive) in
        [(&mut a, "first", true), (&mut b2, "other client", true), (&mut dup, "same client again", false)]
    {
        s.write_all(&get("/")).await.unwrap();
        let mut out = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_string(&mut out)).await;
        assert_eq!(status(&out) == 200, alive, "{label}: {out:?}");
    }
    h.running.shutdown().await;
}

#[tokio::test]
async fn l4_proxies_can_require_a_proxy_header_and_do_not_forward_it() {
    // A raw TCP echo backend.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    let cfg = format!(
        "[server]\nproxy_protocol_trusted = [\"127.0.0.0/8\"]\n[admin]\n\
         [[upstream]]\nname = \"raw\"\nbackends = [{{ addr = \"{echo}\" }}]\n\
         [[tcp_proxy]]\nlisten = \"127.0.0.1:0\"\nupstream = \"raw\"\nproxy_protocol = true\n"
    );
    let h = start_l4(&cfg).await;
    let addr = h.running.tcp_proxy_addrs[0];
    let mut req = encode_v2(sa("203.0.113.5:1"), sa("10.0.0.1:9000"), &[]);
    req.extend_from_slice(b"ping");
    let r = raw(addr, &req, Duration::from_millis(400)).await;
    assert_eq!(r, "ping", "the header is consumed, never relayed to the backend");
    // Anything that does not start with a header is dropped.
    assert_eq!(raw(addr, b"ping", Duration::from_millis(400)).await, "");
    h.running.shutdown().await;
}

async fn start_l4(toml: &str) -> Harness {
    let cfg = Config::from_toml_str(toml).unwrap();
    let state = SharedState::new(cfg).unwrap();
    let proxy =
        Proxy::new(state, Arc::new(Metrics::new().unwrap()), Arc::new(ChallengeStore::default()), Shutdown::new());
    let running = velox_proxy::start(Arc::clone(&proxy), None).await.unwrap();
    Harness { addr: "127.0.0.1:1".parse().unwrap(), proxy, running }
}

// ---------------- response compression ----------------

use http_body_util::{BodyExt, Empty};
use std::io::Read as _;

/// One request through a real client connection; returns status, headers and the
/// raw (still encoded) body.
async fn fetch(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> (http::StatusCode, http::HeaderMap, Vec<u8>) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(conn);
    let mut req = Request::builder().method(method).uri(path).header("host", "example.test");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = sender.send_request(req.body(Empty::<Bytes>::new()).unwrap()).await.unwrap();
    let (parts, body) = resp.into_parts();
    (parts.status, parts.headers, body.collect().await.unwrap().to_bytes().to_vec())
}

fn decode(encoding: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    match encoding {
        "gzip" => flate2::read::GzDecoder::new(data).read_to_end(&mut out).unwrap(),
        "br" => brotli::Decompressor::new(data, 4096).read_to_end(&mut out).unwrap(),
        "zstd" => zstd::stream::read::Decoder::new(data).unwrap().read_to_end(&mut out).unwrap(),
        other => panic!("unknown encoding {other}"),
    };
    out
}

fn article() -> Vec<u8> {
    let line =
        "Velox compresses responses on the fly: {\"id\": 42, \"name\": \"streaming\", \"tags\": [\"a\", \"b\"]}\n";
    line.repeat(300).into_bytes()
}

fn content_backend(
    content_type: &'static str,
    body: Vec<u8>,
    extra: &'static [(&'static str, &'static str)],
) -> Handler {
    Arc::new(move |_req| {
        let mut r = Response::new(Full::new(Bytes::from(body.clone())));
        r.headers_mut().insert("content-type", content_type.parse().unwrap());
        r.headers_mut().insert("etag", "\"v1\"".parse().unwrap());
        for (k, v) in extra {
            r.headers_mut().insert(*k, v.parse().unwrap());
        }
        r
    })
}

fn compression_config(backend: SocketAddr, compression: &str, route: &str) -> String {
    base(route, &[backend]).replace("[admin]", &format!("[compression]\n{compression}\n[admin]"))
}

#[tokio::test]
async fn responses_are_compressed_according_to_accept_encoding() {
    let doc = article();
    let (b, hits) = backend(content_backend("application/json", doc.clone(), &[])).await;
    let h = start(&compression_config(b, "enabled = true", "")).await;

    for (accept, expect) in [
        ("zstd", Some("zstd")),
        ("br", Some("br")),
        ("gzip", Some("gzip")),
        ("gzip, deflate, br", Some("br")),
        ("gzip, br, zstd", Some("zstd")),
        ("br;q=0.2, gzip;q=0.9", Some("gzip")),
        ("br;q=0, gzip;q=0, zstd;q=0", None),
        ("identity", None),
        ("deflate", None),
    ] {
        let (status, headers, body) = fetch(h.addr, "GET", "/doc", &[("accept-encoding", accept)]).await;
        assert_eq!(status, 200, "{accept}");
        assert_eq!(headers["vary"], "Accept-Encoding", "{accept}: caches must key on the header");
        match expect {
            Some(enc) => {
                assert_eq!(headers["content-encoding"], enc, "{accept}");
                assert!(!headers.contains_key("content-length"), "{accept}: length is unknown when streaming");
                assert_eq!(headers["transfer-encoding"], "chunked", "{accept}");
                assert_eq!(headers["etag"], "W/\"v1\"", "{accept}: compressed variant has a weak validator");
                assert_eq!(decode(enc, &body), doc, "{accept}: body must decode to the original");
                assert!(body.len() < doc.len() / 5, "{accept}: {} → {}", doc.len(), body.len());
            }
            None => {
                assert!(!headers.contains_key("content-encoding"), "{accept}");
                assert_eq!(body, doc, "{accept}");
                assert_eq!(headers["etag"], "\"v1\"", "{accept}: identity keeps its strong validator");
            }
        }
    }
    // No Accept-Encoding header at all.
    let (_, headers, body) = fetch(h.addr, "GET", "/doc", &[]).await;
    assert!(!headers.contains_key("content-encoding") && body == doc);
    assert_eq!(headers["vary"], "Accept-Encoding");
    assert_eq!(hits.load(Ordering::SeqCst), 10);
    let m = h.proxy.metrics().render().unwrap();
    assert!(m.contains("velox_compression_responses_total{encoding=\"br\"} 2"), "{m}");
    h.running.shutdown().await;
}

#[tokio::test]
async fn compression_is_opt_in_and_routes_can_override_it() {
    let doc = article();
    let (b, _) = backend(content_backend("text/html", doc.clone(), &[])).await;
    let ae = [("accept-encoding", "gzip")];

    // Off by default: bytes pass through, no Vary noise.
    let h = start(&base("", &[b])).await;
    let (_, headers, body) = fetch(h.addr, "GET", "/", &ae).await;
    assert!(!headers.contains_key("content-encoding") && !headers.contains_key("vary"));
    assert_eq!((body.len(), headers["content-length"].to_str().unwrap()), (doc.len(), doc.len().to_string().as_str()));
    h.running.shutdown().await;

    // A route can opt in while the global switch is off…
    let on_route = base("compress = true\n", &[b]);
    let h = start(&on_route).await;
    let (_, headers, _) = fetch(h.addr, "GET", "/", &ae).await;
    assert_eq!(headers["content-encoding"], "gzip");
    h.running.shutdown().await;

    // …and opt out while it is on.
    let h = start(&compression_config(b, "enabled = true", "compress = false\n")).await;
    let (_, headers, _) = fetch(h.addr, "GET", "/", &ae).await;
    assert!(!headers.contains_key("content-encoding") && !headers.contains_key("vary"));
    h.running.shutdown().await;

    // Restricting algorithms applies to negotiation.
    let h = start(&compression_config(b, "enabled = true\nalgorithms = [\"gzip\"]", "")).await;
    let (_, headers, _) = fetch(h.addr, "GET", "/", &[("accept-encoding", "zstd, br, gzip")]).await;
    assert_eq!(headers["content-encoding"], "gzip");
    h.running.shutdown().await;
}

#[tokio::test]
async fn already_encoded_small_binary_and_no_transform_responses_pass_through_unchanged() {
    use std::io::Write as _;
    let doc = article();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&doc).unwrap();
    let pre_gzipped = gz.finish().unwrap();

    // (label, backend, body expected on the wire, Content-Encoding expected)
    let cases: Vec<(&str, Handler, Vec<u8>, Option<&str>)> = vec![
        (
            "backend already gzipped",
            content_backend("text/html", pre_gzipped.clone(), &[("content-encoding", "gzip")]),
            pre_gzipped.clone(),
            Some("gzip"),
        ),
        ("too small", content_backend("text/html", vec![b'a'; 200], &[]), vec![b'a'; 200], None),
        ("image", content_backend("image/png", doc.clone(), &[]), doc.clone(), None),
        (
            "no-transform",
            content_backend("text/html", doc.clone(), &[("cache-control", "public, no-transform")]),
            doc.clone(),
            None,
        ),
        ("SSE", content_backend("text/event-stream", doc.clone(), &[]), doc.clone(), None),
    ];
    for (label, handler, wire, encoding) in cases {
        let (b, _) = backend(handler).await;
        let h = start(&compression_config(b, "enabled = true\nmin_size = 1000", "")).await;
        let (status, headers, body) = fetch(h.addr, "GET", "/", &[("accept-encoding", "gzip, br")]).await;
        assert_eq!(status, 200, "{label}");
        assert_eq!(body, wire, "{label}: bytes must be exactly what the backend sent (never double-encoded)");
        assert_eq!(headers.get("content-encoding").map(|v| v.to_str().unwrap()), encoding, "{label}");
        assert!(!headers.contains_key("vary"), "{label}: an ineligible response is left completely alone: {headers:?}");
        assert_eq!(headers["etag"], "\"v1\"", "{label}: validators untouched");
        h.running.shutdown().await;
    }
}

#[tokio::test]
async fn head_requests_vary_but_are_never_encoded_and_status_codes_without_bodies_are_ignored() {
    let doc = article();
    let (b, _) = backend(content_backend("text/html", doc.clone(), &[])).await;
    let h = start(&compression_config(b, "enabled = true", "")).await;
    let (status, headers, body) = fetch(h.addr, "HEAD", "/", &[("accept-encoding", "gzip")]).await;
    assert_eq!(status, 200);
    assert!(body.is_empty());
    assert!(!headers.contains_key("content-encoding"));
    assert_eq!(headers["vary"], "Accept-Encoding");
    assert_eq!(headers["content-length"].to_str().unwrap(), doc.len().to_string());
    h.running.shutdown().await;

    let (b, _) = backend(Arc::new(|_| {
        let mut r = text("");
        *r.status_mut() = http::StatusCode::NOT_MODIFIED;
        r.headers_mut().insert("content-type", "text/html".parse().unwrap());
        r
    }))
    .await;
    let h = start(&compression_config(b, "enabled = true", "")).await;
    let (status, headers, _) = fetch(h.addr, "GET", "/", &[("accept-encoding", "gzip")]).await;
    assert_eq!(status, 304);
    assert!(!headers.contains_key("content-encoding") && !headers.contains_key("vary"));
    h.running.shutdown().await;
}

#[tokio::test]
async fn streamed_responses_are_delivered_incrementally_not_held_until_the_end() {
    // A backend that emits an NDJSON event, then goes quiet for a while, then another.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    let (tx, rx) = tokio::sync::mpsc::channel::<Result<http_body::Frame<Bytes>, Infallible>>(4);
                    tokio::spawn(async move {
                        let _ = tx.send(Ok(http_body::Frame::data(Bytes::from_static(b"{\"event\":1}\n")))).await;
                        tokio::time::sleep(Duration::from_millis(1200)).await;
                        let _ = tx.send(Ok(http_body::Frame::data(Bytes::from_static(b"{\"event\":2}\n")))).await;
                    });
                    let body = http_body_util::StreamBody::new(tokio_stream_from(rx));
                    let mut r = Response::new(body);
                    r.headers_mut().insert("content-type", "application/x-ndjson".parse().unwrap());
                    Ok::<_, Infallible>(r)
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
        }
    });
    let h = start(&compression_config(b, "enabled = true", "")).await;
    let stream = TcpStream::connect(h.addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .uri("/events")
        .header("host", "example.test")
        .header("accept-encoding", "gzip")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let t0 = std::time::Instant::now();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.headers()["content-encoding"], "gzip");
    let mut body = resp.into_body();
    // The first compressed bytes must arrive long before the second event exists.
    let first = loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), body.frame()).await.unwrap().unwrap().unwrap();
        if let Ok(d) = frame.into_data() {
            if !d.is_empty() {
                break d;
            }
        }
    };
    assert!(t0.elapsed() < Duration::from_millis(900), "event 1 was held back for {:?}", t0.elapsed());
    let mut partial = flate2::read::GzDecoder::new(&first[..]);
    let mut buf = [0u8; 64];
    let n = partial.read(&mut buf).unwrap_or(0);
    assert_eq!(&buf[..n], b"{\"event\":1}\n", "the early bytes decode to the first event on their own");
    // …and the whole stream still decodes after the second one.
    let mut all = first.to_vec();
    while let Some(f) = body.frame().await {
        if let Ok(d) = f.unwrap().into_data() {
            all.extend_from_slice(&d);
        }
    }
    assert_eq!(decode("gzip", &all), b"{\"event\":1}\n{\"event\":2}\n");
    h.running.shutdown().await;
}

/// `mpsc::Receiver` as a `Stream` without pulling in `tokio-stream`.
fn tokio_stream_from<T>(rx: tokio::sync::mpsc::Receiver<T>) -> impl futures_util::Stream<Item = T> {
    futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|v| (v, rx)) })
}
