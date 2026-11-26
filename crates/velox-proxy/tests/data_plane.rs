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

// ---------------- HTTP/1.0 backends ----------------

/// A deliberately ancient backend: answers `HTTP/1.0`, optionally with no
/// length (the body is delimited by closing the connection).
async fn http10_backend(with_length: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let reply: &[u8] = if with_length {
                    b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nX-Legacy: yes\r\n\r\nhello legacy"
                } else {
                    b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nX-Legacy: yes\r\n\r\nhello legacy"
                };
                // (11 bytes declared: "hello legacy" is 12, the declared length wins)
                let _ = s.write_all(reply).await;
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn http10_backend_responses_are_normalised_for_clients() {
    for with_length in [false, true] {
        let b = http10_backend(with_length).await;
        let h = start(&base("", &[b])).await;
        let r =
            raw(h.addr, b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n", Duration::from_secs(2))
                .await;
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"), "length={with_length}: the 1.0 status line must not leak: {r}");
        assert!(r.to_ascii_lowercase().contains("x-legacy: yes"), "headers survive: {r}");
        if with_length {
            assert!(r.to_ascii_lowercase().contains("content-length: 11"), "{r}");
            assert_eq!(body(&r), "hello legac", "declared framing is preserved exactly");
        } else {
            // Close-delimited upstream body becomes a properly framed HTTP/1.1 body.
            assert!(r.to_ascii_lowercase().contains("transfer-encoding: chunked"), "{r}");
            assert!(r.contains("hello legacy"), "{r}");
        }
        // Keep-alive works toward the client even though the backend hop never could.
        let two = raw(
            h.addr,
            b"GET /a HTTP/1.1\r\nHost: example.test\r\n\r\nGET /b HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(two.matches("HTTP/1.1 200 OK").count(), 2, "{two}");
        assert!(!two.contains("HTTP/1.0"), "{two}");
        h.running.shutdown().await;
    }
}

#[tokio::test]
async fn http10_clients_still_get_http10_semantics() {
    let (b, _) = backend(echo_headers()).await;
    let h = start(&base("", &[b])).await;
    let r = raw(h.addr, b"GET / HTTP/1.0\r\nHost: example.test\r\n\r\n", Duration::from_secs(2)).await;
    assert!(r.starts_with("HTTP/1.0 200") || r.starts_with("HTTP/1.1 200"), "{r}");
    assert!(!r.to_ascii_lowercase().contains("transfer-encoding: chunked"), "no chunking for a 1.0 client: {r}");
    h.running.shutdown().await;
}

// ---------------- compression: encoder cap ----------------

/// `/hold` streams one chunk and then stays open until released; anything else
/// is an ordinary compressible document.
async fn hold_backend(release: Arc<tokio::sync::Notify>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let doc = article();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let (release, doc) = (Arc::clone(&release), doc.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let (release, doc) = (Arc::clone(&release), doc.clone());
                    async move {
                        let hold = req.uri().path() == "/hold";
                        let (tx, rx) = tokio::sync::mpsc::channel::<Result<http_body::Frame<Bytes>, Infallible>>(4);
                        tokio::spawn(async move {
                            let _ = tx.send(Ok(http_body::Frame::data(Bytes::from(doc)))).await;
                            if hold {
                                release.notified().await;
                                let _ = tx.send(Ok(http_body::Frame::data(Bytes::from_static(b"tail\n")))).await;
                            }
                        });
                        let mut r = Response::new(http_body_util::StreamBody::new(tokio_stream_from(rx)));
                        r.headers_mut().insert("content-type", "text/html".parse().unwrap());
                        Ok::<_, Infallible>(r)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn compression_never_queues_or_fails_traffic_when_every_encoder_slot_is_busy() {
    let release = Arc::new(tokio::sync::Notify::new());
    let b = hold_backend(Arc::clone(&release)).await;
    let h = start(&compression_config(b, "enabled = true\nmax_concurrent_encoders = 1", "")).await;
    let ae = [("accept-encoding", "gzip")];

    // Request A takes the only slot and keeps it (its body is still streaming).
    let stream = TcpStream::connect(h.addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .uri("/hold")
        .header("host", "example.test")
        .header("accept-encoding", "gzip")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.headers()["content-encoding"], "gzip");
    let mut a_body = resp.into_body();
    let first = a_body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert!(!first.is_empty());

    // B finds no free slot: it is served promptly, correctly, just uncompressed —
    // and its headers do not pretend otherwise.
    let t0 = std::time::Instant::now();
    let (status, headers, body) = fetch(h.addr, "GET", "/doc", &ae).await;
    assert_eq!(status, 200);
    assert!(t0.elapsed() < Duration::from_secs(1), "no queueing behind the busy encoder: {:?}", t0.elapsed());
    assert!(!headers.contains_key("content-encoding"), "{headers:?}");
    assert_eq!(headers["vary"], "Accept-Encoding");
    assert_eq!(body, article());
    let m = h.proxy.metrics().render().unwrap();
    assert!(m.contains("velox_compression_skipped_total{reason=\"saturated\"} 1"), "{m}");
    assert!(m.contains("velox_compression_encoders_active 1"), "{m}");

    // Finish A: the slot frees up and compression resumes.
    release.notify_waiters();
    let mut all = first.to_vec();
    while let Some(f) = a_body.frame().await {
        if let Ok(d) = f.unwrap().into_data() {
            all.extend_from_slice(&d);
        }
    }
    let mut expected = article();
    expected.extend_from_slice(b"tail\n");
    assert_eq!(decode("gzip", &all), expected, "the held response completed intact");
    for _ in 0..100 {
        if h.proxy.metrics().render().unwrap().contains("velox_compression_encoders_active 0") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (_, headers, body) = fetch(h.addr, "GET", "/doc", &ae).await;
    assert_eq!(headers["content-encoding"], "gzip", "slot released ⇒ compressing again");
    assert_eq!(decode("gzip", &body), article());
    h.running.shutdown().await;
}

// ---------------- CORS ----------------

fn cors_config(backend: SocketAddr, cors: &str) -> String {
    base(&format!("[route.cors]\n{cors}\n"), &[backend])
}

fn cors_backend() -> Handler {
    // A backend with opinions of its own: it claims `*` + credentials, which the
    // edge policy must override.
    Arc::new(|req| {
        let mut r = text(&format!("{} {}", req.method(), req.uri()));
        r.headers_mut().insert("access-control-allow-origin", "*".parse().unwrap());
        r.headers_mut().insert("access-control-allow-credentials", "true".parse().unwrap());
        r.headers_mut().insert("access-control-expose-headers", "x-backend-secret".parse().unwrap());
        r
    })
}

#[tokio::test]
async fn cors_preflights_are_answered_at_the_edge_and_never_reach_the_backend() {
    let (b, hits) = backend(cors_backend()).await;
    let h = start(&cors_config(
        b,
        "allow_origins = [\"https://app.example.com\", \"https://*.partner.test\"]\n\
         allow_methods = [\"GET\", \"POST\", \"PUT\"]\nallow_headers = [\"content-type\", \"x-api-key\"]\n\
         allow_credentials = true\nmax_age = \"10m\"\nexpose_headers = [\"x-request-id\"]",
    ))
    .await;
    let preflight = |origin: &'static str, method: &'static str, headers: &'static str| {
        let extra: Vec<(&str, &str)> = [("origin", origin), ("access-control-request-method", method)]
            .into_iter()
            .chain((!headers.is_empty()).then_some(("access-control-request-headers", headers)))
            .collect();
        let addr = h.addr;
        async move { fetch(addr, "OPTIONS", "/api", &extra).await }
    };

    for origin in ["https://app.example.com", "https://eu.partner.test"] {
        let (status, headers, body) = preflight(origin, "PUT", "content-type, x-api-key").await;
        assert_eq!(status, 204, "{origin}");
        assert!(body.is_empty());
        assert_eq!(headers["access-control-allow-origin"], origin);
        assert_eq!(headers["access-control-allow-methods"], "GET, POST, PUT");
        assert_eq!(headers["access-control-allow-headers"], "content-type, x-api-key");
        assert_eq!(headers["access-control-allow-credentials"], "true");
        assert_eq!(headers["access-control-max-age"], "600");
        let vary = headers.get_all("vary").iter().map(|v| v.to_str().unwrap()).collect::<Vec<_>>().join(",");
        assert!(vary.contains("Origin") && vary.contains("Access-Control-Request-Method"), "{vary}");
    }
    // Refusals: 403 and no Access-Control-* at all.
    for (origin, method, hdrs, why) in [
        ("https://evil.test", "GET", "", "origin"),
        ("https://app.example.com", "DELETE", "", "method"),
        ("https://app.example.com", "GET", "x-secret", "header"),
    ] {
        let (status, headers, _) = preflight(origin, method, hdrs).await;
        assert_eq!(status, 403, "{why}");
        assert!(!headers.keys().any(|k| k.as_str().starts_with("access-control-")), "{why}: {headers:?}");
        let m = h.proxy.metrics().render().unwrap();
        assert!(m.contains(&format!("velox_cors_denied_total{{reason=\"{why}\",route=\"route-0\"}}")), "{m}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no preflight, allowed or not, reached the backend");

    // An OPTIONS request that is *not* a preflight (no Access-Control-Request-Method) is just proxied.
    let (status, _, body) = fetch(h.addr, "OPTIONS", "/api", &[("origin", "https://app.example.com")]).await;
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).starts_with("OPTIONS /api"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    h.running.shutdown().await;
}

#[tokio::test]
async fn cors_policy_replaces_the_backends_headers_on_real_and_error_responses() {
    let (b, _) = backend(cors_backend()).await;
    let h =
        start(&cors_config(b, "allow_origins = [\"https://app.example.com\"]\nexpose_headers = [\"x-request-id\"]"))
            .await;
    // Allowed origin: the edge's policy, not the backend's `*` + credentials.
    let (status, headers, _) = fetch(h.addr, "GET", "/data", &[("origin", "https://app.example.com")]).await;
    assert_eq!(status, 200);
    assert_eq!(headers["access-control-allow-origin"], "https://app.example.com");
    assert!(!headers.contains_key("access-control-allow-credentials"), "backend's credentials claim removed");
    assert_eq!(headers["access-control-expose-headers"], "x-request-id");
    assert!(headers["vary"].to_str().unwrap().contains("Origin"));
    // Disallowed origin: the backend's permissive headers are stripped, nothing replaces them.
    let (status, headers, body) = fetch(h.addr, "GET", "/data", &[("origin", "https://evil.test")]).await;
    assert_eq!(status, 200, "the request itself is still served (CORS is enforced by the browser)");
    assert!(!headers.keys().any(|k| k.as_str().starts_with("access-control-")), "{headers:?}");
    assert!(!body.is_empty());
    // No Origin: no CORS headers, still varies.
    let (_, headers, _) = fetch(h.addr, "GET", "/data", &[]).await;
    assert!(!headers.contains_key("access-control-allow-origin"));
    assert!(headers["vary"].to_str().unwrap().contains("Origin"));
    h.running.shutdown().await;

    // Velox's own errors carry the policy, so the browser reports the real status.
    let dead = refused_port().await;
    let h = start(&cors_config(dead, "allow_origins = [\"https://app.example.com\"]")).await;
    let (status, headers, _) = fetch(h.addr, "GET", "/", &[("origin", "https://app.example.com")]).await;
    assert_eq!(status, 502);
    assert_eq!(
        headers["access-control-allow-origin"], "https://app.example.com",
        "a 502 must not look like a CORS failure"
    );
    h.running.shutdown().await;

    // Rate limited requests too.
    let (b, _) = backend(cors_backend()).await;
    let cfg = cors_config(b, "allow_origins = [\"https://app.example.com\"]")
        .replace("[route.cors]", "rate_limit = { requests_per_second = 0.001, burst = 1 }\n[route.cors]");
    let h = start(&cfg).await;
    let mut statuses = Vec::new();
    for _ in 0..3 {
        let (status, headers, _) = fetch(h.addr, "GET", "/", &[("origin", "https://app.example.com")]).await;
        assert_eq!(headers["access-control-allow-origin"], "https://app.example.com", "status {status}");
        statuses.push(status);
    }
    assert!(statuses.contains(&http::StatusCode::TOO_MANY_REQUESTS), "{statuses:?}");
    h.running.shutdown().await;
}

#[tokio::test]
async fn routes_without_cors_are_untouched_and_wildcard_origin_needs_no_credentials() {
    let (b, hits) = backend(cors_backend()).await;
    // No [route.cors]: the backend's own headers pass through, preflights are proxied.
    let h = start(&base("", &[b])).await;
    let (_, headers, _) = fetch(h.addr, "GET", "/", &[("origin", "https://x.test")]).await;
    assert_eq!(headers["access-control-allow-origin"], "*");
    assert_eq!(headers["access-control-allow-credentials"], "true");
    let (status, _, _) =
        fetch(h.addr, "OPTIONS", "/", &[("origin", "https://x.test"), ("access-control-request-method", "GET")]).await;
    assert_eq!(status, 200);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    h.running.shutdown().await;

    let h = start(&cors_config(b, "allow_origins = [\"*\"]")).await;
    let (_, headers, _) = fetch(h.addr, "GET", "/", &[("origin", "https://anyone.test")]).await;
    assert_eq!(headers["access-control-allow-origin"], "*");
    assert!(!headers.contains_key("access-control-allow-credentials"));
    let (_, headers, _) = fetch(h.addr, "GET", "/", &[]).await;
    assert_eq!(headers["access-control-allow-origin"], "*", "a credential-less `*` answers everyone");
    h.running.shutdown().await;
}

// ---------------- W3C trace context ----------------

fn echo_trace() -> Handler {
    Arc::new(|req| {
        let get = |n: &str| req.headers().get(n).map_or_else(String::new, |v| v.to_str().unwrap().to_owned());
        text(&format!("traceparent={}\ntracestate={}\n", get("traceparent"), get("tracestate")))
    })
}

fn field<'a>(body: &'a str, name: &str) -> &'a str {
    body.lines().find_map(|l| l.strip_prefix(&format!("{name}="))).unwrap_or("")
}

#[tokio::test]
async fn traceparent_is_continued_or_minted_and_never_forwarded_when_disabled() {
    const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const SPAN: &str = "00f067aa0ba902b7";
    let (b, _) = backend(echo_trace()).await;
    let cfg = base("", &[b]).replace("[admin]", "[telemetry]\ntraceparent = true\n[admin]");
    let h = start(&cfg).await;
    let go = |headers: Vec<(&'static str, String)>| {
        let addr = h.addr;
        async move {
            let hdrs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let (_, _, body) = fetch(addr, "GET", "/", &hdrs).await;
            String::from_utf8(body).unwrap()
        }
    };
    // Valid inbound: same trace, new span, flags and tracestate kept.
    let body = go(vec![("traceparent", format!("00-{TRACE}-{SPAN}-01")), ("tracestate", "vendor=x".to_owned())]).await;
    let tp = field(&body, "traceparent");
    assert!(tp.starts_with(&format!("00-{TRACE}-")) && tp.ends_with("-01"), "{tp}");
    assert_ne!(&tp[36..52], SPAN, "our hop is a new span");
    assert_eq!(field(&body, "tracestate"), "vendor=x");
    // Not sampled stays not sampled.
    let body = go(vec![("traceparent", format!("00-{TRACE}-{SPAN}-00"))]).await;
    assert!(field(&body, "traceparent").ends_with("-00"));
    // Missing, malformed, zero ids, duplicates: a fresh, valid trace and no orphan tracestate.
    for headers in [
        vec![],
        vec![("traceparent", "garbage".to_owned()), ("tracestate", "vendor=x".to_owned())],
        vec![("traceparent", format!("00-{}-{SPAN}-01", "0".repeat(32)))],
        vec![("traceparent", format!("00-{TRACE}-{SPAN}-01")), ("traceparent", format!("00-{TRACE}-{SPAN}-00"))],
    ] {
        let body = go(headers).await;
        let tp = field(&body, "traceparent");
        assert_eq!(tp.len(), 55, "{tp}");
        assert!(tp.starts_with("00-") && tp.ends_with("-01"), "{tp}");
        assert_ne!(&tp[3..35], TRACE);
        assert_eq!(field(&body, "tracestate"), "", "{body}");
    }
    h.running.shutdown().await;

    // Off by default: whatever the client sent is simply forwarded, nothing minted.
    let (b, _) = backend(echo_trace()).await;
    let h = start(&base("", &[b])).await;
    let (_, _, body) = fetch(h.addr, "GET", "/", &[]).await;
    assert_eq!(field(std::str::from_utf8(&body).unwrap(), "traceparent"), "");
    let (_, _, body) = fetch(h.addr, "GET", "/", &[("traceparent", "anything")]).await;
    assert_eq!(field(std::str::from_utf8(&body).unwrap(), "traceparent"), "anything");
    h.running.shutdown().await;
}

// ---------------- response cache ----------------

/// A backend whose every invocation yields a distinct body (`n=<count>`), so a
/// cached answer is distinguishable from a fresh one, with caller-chosen headers.
fn counting_backend(headers: &'static [(&'static str, &'static str)]) -> Handler {
    let n = Arc::new(AtomicUsize::new(0));
    Arc::new(move |req| {
        let i = n.fetch_add(1, Ordering::SeqCst) + 1;
        let lang = req.headers().get("accept-language").map_or("-", |v| v.to_str().unwrap_or("?")).to_owned();
        let mut r = text(&format!("n={i} lang={lang} {} {}", req.method(), req.uri()));
        r.headers_mut().insert("content-type", "text/plain".parse().unwrap());
        for (k, v) in headers {
            r.headers_mut().insert(*k, v.parse().unwrap());
        }
        r
    })
}

fn cache_config(backend: SocketAddr, route_cache: &str, global: &str) -> String {
    base(&format!("cache = {route_cache}\n"), &[backend]).replace("[admin]", &format!("[cache]\n{global}\n[admin]"))
}

fn cache_state(headers: &http::HeaderMap) -> &str {
    headers.get("x-velox-cache").map_or("", |v| v.to_str().unwrap())
}

fn text_of(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
}

#[tokio::test]
async fn cacheable_responses_are_served_from_memory_until_they_expire() {
    let (b, hits) = backend(counting_backend(&[("cache-control", "max-age=1"), ("etag", "\"v1\"")])).await;
    let h = start(&cache_config(b, "{}", "")).await;

    let (s1, h1, b1) = fetch(h.addr, "GET", "/page?x=1", &[]).await;
    assert_eq!((s1.as_u16(), cache_state(&h1)), (200, "MISS"));
    let (s2, h2, b2) = fetch(h.addr, "GET", "/page?x=1", &[]).await;
    assert_eq!((s2.as_u16(), cache_state(&h2)), (200, "HIT"));
    assert_eq!(b1, b2, "the hit is byte-identical to the stored response");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the backend was asked once");
    assert!(h2.contains_key("age") && h2["etag"] == "\"v1\"", "{h2:?}");
    assert_eq!(h2["content-length"].to_str().unwrap(), b2.len().to_string());
    // A different query string is a different object.
    let (_, h3, b3) = fetch(h.addr, "GET", "/page?x=2", &[]).await;
    assert_eq!(cache_state(&h3), "MISS");
    assert_ne!(b3, b1);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    // A HEAD is answered from the stored GET: headers, no body.
    let (sh, hh, bh) = fetch(h.addr, "HEAD", "/page?x=1", &[]).await;
    assert_eq!((sh.as_u16(), cache_state(&hh)), (200, "HIT"));
    assert!(bh.is_empty());
    assert_eq!(hh["content-length"].to_str().unwrap(), b1.len().to_string());
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    // After max-age the entry is gone and the backend is asked again.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let (_, h4, b4) = fetch(h.addr, "GET", "/page?x=1", &[]).await;
    assert_eq!(cache_state(&h4), "MISS");
    assert_ne!(b4, b1, "fresh content, not the stale entry");
    let m = h.proxy.metrics().render().unwrap();
    assert!(m.contains("velox_cache_hits_total{route=\"route-0\"} 2"), "{m}");
    assert!(m.contains("velox_cache_misses_total{route=\"route-0\"} 3"), "{m}");
    assert!(m.contains("velox_cache_stores_total 3"), "{m}");
    h.running.shutdown().await;
}

#[tokio::test]
async fn responses_the_backend_forbids_or_does_not_date_are_never_cached() {
    for (label, headers, cached) in [
        ("no-store", &[("cache-control", "no-store, max-age=60")][..], false),
        ("private", &[("cache-control", "private, max-age=60")][..], false),
        ("no-cache", &[("cache-control", "no-cache")][..], false),
        ("set-cookie", &[("cache-control", "max-age=60"), ("set-cookie", "sid=1")][..], false),
        ("vary *", &[("cache-control", "max-age=60"), ("vary", "*")][..], false),
        ("max-age=0", &[("cache-control", "max-age=0")][..], false),
        ("no freshness at all", &[][..], false),
        ("s-maxage alone is enough", &[("cache-control", "s-maxage=60")][..], true),
    ] {
        let (b, hits) = backend(counting_backend(Box::leak(headers.to_vec().into_boxed_slice()))).await;
        let h = start(&cache_config(b, "{}", "")).await;
        for i in 0..3 {
            let (status, headers, _) = fetch(h.addr, "GET", "/x", &[]).await;
            assert_eq!(status, 200, "{label}");
            let expect_hit = cached && i > 0;
            assert_eq!(cache_state(&headers) == "HIT", expect_hit, "{label} request {i}: {headers:?}");
            if !cached {
                assert_eq!(cache_state(&headers), "PASS", "{label}");
            }
        }
        assert_eq!(hits.load(Ordering::SeqCst), if cached { 1 } else { 3 }, "{label}");
        h.running.shutdown().await;
    }
    // Velox does not invent freshness… unless the route says how long to keep things.
    let (b, hits) = backend(counting_backend(&[])).await;
    let h = start(&cache_config(b, "{ default_ttl = \"30s\" }", "")).await;
    for _ in 0..3 {
        fetch(h.addr, "GET", "/x", &[]).await;
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    h.running.shutdown().await;
    // …and `max_ttl` caps what a backend asks for.
    let (b, hits) = backend(counting_backend(&[("cache-control", "max-age=3600")])).await;
    let h = start(&cache_config(b, "{ max_ttl = \"1s\" }", "")).await;
    fetch(h.addr, "GET", "/x", &[]).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    fetch(h.addr, "GET", "/x", &[]).await;
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    h.running.shutdown().await;
}

#[tokio::test]
async fn vary_creates_separate_variants_and_conditionals_return_304_from_the_cache() {
    let (b, hits) =
        backend(counting_backend(&[("cache-control", "max-age=60"), ("vary", "Accept-Language"), ("etag", "\"v1\"")]))
            .await;
    let h = start(&cache_config(b, "{}", "")).await;
    let get = |lang: &'static str| {
        let addr = h.addr;
        async move { fetch(addr, "GET", "/doc", &[("accept-language", lang)]).await }
    };
    let (_, h_en1, b_en1) = get("en").await;
    let (_, h_fr1, b_fr1) = get("fr").await;
    let (_, h_en2, b_en2) = get("en").await;
    let (_, h_fr2, b_fr2) = get("fr").await;
    assert_eq!(
        (cache_state(&h_en1), cache_state(&h_fr1), cache_state(&h_en2), cache_state(&h_fr2)),
        ("MISS", "MISS", "HIT", "HIT")
    );
    assert!(text_of(&b_en1).contains("lang=en") && text_of(&b_fr1).contains("lang=fr"));
    assert_eq!((b_en1, b_fr1), (b_en2, b_fr2), "each client gets its own variant back");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert_eq!(h_en2["vary"], "Accept-Language");

    // Conditional requests are answered by the cache itself.
    for inm in ["\"v1\"", "W/\"v1\"", "\"old\", \"v1\"", "*"] {
        let (status, headers, body) =
            fetch(h.addr, "GET", "/doc", &[("accept-language", "en"), ("if-none-match", inm)]).await;
        assert_eq!(status, 304, "{inm}");
        assert!(body.is_empty());
        assert_eq!((cache_state(&headers), headers["etag"].to_str().unwrap()), ("HIT", "\"v1\""));
        assert!(!headers.contains_key("content-type"), "no content headers on a 304");
    }
    let (status, _, body) =
        fetch(h.addr, "GET", "/doc", &[("accept-language", "en"), ("if-none-match", "\"stale\"")]).await;
    assert_eq!(status, 200, "a non-matching validator gets the full response");
    assert!(!body.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 2, "no conditional request reached the backend");
    h.running.shutdown().await;
}

#[tokio::test]
async fn requests_that_must_not_be_cached_bypass_it_and_writes_invalidate() {
    let (b, hits) = backend(counting_backend(&[("cache-control", "max-age=60")])).await;
    let h = start(&cache_config(b, "{}", "")).await;
    fetch(h.addr, "GET", "/res", &[]).await; // fill
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Authorization, Range and no-store requests are never served from, or stored in, the cache.
    for (label, hdr) in [
        ("authorization", ("authorization", "Bearer secret")),
        ("range", ("range", "bytes=0-3")),
        ("no-store", ("cache-control", "no-store")),
    ] {
        let before = hits.load(Ordering::SeqCst);
        let (_, headers, body) = fetch(h.addr, "GET", "/res", &[hdr]).await;
        assert_eq!(cache_state(&headers), "BYPASS", "{label}");
        assert_eq!(hits.load(Ordering::SeqCst), before + 1, "{label}: went to the backend");
        assert!(text_of(&body).starts_with(&format!("n={}", before + 1)), "{label}");
    }
    // The entry that was already there is untouched by those.
    let (_, headers, body) = fetch(h.addr, "GET", "/res", &[]).await;
    assert_eq!(cache_state(&headers), "HIT");
    assert!(text_of(&body).starts_with("n=1 "), "{}", text_of(&body));

    // `no-cache` skips the lookup but refreshes the stored copy.
    let (_, headers, body) = fetch(h.addr, "GET", "/res", &[("cache-control", "no-cache")]).await;
    assert_eq!(cache_state(&headers), "MISS");
    let refreshed = text_of(&body);
    let (_, headers, body) = fetch(h.addr, "GET", "/res", &[]).await;
    assert_eq!((cache_state(&headers), text_of(&body)), ("HIT", refreshed), "the refresh replaced the entry");

    // A successful write to the URL invalidates it (RFC 9111 §4.4).
    let stream = TcpStream::connect(h.addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(conn);
    let post = Request::builder()
        .method("POST")
        .uri("/res")
        .header("host", "example.test")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let r = sender.send_request(post).await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["x-velox-cache"], "BYPASS");
    let (_, headers, _) = fetch(h.addr, "GET", "/res", &[]).await;
    assert_eq!(cache_state(&headers), "MISS", "the POST dropped the cached GET");
    h.running.shutdown().await;
}

#[tokio::test]
async fn oversized_bodies_stream_through_intact_and_are_not_stored() {
    let big = "z".repeat(5_000);
    let (b, hits) =
        backend(content_backend_boxed("text/plain", big.clone().into_bytes(), &[("cache-control", "max-age=60")]))
            .await;
    let h = start(&cache_config(b, "{}", "max_entry_bytes = 2048\nmax_bytes = 1048576\nshards = 4")).await;
    for _ in 0..3 {
        let (status, headers, body) = fetch(h.addr, "GET", "/big", &[]).await;
        assert_eq!(status, 200);
        assert_eq!(text_of(&body), big, "the client always gets the whole body");
        assert_eq!(cache_state(&headers), "PASS");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    assert!(h.proxy.metrics().render().unwrap().contains("velox_cache_bypass_total{reason=\"too-large\"} 3"));
    h.running.shutdown().await;
}

fn content_backend_boxed(
    content_type: &'static str,
    body: Vec<u8>,
    extra: &'static [(&'static str, &'static str)],
) -> Handler {
    content_backend(content_type, body, extra)
}

#[tokio::test]
async fn memory_stays_bounded_and_the_hot_entries_survive() {
    let (b, hits) = backend(counting_backend(&[("cache-control", "max-age=300")])).await;
    // One shard, room for roughly a dozen small entries.
    let h = start(&cache_config(b, "{}", "max_bytes = 6000\nmax_entry_bytes = 1024\nshards = 1")).await;
    fetch(h.addr, "GET", "/hot", &[]).await;
    for i in 0..60 {
        fetch(h.addr, "GET", &format!("/cold/{i}"), &[]).await;
        // Keep /hot warm.
        let (_, headers, _) = fetch(h.addr, "GET", "/hot", &[]).await;
        assert_eq!(cache_state(&headers), "HIT", "round {i}: the recently used entry must not be evicted");
    }
    let m = h.proxy.metrics().render().unwrap();
    let gauge = |name: &str| -> usize {
        m.lines().find_map(|l| l.strip_prefix(name)).and_then(|v| v.trim().parse().ok()).unwrap_or(usize::MAX)
    };
    assert!(gauge("velox_cache_bytes ") <= 6000, "{m}");
    assert!(gauge("velox_cache_entries ") < 60, "old entries were evicted: {m}");
    assert!(!m.contains("velox_cache_evictions_total 0"), "{m}");
    assert_eq!(hits.load(Ordering::SeqCst), 61, "/hot hit the backend exactly once");
    h.running.shutdown().await;
}

#[tokio::test]
async fn compression_and_cors_are_applied_per_client_on_cached_responses() {
    let doc = article();
    let (b, hits) = backend(content_backend("text/html", doc.clone(), &[("cache-control", "max-age=60")])).await;
    let cfg = base("cache = {}\n", &[b]).replace("[admin]", "[compression]\nenabled = true\n[admin]").replace(
        "cache = {}\n",
        "cache = {}\n[route.cors]\nallow_origins = [\"https://a.test\", \"https://b.test\"]\n",
    );
    let h = start(&cfg).await;
    // Fill with an identity client from origin A.
    let (_, h1, b1) = fetch(h.addr, "GET", "/doc", &[("origin", "https://a.test")]).await;
    assert_eq!((cache_state(&h1), h1["access-control-allow-origin"].to_str().unwrap()), ("MISS", "https://a.test"));
    assert_eq!(b1, doc);
    // Hits are compressed per client and carry the *requesting* origin's CORS headers.
    let (_, h2, b2) = fetch(h.addr, "GET", "/doc", &[("accept-encoding", "gzip"), ("origin", "https://b.test")]).await;
    assert_eq!(cache_state(&h2), "HIT");
    assert_eq!(h2["content-encoding"], "gzip");
    assert_eq!(decode("gzip", &b2), doc);
    assert_eq!(h2["access-control-allow-origin"], "https://b.test", "origin A's header must not leak to B");
    let (_, h3, b3) = fetch(h.addr, "GET", "/doc", &[]).await;
    assert_eq!((cache_state(&h3), b3), ("HIT", doc));
    assert!(!h3.contains_key("content-encoding") && !h3.contains_key("access-control-allow-origin"));
    assert_eq!(hits.load(Ordering::SeqCst), 1, "one backend request served all three clients");
    h.running.shutdown().await;
}

#[tokio::test]
async fn routes_hosts_and_the_ignore_query_option_form_the_cache_key() {
    let (b, hits) = backend(counting_backend(&[("cache-control", "max-age=60")])).await;
    let h = start(&cache_config(b, "{ ignore_query = true }", "")).await;
    let (_, h1, b1) = fetch(h.addr, "GET", "/p?utm=1", &[]).await;
    let (_, h2, b2) = fetch(h.addr, "GET", "/p?utm=2", &[]).await;
    assert_eq!(
        (cache_state(&h1), cache_state(&h2), b1 == b2),
        ("MISS", "HIT", true),
        "the query is not part of the key"
    );
    h.running.shutdown().await;

    let h = start(&cache_config(b, "{}", "")).await;
    let on_host = |host: &'static str| {
        let addr = h.addr;
        async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let (mut s, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
            tokio::spawn(conn);
            let req = Request::builder().uri("/same").header("host", host).body(Empty::<Bytes>::new()).unwrap();
            s.send_request(req).await.unwrap().headers()["x-velox-cache"].to_str().unwrap().to_owned()
        }
    };
    assert_eq!(on_host("a.test").await, "MISS");
    assert_eq!(on_host("A.TEST").await, "HIT", "hosts compare case-insensitively");
    assert_eq!(on_host("b.test").await, "MISS", "another host is another object");
    let _ = hits;
    h.running.shutdown().await;
}

#[tokio::test]
async fn routes_without_a_cache_table_are_untouched() {
    let (b, hits) = backend(counting_backend(&[("cache-control", "max-age=60")])).await;
    let h = start(&base("", &[b])).await;
    for _ in 0..3 {
        let (_, headers, _) = fetch(h.addr, "GET", "/x", &[]).await;
        assert!(!headers.contains_key("x-velox-cache"));
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    h.running.shutdown().await;
    // `enabled = false` switches a configured route off without deleting the table.
    let (b, hits) = backend(counting_backend(&[("cache-control", "max-age=60")])).await;
    let h = start(&cache_config(b, "{ enabled = false }", "")).await;
    for _ in 0..2 {
        fetch(h.addr, "GET", "/x", &[]).await;
    }
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    h.running.shutdown().await;
}

#[tokio::test]
async fn requests_with_cookies_never_see_or_fill_the_shared_cache_unless_the_route_opts_in() {
    // The classic leak: a backend that personalises on the cookie but forgot `Vary: Cookie`.
    let (b, hits) = backend(counting_backend(&[("cache-control", "max-age=60")])).await;
    let h = start(&cache_config(b, "{}", "")).await;
    let (_, cold, _) = fetch(h.addr, "GET", "/profile", &[]).await; // an anonymous visitor fills the cache
    assert_eq!(cache_state(&cold), "MISS");
    for who in ["sid=alice", "sid=bob"] {
        let (_, headers, body) = fetch(h.addr, "GET", "/profile", &[("cookie", who)]).await;
        assert_eq!(cache_state(&headers), "BYPASS", "{who}");
        assert!(text_of(&body).starts_with("n="), "{who}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3, "each cookie-bearing request went to the backend");
    // …and their (possibly personal) responses were not stored for others.
    let (_, anon, body) = fetch(h.addr, "GET", "/profile", &[]).await;
    assert_eq!(cache_state(&anon), "HIT");
    assert!(text_of(&body).starts_with("n=1 "), "still the anonymous copy: {}", text_of(&body));
    assert!(h.proxy.metrics().render().unwrap().contains("velox_cache_bypass_total{reason=\"cookie\"} 2"));
    h.running.shutdown().await;

    // An explicit opt-in for routes known not to vary on cookies.
    let (b, hits) = backend(counting_backend(&[("cache-control", "max-age=60")])).await;
    let h = start(&cache_config(b, "{ allow_cookies = true }", "")).await;
    fetch(h.addr, "GET", "/asset.js", &[("cookie", "sid=alice")]).await;
    let (_, headers, _) = fetch(h.addr, "GET", "/asset.js", &[("cookie", "sid=bob")]).await;
    assert_eq!(cache_state(&headers), "HIT");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    h.running.shutdown().await;
}

// ---------------- cache: coalescing and stale serving ----------------

use std::sync::atomic::{AtomicU64, AtomicU8};
use std::sync::Mutex as StdMutex;

/// A backend the test drives: latency, failure mode, validators and counters.
struct Script {
    /// Every request that reached the backend.
    hits: AtomicUsize,
    /// Requests answered with a full `200`.
    full: AtomicUsize,
    /// Conditional requests answered `304`.
    not_modified: AtomicUsize,
    delay_ms: AtomicU64,
    /// 0 = healthy, 1 = `500`, 2 = `503`, 3 = drop the connection.
    mode: AtomicU8,
    cache_control: StdMutex<String>,
    etag: StdMutex<String>,
}

impl Script {
    fn new(cache_control: &str) -> Arc<Self> {
        Arc::new(Self {
            hits: AtomicUsize::new(0),
            full: AtomicUsize::new(0),
            not_modified: AtomicUsize::new(0),
            delay_ms: AtomicU64::new(0),
            mode: AtomicU8::new(0),
            cache_control: StdMutex::new(cache_control.to_owned()),
            etag: StdMutex::new("\"v1\"".to_owned()),
        })
    }
}

async fn scripted_backend(script: Arc<Script>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let script = Arc::clone(&script);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let s = Arc::clone(&script);
                    async move {
                        s.hits.fetch_add(1, Ordering::SeqCst);
                        // A backend decides how to answer when the request arrives, not after it dawdles.
                        let mode = s.mode.load(Ordering::SeqCst);
                        let delay = s.delay_ms.load(Ordering::SeqCst);
                        if delay > 0 {
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                        }
                        let status = match mode {
                            1 => Some(500),
                            2 => Some(503),
                            3 => return Err("connection dropped by the test"),
                            _ => None,
                        };
                        if let Some(code) = status {
                            let mut r = text("backend failure");
                            *r.status_mut() = http::StatusCode::from_u16(code).unwrap();
                            return Ok::<_, &'static str>(r);
                        }
                        let (etag, cc) = (s.etag.lock().unwrap().clone(), s.cache_control.lock().unwrap().clone());
                        let matches =
                            req.headers().get("if-none-match").is_some_and(|v| v.to_str().unwrap_or("") == etag);
                        let mut r;
                        if matches {
                            s.not_modified.fetch_add(1, Ordering::SeqCst);
                            r = text("");
                            *r.status_mut() = http::StatusCode::NOT_MODIFIED;
                        } else {
                            let n = s.full.fetch_add(1, Ordering::SeqCst) + 1;
                            r = text(&format!("body#{n} etag={etag}"));
                        }
                        r.headers_mut().insert("etag", etag.parse().unwrap());
                        r.headers_mut().insert("cache-control", cc.parse().unwrap());
                        r.headers_mut().insert("content-type", "text/plain".parse().unwrap());
                        Ok(r)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
        }
    });
    addr
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn ten_concurrent_misses_make_one_backend_request() {
    let script = Script::new("max-age=60");
    script.delay_ms.store(300, Ordering::SeqCst);
    let b = scripted_backend(Arc::clone(&script)).await;
    let h = start(&cache_config(b, "{}", "")).await;

    let t0 = std::time::Instant::now();
    let clients: Vec<_> = (0..10)
        .map(|_| {
            let addr = h.addr;
            tokio::spawn(async move { fetch(addr, "GET", "/hot", &[]).await })
        })
        .collect();
    let mut tags = Vec::new();
    let mut bodies = Vec::new();
    for c in clients {
        let (status, headers, body) = c.await.unwrap();
        assert_eq!(status, 200);
        tags.push(cache_state(&headers).to_owned());
        bodies.push(text_of(&body));
    }
    assert_eq!(script.hits.load(Ordering::SeqCst), 1, "ten simultaneous misses, one backend request");
    assert!(bodies.iter().all(|b| b == &bodies[0]), "everyone got the leader's response: {bodies:?}");
    assert_eq!(tags.iter().filter(|t| *t == "MISS").count(), 1, "{tags:?}");
    assert_eq!(tags.iter().filter(|t| *t == "HIT").count(), 9, "{tags:?}");
    assert!(t0.elapsed() < Duration::from_millis(900), "followers waited for one fetch, not ten: {:?}", t0.elapsed());
    let m = h.proxy.metrics().render().unwrap();
    assert!(m.contains("velox_cache_coalesced_total{route=\"route-0\"} 9"), "{m}");
    // And the object is now simply cached.
    assert_eq!(cache_state(&fetch(h.addr, "GET", "/hot", &[]).await.1), "HIT");
    assert_eq!(script.hits.load(Ordering::SeqCst), 1);
    h.running.shutdown().await;
}

#[tokio::test]
async fn followers_fall_back_to_their_own_fetch_when_the_result_cannot_be_shared() {
    // Not cacheable: nothing to share, so every waiter fetches for itself — and none fails.
    let script = Script::new("no-store");
    script.delay_ms.store(200, Ordering::SeqCst);
    let b = scripted_backend(Arc::clone(&script)).await;
    let h = start(&cache_config(b, "{}", "")).await;
    let results = futures_util::future::join_all((0..6).map(|_| fetch(h.addr, "GET", "/p", &[]))).await;
    assert!(results.iter().all(|(s, ..)| *s == 200));
    assert_eq!(script.hits.load(Ordering::SeqCst), 6, "no coalescing for an unshareable response");
    assert!(results.iter().all(|(_, hd, _)| cache_state(hd) == "PASS"));
    h.running.shutdown().await;

    // The leader fails: followers do not inherit its failure.
    let script = Script::new("max-age=60");
    script.delay_ms.store(250, Ordering::SeqCst);
    script.mode.store(2, Ordering::SeqCst); // the first request will see a 503
    let b = scripted_backend(Arc::clone(&script)).await;
    let h = start(&cache_config(b, "{}", "")).await;
    let leader = tokio::spawn({
        let addr = h.addr;
        async move { fetch(addr, "GET", "/f", &[]).await }
    });
    until("the leader to reach the backend", || script.hits.load(Ordering::SeqCst) == 1).await;
    script.mode.store(0, Ordering::SeqCst); // the backend recovers while the followers wait
    let followers: Vec<_> = (0..4).map(|_| fetch(h.addr, "GET", "/f", &[])).collect();
    let followers = futures_util::future::join_all(followers).await;
    assert_eq!(leader.await.unwrap().0, 503, "the leader reports the failure it saw");
    assert!(followers.iter().all(|(s, ..)| *s == 200), "followers fetched for themselves and succeeded");
    h.running.shutdown().await;
}

#[tokio::test]
async fn coalescing_can_be_disabled_and_waiters_give_up_after_their_timeout() {
    let script = Script::new("max-age=60");
    script.delay_ms.store(300, Ordering::SeqCst);
    let b = scripted_backend(Arc::clone(&script)).await;
    let h = start(&cache_config(b, "{ coalesce = false }", "")).await;
    futures_util::future::join_all((0..5).map(|_| fetch(h.addr, "GET", "/x", &[]))).await;
    assert_eq!(script.hits.load(Ordering::SeqCst), 5, "opt-out: every miss goes to the backend");
    h.running.shutdown().await;

    let script = Script::new("max-age=60");
    script.delay_ms.store(900, Ordering::SeqCst);
    let b = scripted_backend(Arc::clone(&script)).await;
    let h = start(&cache_config(b, "{ coalesce_timeout = \"150ms\" }", "")).await;
    let t0 = std::time::Instant::now();
    let r = futures_util::future::join_all((0..4).map(|_| fetch(h.addr, "GET", "/slow", &[]))).await;
    assert!(r.iter().all(|(s, ..)| *s == 200));
    assert_eq!(script.hits.load(Ordering::SeqCst), 4, "waiters stopped waiting and fetched themselves");
    assert!(t0.elapsed() < Duration::from_millis(1800), "{:?}", t0.elapsed());
    assert!(h.proxy.metrics().render().unwrap().contains("velox_cache_coalesce_timeouts_total{route=\"route-0\"} 3"));
    h.running.shutdown().await;
}

#[tokio::test]
async fn stale_while_revalidate_answers_instantly_and_refreshes_once_in_the_background() {
    let script = Script::new("max-age=1, stale-while-revalidate=30");
    let b = scripted_backend(Arc::clone(&script)).await;
    let h = start(&cache_config(b, "{}", "")).await;
    let (_, h1, b1) = fetch(h.addr, "GET", "/doc", &[]).await;
    assert_eq!(cache_state(&h1), "MISS");
    assert_eq!(text_of(&b1), "body#1 etag=\"v1\"");
    tokio::time::sleep(Duration::from_millis(1300)).await; // now stale, inside the window

    // The backend is slow now; the client must not feel it. Several stale
    // requests at once trigger exactly one revalidation.
    script.delay_ms.store(500, Ordering::SeqCst);
    let t0 = std::time::Instant::now();
    let stale = futures_util::future::join_all((0..5).map(|_| fetch(h.addr, "GET", "/doc", &[]))).await;
    assert!(
        t0.elapsed() < Duration::from_millis(400),
        "answered from the stale copy, not the slow backend: {:?}",
        t0.elapsed()
    );
    for (status, headers, body) in &stale {
        assert_eq!(*status, 200);
        assert_eq!(cache_state(headers), "REVALIDATING");
        assert_eq!(text_of(body), "body#1 etag=\"v1\"", "the stale copy");
        assert!(headers["age"].to_str().unwrap().parse::<u64>().unwrap() >= 1, "Age reflects how old it is");
    }
    // The refresh is conditional: the backend confirms with a 304, no body re-sent.
    until("the revalidation to finish", || script.not_modified.load(Ordering::SeqCst) == 1).await;
    script.delay_ms.store(0, Ordering::SeqCst);
    until("the entry to be fresh again", || {
        h.proxy
            .metrics()
            .render()
            .unwrap()
            .contains("velox_cache_revalidations_total{result=\"not_modified\",route=\"route-0\"} 1")
    })
    .await;
    assert_eq!(
        script.hits.load(Ordering::SeqCst),
        2,
        "one full fetch + ONE conditional refresh for five stale requests"
    );
    assert_eq!(script.full.load(Ordering::SeqCst), 1, "no second body was transferred");
    let (_, h2, b2) = fetch(h.addr, "GET", "/doc", &[]).await;
    assert_eq!(cache_state(&h2), "HIT", "fresh again");
    assert_eq!(text_of(&b2), "body#1 etag=\"v1\"");
    let m = h.proxy.metrics().render().unwrap();
    assert!(m.contains("velox_cache_stale_served_total{kind=\"swr\",route=\"route-0\"} 5"), "{m}");
    h.running.shutdown().await;
}

#[tokio::test]
async fn a_changed_object_replaces_the_stale_copy_after_background_revalidation() {
    let script = Script::new("max-age=1, stale-while-revalidate=30");
    let b = scripted_backend(Arc::clone(&script)).await;
    let h = start(&cache_config(b, "{}", "")).await;
    fetch(h.addr, "GET", "/doc", &[]).await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    // The object changed at the origin (new validator, so the conditional request gets a full 200).
    *script.etag.lock().unwrap() = "\"v2\"".to_owned();
    let (_, headers, body) = fetch(h.addr, "GET", "/doc", &[]).await;
    assert_eq!(
        (cache_state(&headers), text_of(&body).as_str()),
        ("REVALIDATING", "body#1 etag=\"v1\""),
        "the caller still gets the old copy"
    );
    until("the new version to be stored", || script.full.load(Ordering::SeqCst) == 2).await;
    let mut replaced = false;
    for _ in 0..100 {
        let (_, headers, body) = fetch(h.addr, "GET", "/doc", &[]).await;
        if cache_state(&headers) == "HIT" && text_of(&body).contains("v2") {
            assert_eq!(text_of(&body), "body#2 etag=\"v2\"");
            replaced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(replaced, "the revalidated object never replaced the stale one");
    assert!(h
        .proxy
        .metrics()
        .render()
        .unwrap()
        .contains("velox_cache_revalidations_total{result=\"updated\",route=\"route-0\"} 1"));
    h.running.shutdown().await;
}

#[tokio::test]
async fn stale_if_error_serves_the_expired_copy_while_the_backend_is_failing() {
    let script = Script::new("max-age=1, stale-if-error=30");
    let b = scripted_backend(Arc::clone(&script)).await;
    let h = start(&cache_config(b, "{}", "")).await;
    let (_, h0, b0) = fetch(h.addr, "GET", "/doc", &[]).await;
    assert_eq!((cache_state(&h0), text_of(&b0).as_str()), ("MISS", "body#1 etag=\"v1\""));
    tokio::time::sleep(Duration::from_millis(1300)).await; // expired, inside the error window

    for (mode, what) in [(1, "500"), (2, "503"), (3, "a dropped connection")] {
        script.mode.store(mode, Ordering::SeqCst);
        let (status, headers, body) = fetch(h.addr, "GET", "/doc", &[]).await;
        assert_eq!(status, 200, "{what}: the client never sees the failure");
        assert_eq!(cache_state(&headers), "STALE", "{what}");
        assert_eq!(text_of(&body), "body#1 etag=\"v1\"", "{what}: the expired copy");
        assert!(headers["age"].to_str().unwrap().parse::<u64>().unwrap() >= 1, "{what}");
    }
    let m = h.proxy.metrics().render().unwrap();
    assert!(m.contains("velox_cache_stale_served_total{kind=\"sie\",route=\"route-0\"} 3"), "{m}");

    // Once the backend is healthy again the object is simply refetched.
    script.mode.store(0, Ordering::SeqCst);
    let (_, headers, body) = fetch(h.addr, "GET", "/doc", &[]).await;
    assert_eq!((cache_state(&headers), text_of(&body).as_str()), ("MISS", "body#2 etag=\"v1\""));
    assert_eq!(cache_state(&fetch(h.addr, "GET", "/doc", &[]).await.1), "HIT");
    h.running.shutdown().await;
}

#[tokio::test]
async fn stale_if_error_ends_with_its_window_and_never_applies_to_must_revalidate() {
    // Window of 1 s after a 1 s lifetime.
    let script = Script::new("max-age=1, stale-if-error=1");
    let b = scripted_backend(Arc::clone(&script)).await;
    let h = start(&cache_config(b, "{}", "")).await;
    fetch(h.addr, "GET", "/doc", &[]).await;
    script.mode.store(1, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert_eq!(cache_state(&fetch(h.addr, "GET", "/doc", &[]).await.1), "STALE", "inside the window");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (status, headers, _) = fetch(h.addr, "GET", "/doc", &[]).await;
    assert_eq!(status, 500, "past the window the failure is the client's problem again");
    assert!(!headers.contains_key("x-velox-cache") || cache_state(&headers) == "PASS");
    h.running.shutdown().await;

    // must-revalidate forbids serving stale at all, whatever else is said.
    let script = Script::new("max-age=1, stale-if-error=60, stale-while-revalidate=60, must-revalidate");
    let b = scripted_backend(Arc::clone(&script)).await;
    let h = start(&cache_config(b, "{ stale_if_error = \"60s\" }", "")).await;
    fetch(h.addr, "GET", "/doc", &[]).await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    script.mode.store(2, Ordering::SeqCst);
    let (status, headers, _) = fetch(h.addr, "GET", "/doc", &[]).await;
    assert_eq!(status, 503, "no stale copy for must-revalidate");
    assert_ne!(cache_state(&headers), "STALE");
    script.mode.store(0, Ordering::SeqCst);
    let (_, headers, _) = fetch(h.addr, "GET", "/doc", &[]).await;
    assert_eq!(cache_state(&headers), "MISS", "no stale-while-revalidate either: it was refetched synchronously");
    h.running.shutdown().await;
}

#[tokio::test]
async fn route_defaults_enable_stale_serving_for_backends_that_do_not_ask_for_it() {
    let script = Script::new("max-age=1"); // says nothing about staleness
    let b = scripted_backend(Arc::clone(&script)).await;
    let h = start(&cache_config(b, "{ stale_if_error = \"30s\", stale_while_revalidate = \"30s\" }", "")).await;
    fetch(h.addr, "GET", "/doc", &[]).await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    // stale-while-revalidate takes precedence while the backend is fine…
    let (_, headers, _) = fetch(h.addr, "GET", "/doc", &[]).await;
    assert_eq!(cache_state(&headers), "REVALIDATING");
    until("the refresh", || script.not_modified.load(Ordering::SeqCst) == 1).await;
    // …and the entry is fresh again; let it expire and break the backend.
    until("fresh again", || {
        h.proxy.metrics().render().unwrap().contains("velox_cache_revalidations_total{result=\"not_modified\"")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    script.mode.store(1, Ordering::SeqCst);
    let (status, headers, _) = fetch(h.addr, "GET", "/doc", &[]).await;
    // …the stale-while-revalidate window is open too, so the stale copy is served either way,
    // and the failing refresh does not take the object away.
    assert_eq!(status, 200);
    assert!(matches!(cache_state(&headers), "REVALIDATING" | "STALE"), "{headers:?}");
    until("the failed refresh to be counted", || {
        h.proxy.metrics().render().unwrap().contains("velox_cache_revalidations_total{result=\"error\"")
    })
    .await;
    let (status, headers, body) = fetch(h.addr, "GET", "/doc", &[]).await;
    assert_eq!(status, 200, "still served from the stale copy after the refresh failed");
    assert!(cache_state(&headers) == "REVALIDATING" || cache_state(&headers) == "STALE");
    assert!(text_of(&body).starts_with("body#1"));
    h.running.shutdown().await;
}

// ---------------- IP access lists ----------------

fn acl_config(backend: SocketAddr, security: &str, route: &str) -> String {
    base(route, &[backend]).replace("[admin]", &format!("[security]\n{security}\n[admin]"))
}

#[tokio::test]
async fn deny_and_allow_lists_apply_to_the_client_address_before_anything_else_happens() {
    let (b, hits) = backend(echo_headers()).await;
    // The test client is 127.0.0.1.
    let h = start(&acl_config(b, "ip_deny = [\"127.0.0.0/8\"]", "")).await;
    let r = raw(h.addr, &get("/secret"), Duration::from_secs(1)).await;
    assert_eq!(status(&r), 403, "{r}");
    assert!(
        body(&r).contains("forbidden") && !body(&r).contains("127.0.0.1") && !body(&r).contains("deny"),
        "no detail leaks: {r}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the backend never saw it");
    assert!(h
        .proxy
        .metrics()
        .render()
        .unwrap()
        .contains("velox_acl_denied_total{reason=\"deny\",route=\"route-0\",scope=\"global\"} 1"));
    h.running.shutdown().await;

    // An allow list that does not include the client.
    let h = start(&acl_config(b, "ip_allow = [\"10.0.0.0/8\"]", "")).await;
    assert_eq!(status(&raw(h.addr, &get("/"), Duration::from_secs(1)).await), 403);
    assert!(h.proxy.metrics().render().unwrap().contains("reason=\"not_allowed\""));
    h.running.shutdown().await;

    // One that does, and deny still beats it.
    let h = start(&acl_config(b, "ip_allow = [\"127.0.0.0/8\"]", "")).await;
    assert_eq!(status(&raw(h.addr, &get("/"), Duration::from_secs(1)).await), 200);
    h.running.shutdown().await;
    let h = start(&acl_config(b, "ip_allow = [\"127.0.0.0/8\"]\nip_deny = [\"127.0.0.1/32\"]", "")).await;
    assert_eq!(status(&raw(h.addr, &get("/"), Duration::from_secs(1)).await), 403, "deny wins");
    h.running.shutdown().await;
}

#[tokio::test]
async fn acls_see_the_real_client_not_the_proxy_in_front_of_us() {
    let (b, hits) = backend(echo_headers()).await;
    // 127.0.0.1 is a trusted proxy; the *client* it reports is what the lists judge.
    let cfg = |extra: &str| acl_config(b, &format!("trusted_proxies = [\"127.0.0.0/8\"]\n{extra}"), "");
    let h = start(&cfg("ip_deny = [\"203.0.113.0/24\"]")).await;
    let via = |xff: &'static str| {
        let addr = h.addr;
        async move {
            let req =
                format!("GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: {xff}\r\nConnection: close\r\n\r\n");
            status(&raw(addr, req.as_bytes(), Duration::from_secs(1)).await)
        }
    };
    assert_eq!(via("203.0.113.9").await, 403, "the denied client behind the trusted proxy");
    assert_eq!(via("198.51.100.4").await, 200, "another client behind the same proxy");
    // The chain is walked right-to-left past trusted hops: the rightmost entry is what the
    // trusted proxy actually saw, everything to its left is just a claim.
    assert_eq!(
        via("198.51.100.4, 203.0.113.9").await,
        403,
        "prepending a harmless address cannot launder a denied client"
    );
    assert_eq!(via("203.0.113.9, 198.51.100.4").await, 200, "a denied address further left is only a claim");
    h.running.shutdown().await;

    // Without trust, X-Forwarded-For is ignored: the TCP peer (127.0.0.1) is the client.
    let h = start(&acl_config(b, "ip_deny = [\"203.0.113.0/24\"]", "")).await;
    let req = b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 203.0.113.9\r\nConnection: close\r\n\r\n";
    assert_eq!(
        status(&raw(h.addr, req, Duration::from_secs(1)).await),
        200,
        "a client cannot talk its way into or out of a list"
    );
    h.running.shutdown().await;
    let _ = hits;
}

#[tokio::test]
async fn proxy_protocol_addresses_are_what_the_acl_judges() {
    use velox_proxy::proxy_protocol::encode_v2;
    let (b, hits) = backend(echo_headers()).await;
    let cfg = pp_config(b, "", "").replace("[admin]", "[security]\nip_deny = [\"203.0.113.0/24\"]\n[admin]");
    let h = start(&cfg).await;
    for (client, expect) in [("203.0.113.50:1", 403), ("198.51.100.50:1", 200)] {
        let mut req = encode_v2(sa(client), sa("10.0.0.1:80"), &[]);
        req.extend_from_slice(&get("/"));
        assert_eq!(status(&raw(h.addr, &req, Duration::from_secs(1)).await), expect, "{client}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    h.running.shutdown().await;
}

#[tokio::test]
async fn route_lists_only_narrow_what_the_global_lists_allow_and_come_before_redirects_and_limits() {
    let (b, hits) = backend(echo_headers()).await;
    let toml = format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\n[security]\nip_allow = [\"127.0.0.0/8\"]\n\
         [[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"{b}\" }}]\n\
         [[route]]\nname = \"open\"\nhosts = [\"open.test\"]\nupstream = \"app\"\n\
         [[route]]\nname = \"closed\"\nhosts = [\"closed.test\"]\nupstream = \"app\"\nip_deny = [\"127.0.0.1/32\"]\n\
         [[route]]\nname = \"redir\"\nhosts = [\"redir.test\"]\nupstream = \"app\"\nredirect_https = true\nip_deny = [\"127.0.0.1/32\"]\n\
         [[route]]\nname = \"limited\"\nhosts = [\"limited.test\"]\nupstream = \"app\"\nip_deny = [\"127.0.0.1/32\"]\n\
         rate_limit = {{ requests_per_second = 0.001, burst = 1 }}\n"
    );
    let h = start(&toml).await;
    let on = |host: &'static str| {
        let addr = h.addr;
        async move {
            let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            status(&raw(addr, req.as_bytes(), Duration::from_secs(1)).await)
        }
    };
    assert_eq!(on("open.test").await, 200);
    assert_eq!(on("closed.test").await, 403, "the route list narrows");
    assert_eq!(on("redir.test").await, 403, "a refused client is not even redirected");
    for _ in 0..3 {
        assert_eq!(on("limited.test").await, 403, "refused every time: never reaches (or exhausts) the rate limiter");
    }
    assert!(!h.proxy.metrics().render().unwrap().contains("velox_rate_limited_total{"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    h.running.shutdown().await;

    // A route cannot widen the global allow list.
    let toml = format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\n[security]\nip_allow = [\"10.0.0.0/8\"]\n\
         [[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"{b}\" }}]\n\
         [[route]]\nupstream = \"app\"\nip_allow = [\"127.0.0.0/8\"]\n"
    );
    let h = start(&toml).await;
    assert_eq!(status(&raw(h.addr, &get("/"), Duration::from_secs(1)).await), 403);
    h.running.shutdown().await;
}

// ---------------- edge JWT verification ----------------

mod jwt_support {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;
    use ring::hmac;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub const SECRET: &[u8] = b"an-hs256-secret-that-is-comfortably-long";

    pub fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    pub struct Es256 {
        pair: EcdsaKeyPair,
        pub spki_pem: String,
    }

    pub fn es256() -> Es256 {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        // SubjectPublicKeyInfo for a P-256 key: fixed prefix + the uncompressed point.
        let mut spki = hex_to_bytes("3059301306072a8648ce3d020106082a8648ce3d030107034200");
        spki.extend_from_slice(pair.public_key().as_ref());
        let body = STANDARD
            .encode(&spki)
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap().to_owned())
            .collect::<Vec<_>>()
            .join("\n");
        Es256 { pair, spki_pem: format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n") }
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn enc(v: &serde_json::Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    }

    impl Es256 {
        pub fn token(&self, claims: &serde_json::Value) -> String {
            let input = format!("{}.{}", enc(&serde_json::json!({ "alg": "ES256" })), enc(claims));
            let sig = self.pair.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
        }
    }

    pub fn hs256(claims: &serde_json::Value) -> String {
        let input = format!("{}.{}", enc(&serde_json::json!({ "alg": "HS256" })), enc(claims));
        let sig = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, SECRET), input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }

    pub fn write(dir: &Path, name: &str, data: &[u8]) -> String {
        let p = dir.join(name);
        std::fs::write(&p, data).unwrap();
        p.display().to_string()
    }
}

fn jwt_config(backend: SocketAddr, jwt_table: &str) -> String {
    base(&format!("[route.jwt]\n{jwt_table}\n"), &[backend])
}

fn bearer(token: &str) -> [(&'static str, String); 1] {
    [("authorization", format!("Bearer {token}"))]
}

async fn get_with(
    addr: SocketAddr,
    path: &str,
    headers: &[(&'static str, String)],
) -> (http::StatusCode, http::HeaderMap, Vec<u8>) {
    let hs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
    fetch(addr, "GET", path, &hs).await
}

#[tokio::test]
async fn invalid_tokens_never_reach_the_backend_and_valid_ones_do() {
    use jwt_support::*;
    let dir = tempfile::tempdir().unwrap();
    let ec = es256();
    let pem = write(dir.path(), "pub.pem", ec.spki_pem.as_bytes());
    let secret = write(dir.path(), "secret", SECRET);
    let (b, hits) = backend(echo_headers()).await;
    let h = start(&jwt_config(
        b,
        &format!(
            "algorithms = [\"ES256\", \"HS256\"]\npublic_key_file = \"{pem}\"\nsecret_file = \"{secret}\"\n\
             issuer = \"https://issuer.test\"\naudience = [\"api\"]\nleeway = \"0s\""
        ),
    ))
    .await;
    let good = |extra: serde_json::Value| {
        let mut c =
            serde_json::json!({ "sub": "alice", "iss": "https://issuer.test", "aud": "api", "exp": now() + 300 });
        c.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        c
    };

    // 200 for both algorithms.
    for (label, token) in
        [("ES256", ec.token(&good(serde_json::json!({})))), ("HS256", hs256(&good(serde_json::json!({}))))]
    {
        let (status, _, _) = get_with(h.addr, "/", &bearer(&token)).await;
        assert_eq!(status, 200, "{label}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    // Everything else is a 401 before the backend is involved.
    let expired = ec.token(&good(serde_json::json!({ "exp": now() - 60 })));
    let wrong_iss = ec.token(&good(serde_json::json!({ "iss": "https://evil.test" })));
    let wrong_aud = ec.token(&good(serde_json::json!({ "aud": "other" })));
    let not_yet = ec.token(&good(serde_json::json!({ "nbf": now() + 600 })));
    let no_exp = ec.token(&serde_json::json!({ "sub": "a", "iss": "https://issuer.test", "aud": "api" }));
    let other_key = es256().token(&good(serde_json::json!({})));
    let tampered = {
        let t = ec.token(&good(serde_json::json!({})));
        let mut p: Vec<&str> = t.split('.').collect();
        let forged = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            br#"{"sub":"admin","iss":"https://issuer.test","aud":"api","exp":9999999999}"#,
        );
        p[1] = &forged;
        p.join(".")
    };
    let none_alg = format!(
        "{}.{}.AAAA",
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, br#"{"alg":"none"}"#),
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_vec(&good(serde_json::json!({}))).unwrap()
        )
    );
    for (label, token) in [
        ("expired", expired),
        ("wrong issuer", wrong_iss),
        ("wrong audience", wrong_aud),
        ("not yet valid", not_yet),
        ("no exp", no_exp),
        ("signed by another key", other_key),
        ("tampered payload", tampered),
        ("alg none", none_alg),
        ("garbage", "not.a.jwt".to_owned()),
        ("empty", String::new()),
    ] {
        let (status, headers, body) = get_with(h.addr, "/", &bearer(&token)).await;
        assert_eq!(status, 401, "{label}");
        assert_eq!(headers["www-authenticate"], "Bearer realm=\"velox\", error=\"invalid_token\"", "{label}");
        let body = text_of(&body);
        assert!(
            !body.contains("expired") && !body.contains("signature") && !body.contains("audience"),
            "{label}: no oracle: {body}"
        );
    }
    // No token at all: 401 with the plain challenge (RFC 6750 §3.1).
    let (status, headers, _) = fetch(h.addr, "GET", "/", &[]).await;
    assert_eq!(status, 401);
    assert_eq!(headers["www-authenticate"], "Bearer realm=\"velox\"");
    assert_eq!(hits.load(Ordering::SeqCst), 2, "not one rejected request reached the backend");

    let m = h.proxy.metrics().render().unwrap();
    for reason in ["expired", "issuer", "audience", "not_yet_valid", "signature", "algorithm", "malformed", "missing"] {
        assert!(
            m.contains(&format!("velox_jwt_rejected_total{{reason=\"{reason}\",route=\"route-0\"}}")),
            "{reason}: {m}"
        );
    }
    h.running.shutdown().await;
}

#[tokio::test]
async fn verified_claims_are_forwarded_and_client_supplied_claim_headers_are_discarded() {
    use jwt_support::*;
    let dir = tempfile::tempdir().unwrap();
    let ec = es256();
    let pem = write(dir.path(), "pub.pem", ec.spki_pem.as_bytes());
    let (b, _) = backend(echo_headers()).await;
    let h = start(&jwt_config(
        b,
        &format!("public_key_file = \"{pem}\"\nforward_claims = [\"sub\", \"roles\", \"tenant_id\", \"missing\", \"nested\"]"),
    ))
    .await;
    let token = ec.token(&serde_json::json!({
        "sub": "alice", "roles": ["admin", "dev"], "tenant_id": 42, "nested": { "x": 1 }, "exp": now() + 300
    }));
    let mut headers = bearer(&token).to_vec();
    // A client trying to assert its own identity to the backend.
    headers.push(("x-jwt-sub", "root".to_owned()));
    headers.push(("x-jwt-admin", "true".to_owned()));
    let (status, _, body) = get_with(h.addr, "/who", &headers).await;
    assert_eq!(status, 200);
    let echoed = text_of(&body).to_ascii_lowercase();
    assert!(echoed.contains("x-jwt-sub: alice"), "{echoed}");
    assert!(echoed.contains("x-jwt-roles: admin,dev"), "{echoed}");
    assert!(echoed.contains("x-jwt-tenant_id: 42"), "{echoed}");
    assert!(!echoed.contains("root") && !echoed.contains("x-jwt-admin"), "spoofed headers must be dropped: {echoed}");
    assert!(!echoed.contains("x-jwt-nested") && !echoed.contains("x-jwt-missing"), "{echoed}");
    assert!(echoed.contains("authorization: bearer"), "the token itself still travels on: {echoed}");
    h.running.shutdown().await;
}

#[tokio::test]
async fn optional_tokens_cors_preflights_and_unprotected_routes() {
    use jwt_support::*;
    let dir = tempfile::tempdir().unwrap();
    let ec = es256();
    let pem = write(dir.path(), "pub.pem", ec.spki_pem.as_bytes());
    let (b, hits) = backend(echo_headers()).await;

    // `required = false`: anonymous passes, a presented token must still be valid.
    let h = start(&jwt_config(b, &format!("public_key_file = \"{pem}\"\nrequired = false"))).await;
    assert_eq!(fetch(h.addr, "GET", "/", &[]).await.0, 200, "anonymous allowed");
    let (status, ..) = get_with(h.addr, "/", &bearer(&ec.token(&serde_json::json!({ "exp": now() + 60 })))).await;
    assert_eq!(status, 200);
    assert_eq!(get_with(h.addr, "/", &bearer("bad.token.here")).await.0, 401, "a present token is always checked");
    h.running.shutdown().await;

    // CORS preflights carry no credentials: they must not be blocked by JWT.
    let toml = jwt_config(b, &format!("public_key_file = \"{pem}\"")).replace(
        "[route.jwt]",
        "[route.cors]\nallow_origins = [\"https://app.test\"]\nallow_headers = [\"authorization\"]\n[route.jwt]",
    );
    let h = start(&toml).await;
    let (status, headers, _) = fetch(
        h.addr,
        "OPTIONS",
        "/api",
        &[
            ("origin", "https://app.test"),
            ("access-control-request-method", "GET"),
            ("access-control-request-headers", "authorization"),
        ],
    )
    .await;
    assert_eq!(status, 204, "the preflight is answered before authentication");
    assert_eq!(headers["access-control-allow-origin"], "https://app.test");
    // …while the real request still needs a token, and its 401 carries the CORS headers.
    let (status, headers, _) = fetch(h.addr, "GET", "/api", &[("origin", "https://app.test")]).await;
    assert_eq!(status, 401);
    assert_eq!(headers["access-control-allow-origin"], "https://app.test");
    h.running.shutdown().await;
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    // A route without [route.jwt] is open.
    let h = start(&base("", &[b])).await;
    assert_eq!(fetch(h.addr, "GET", "/", &[]).await.0, 200);
    h.running.shutdown().await;
}

#[tokio::test]
async fn jwt_keys_rotate_live_and_a_broken_rotation_does_not_lock_users_out() {
    use jwt_support::*;
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = (es256(), es256());
    let pem = write(dir.path(), "pub.pem", old.spki_pem.as_bytes());
    let (b, _) = backend(echo_headers()).await;
    let h = start(&jwt_config(b, &format!("public_key_file = \"{pem}\"\nreload_interval = \"100ms\""))).await;
    let claims = || serde_json::json!({ "exp": now() + 600 });
    assert_eq!(get_with(h.addr, "/", &bearer(&old.token(&claims()))).await.0, 200);
    assert_eq!(get_with(h.addr, "/", &bearer(&new.token(&claims()))).await.0, 401, "not yet trusted");

    // Rotate: publish the new key in place (different length, so the change is certain to be seen).
    let rotated = format!("{}\n# rotated\n", new.spki_pem);
    std::fs::write(dir.path().join("pub.pem"), rotated).unwrap();
    let mut switched = false;
    for _ in 0..60 {
        if get_with(h.addr, "/", &bearer(&new.token(&claims()))).await.0 == 200 {
            switched = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(switched, "the rotated key was never picked up");
    assert_eq!(get_with(h.addr, "/", &bearer(&old.token(&claims()))).await.0, 401, "the retired key stopped working");

    // A half-written key file keeps the last good key serving.
    std::fs::write(dir.path().join("pub.pem"), "-----BEGIN PUBLIC KEY-----\ngarbage").unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(get_with(h.addr, "/", &bearer(&new.token(&claims()))).await.0, 200, "last good keys kept");
    h.running.shutdown().await;
}
