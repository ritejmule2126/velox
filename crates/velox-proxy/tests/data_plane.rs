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
