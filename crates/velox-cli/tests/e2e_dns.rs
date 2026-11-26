//! Periodic DNS refresh of multi-address hostname backends, through the full app.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use support::*;
use velox_cli::App;
use velox_core::Config;
use velox_health::Resolver;

/// A resolver whose answer the test changes at will.
#[derive(Default)]
struct Scripted(Mutex<Vec<IpAddr>>);

impl Scripted {
    fn set(&self, ips: &[&str]) {
        *self.0.lock().unwrap() = ips.iter().map(|s| s.parse().unwrap()).collect();
    }
}

impl Resolver for Scripted {
    fn resolve<'a>(
        &'a self,
        _host: &'a str,
        _port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>> {
        Box::pin(async move { Ok(self.0.lock().unwrap().clone()) })
    }
}

/// Two backends on the *same port* but different loopback addresses, like two
/// pods behind one headless service. `None` if IPv6 loopback is unavailable.
async fn twin_backends(slow_v4: Option<Arc<tokio::sync::Notify>>) -> Option<(u16, Mock, Mock)> {
    // A port that is free on both loopbacks (and IPv6 loopback must exist at all).
    let port = (0..50).find_map(|_| {
        let v6 = std::net::TcpListener::bind("[::1]:0").ok()?;
        let port = v6.local_addr().ok()?.port();
        let v4 = std::net::TcpListener::bind(("127.0.0.1", port)).ok()?;
        drop((v6, v4));
        Some(port)
    })?;
    let v4 = handler(move |_| {
        let gate = slow_v4.clone();
        async move {
            if let Some(g) = gate {
                g.notified().await;
            }
            text("v4")
        }
    });
    let a = Mock::start_on(format!("127.0.0.1:{port}").parse().unwrap(), v4).await;
    let b = Mock::start_on(format!("[::1]:{port}").parse().unwrap(), handler(|_| async { text("v6") })).await;
    Some((port, a, b))
}

fn config(port: u16, dns: &str) -> Config {
    Config::from_toml_str(&format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\ndrain_timeout = \"1s\"\n[admin]\naddr = \"127.0.0.1:0\"\n\
         [[upstream]]\nname = \"app\"\nretries = 0\ndns = {dns}\nbackends = [{{ addr = \"svc.internal:{port}\" }}]\n\
         [[route]]\nupstream = \"app\"\n"
    ))
    .unwrap()
}

async fn body_of(addr: SocketAddr) -> (u16, String) {
    let (status, _, body) = plain(addr, "/", "").await;
    (status, body)
}

#[tokio::test]
async fn the_pool_follows_dns_without_dropping_a_request() {
    let Some((port, v4, v6)) = twin_backends(None).await else {
        eprintln!("skipping: no IPv6 loopback in this environment");
        return;
    };
    let resolver = Arc::new(Scripted::default());
    resolver.set(&["127.0.0.1"]);
    let app =
        App::start_with_resolver(config(port, "{ refresh_interval = \"1s\" }"), None, resolver.clone()).await.unwrap();
    let (http, admin_addr) = (app.running.http_addr.unwrap(), app.admin_addr.unwrap());

    // Phase 1: one address.
    eventually(10, "pool to expand to the first answer", || async {
        let (_, v) = admin(admin_addr, "GET", "/admin/v1/upstreams/app", None).await;
        v["backends"][0]["resolved_from"] == "svc.internal"
    })
    .await;
    for _ in 0..6 {
        assert_eq!(body_of(http).await, (200, "v4".to_owned()));
    }
    let (_, v) = admin(admin_addr, "GET", "/admin/v1/upstreams/app", None).await;
    assert_eq!(v["backends"][0]["addr"], format!("127.0.0.1:{port}"));

    // Phase 2: the service scales to two addresses while traffic keeps flowing.
    let stop = Arc::new(AtomicBool::new(false));
    let (ok, failed) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let load: Vec<_> = (0..4)
        .map(|_| {
            let (stop, ok, failed) = (Arc::clone(&stop), Arc::clone(&ok), Arc::clone(&failed));
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    match body_of(http).await {
                        (200, _) => ok.fetch_add(1, Ordering::Relaxed),
                        _ => failed.fetch_add(1, Ordering::Relaxed),
                    };
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
        })
        .collect();
    resolver.set(&["127.0.0.1", "::1"]);
    eventually(10, "both addresses to serve traffic", || async {
        let (a, b) = (v4.hits(), v6.hits());
        a > 5 && b > 5
    })
    .await;
    let (_, v) = admin(admin_addr, "GET", "/admin/v1/upstreams/app", None).await;
    assert_eq!(v["backends"].as_array().unwrap().len(), 2);

    // Phase 3: the IPv4 member is retired; the survivor takes over.
    resolver.set(&["::1"]);
    eventually(10, "the retired address to stop receiving traffic", || async {
        let before = v4.hits();
        tokio::time::sleep(Duration::from_millis(300)).await;
        v4.hits() == before
    })
    .await;
    stop.store(true, Ordering::Relaxed);
    for l in load {
        l.await.unwrap();
    }
    assert_eq!(
        failed.load(Ordering::Relaxed),
        0,
        "no request failed while the pool changed ({} ok)",
        ok.load(Ordering::Relaxed)
    );
    assert!(ok.load(Ordering::Relaxed) > 50);
    for _ in 0..5 {
        assert_eq!(body_of(http).await, (200, "v6".to_owned()));
    }
    let metrics = app.metrics.render().unwrap();
    assert!(metrics.contains("velox_dns_changes_total{upstream=\"app\"} 3"), "{metrics}");
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn a_request_in_flight_on_a_retired_address_still_completes() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let Some((port, _v4, _v6)) = twin_backends(Some(Arc::clone(&gate))).await else {
        eprintln!("skipping: no IPv6 loopback in this environment");
        return;
    };
    let resolver = Arc::new(Scripted::default());
    resolver.set(&["127.0.0.1"]);
    let app =
        App::start_with_resolver(config(port, "{ refresh_interval = \"1s\" }"), None, resolver.clone()).await.unwrap();
    let http = app.running.http_addr.unwrap();
    eventually(10, "expansion", || async {
        let (_, v) = admin(app.admin_addr.unwrap(), "GET", "/admin/v1/upstreams/app", None).await;
        v["backends"][0]["resolved_from"] == "svc.internal"
    })
    .await;

    // Park a request on the IPv4 member…
    let parked = tokio::spawn(async move { body_of(http).await });
    eventually(5, "the request to reach the backend", || async {
        let (_, v) = admin(app.admin_addr.unwrap(), "GET", "/admin/v1/upstreams/app", None).await;
        v["backends"][0]["active_requests"] == 1
    })
    .await;
    // …then remove that address from DNS and wait for the pool to drop it.
    resolver.set(&["::1"]);
    eventually(10, "the IPv4 member to leave the pool", || async {
        let (_, v) = admin(app.admin_addr.unwrap(), "GET", "/admin/v1/upstreams/app", None).await;
        v["backends"][0]["addr"] == format!("[::1]:{port}")
    })
    .await;
    // The request that was already running is untouched by the change.
    gate.notify_waiters();
    assert_eq!(parked.await.unwrap(), (200, "v4".to_owned()));
    assert!(app.shutdown().await);
}
