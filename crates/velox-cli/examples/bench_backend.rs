//! A minimal, fast HTTP/1.1 backend for load tests.
//!
//! ```text
//! cargo run --release -p velox-cli --example bench_backend -- 127.0.0.1:3000
//! ```
#![allow(missing_docs)]

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:3000".to_owned());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("bench backend listening on {addr}");
    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        tokio::spawn(async move {
            let svc = service_fn(|req: Request<hyper::body::Incoming>| async move {
                // `/big…` answers a cacheable 64 KiB body (exercises large buffers and
                // the response cache); everything else is a tiny fixed reply.
                if req.uri().path().starts_with("/big") {
                    let mut r = Response::new(Full::new(Bytes::from(vec![b'x'; 64 * 1024])));
                    r.headers_mut().insert("cache-control", http::HeaderValue::from_static("max-age=300"));
                    r.headers_mut().insert("content-type", http::HeaderValue::from_static("application/octet-stream"));
                    return Ok::<_, Infallible>(r);
                }
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"hello from the backend\n"))))
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
        });
    }
}
