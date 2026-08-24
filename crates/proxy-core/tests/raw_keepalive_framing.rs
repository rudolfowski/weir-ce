//! The raw-send and race paths must end a read when the RESPONSE ends, not when the connection
//! goes quiet. A keep-alive target never closes, so an idle-terminated read charges every send the
//! full idle backstop — 3 s per raw replay, and 3 s added to every shot of a last-byte race, which
//! is where `time_ms` is supposed to show the millisecond spread that decides who won.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use http_model::{Header, HttpRequest};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use proxy_core::TlsContext;
use tempfile::tempdir;
use tokio::net::TcpListener;

/// Anything under this proves the read did not wait out the 3 s idle backstop; the real figure is
/// single-digit milliseconds, so the margin is for a loaded CI box, not for the bug.
const FRAMED_CEILING: Duration = Duration::from_millis(1500);

fn test_tls() -> Arc<TlsContext> {
    let dir = tempdir().expect("tempdir");
    TlsContext::new(dir.path(), Vec::new()).expect("tls context")
}

/// A KEEP-ALIVE origin: hyper's http1 server answers with `Content-Length` and holds the connection
/// open afterwards — exactly what a real target does, and what an idle-terminated read cannot tell
/// apart from a target that is still thinking.
async fn spawn_keepalive_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|req: Request<Incoming>| async move {
                            let path = req.uri().path().to_owned();
                            let _ = req.into_body().collect().await;
                            Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                Bytes::from(format!("ok:{path}")),
                            )))
                        }),
                    )
                    .await;
            });
        }
    });
    addr
}

fn raw_get(addr: SocketAddr, path: &str) -> HttpRequest {
    HttpRequest {
        method: "GET".to_owned(),
        target: format!("http://{addr}{path}"),
        version: "HTTP/1.1".to_owned(),
        headers: vec![Header {
            name: "host".to_owned(),
            value: addr.to_string(),
        }],
        body: Vec::new(),
        raw: true,
    }
}

#[tokio::test]
async fn raw_send_returns_when_the_response_is_complete_not_when_the_socket_goes_quiet() {
    let addr = spawn_keepalive_origin().await;
    let tls = test_tls();
    let request = raw_get(addr, "/raw");

    let started = Instant::now();
    let response = proxy_core::send(&request, &tls).await.expect("raw send");
    let elapsed = started.elapsed();

    assert_eq!(response.status, 200, "the response is parsed, not a blob");
    assert_eq!(response.body, b"ok:/raw", "body framed by Content-Length");
    assert!(
        elapsed < FRAMED_CEILING,
        "raw send took {elapsed:?} — it waited out the idle backstop instead of framing"
    );
}

#[tokio::test]
async fn a_primed_race_shot_reports_the_targets_time_not_the_idle_backstop() {
    let addr = spawn_keepalive_origin().await;
    let tls = test_tls();
    let request = raw_get(addr, "/shot");

    // The race shape: everything but the last byte, then the release, then the read.
    let mut primed = proxy_core::connect_and_prime(&request, &tls, 1)
        .await
        .expect("prime");
    let started = Instant::now();
    primed.send_last().await.expect("release");
    let response = primed.read_response().await.expect("read shot");
    let elapsed = started.elapsed();

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok:/shot");
    assert!(
        elapsed < FRAMED_CEILING,
        "one shot took {elapsed:?} — every shot of a race would carry that, and the spread \
         between shots is the whole verdict"
    );
}
