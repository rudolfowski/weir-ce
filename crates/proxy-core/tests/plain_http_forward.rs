//! Integration test: the proxy forwards a plain-HTTP request to a local echo server
//! and captures the full request/response pair.
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use proxy_core::{bind, ExchangeSink, MatchReplace, TlsContext};
use proxy_core::{CapturedExchange, MatchReplaceRule};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// TlsContext with a one-off CA in a temporary directory (the CA lands in memory, so the
/// directory may disappear after creation).
fn test_tls() -> Arc<TlsContext> {
    let dir = tempdir().expect("tempdir");
    TlsContext::new(dir.path(), Vec::new()).expect("tls context")
}

/// Sink collecting captured exchanges into a vector — for assertions.
struct VecSink(Mutex<Vec<CapturedExchange>>);

impl ExchangeSink for VecSink {
    fn record(&self, captured: CapturedExchange) {
        self.0.lock().expect("sink mutex").push(captured);
    }
}

/// Local target server: responds 200 with body `echo:{METHOD} {PATH}`.
async fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|req: Request<Incoming>| async move {
                            let method = req.method().clone();
                            let path = req.uri().path().to_owned();
                            let _ = req.into_body().collect().await;
                            let body = format!("echo:{method} {path}");
                            Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                Bytes::from(body),
                            )))
                        }),
                    )
                    .await;
            });
        }
    });
    addr
}

/// Raw proxy client: sends an absolute-form request-target (proxy mode) and reads the full response.
async fn proxy_request(proxy: SocketAddr, absolute_url: &str, host_header: &str) -> String {
    let mut stream = TcpStream::connect(proxy).await.expect("connect proxy");
    let req = format!(
        "GET {absolute_url} HTTP/1.1\r\nHost: {host_header}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.expect("write req");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read resp");
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn forwards_plain_http_and_captures_exchange() {
    let origin = spawn_origin().await;
    let sink = Arc::new(VecSink(Mutex::new(Vec::new())));

    let listener = bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind proxy");
    let proxy_addr = listener.local_addr();
    let serve_sink = sink.clone();
    tokio::spawn(async move {
        let _ = listener
            .serve(
                serve_sink,
                test_tls(),
                proxy_core::MatchReplace::new(),
                std::sync::Arc::new(proxy_core::NoIntercept),
            )
            .await;
    });

    let url = format!("http://{origin}/echo");
    let raw = proxy_request(proxy_addr, &url, &origin.to_string()).await;

    // The target's response reached the client through the proxy.
    assert!(raw.starts_with("HTTP/1.1 200"), "status line: {raw}");
    assert!(raw.contains("echo:GET /echo"), "echo in body: {raw}");

    // The exchange was captured (wait a moment in case the sink records just after send).
    let mut captured = Vec::new();
    for _ in 0..50 {
        captured = sink.0.lock().unwrap().clone();
        if !captured.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(captured.len(), 1, "exactly one exchange");

    let ex = &captured[0];
    assert_eq!(ex.request.method, "GET");
    assert_eq!(ex.host, origin.ip().to_string());
    assert!(
        ex.request.target.contains("/echo"),
        "target: {}",
        ex.request.target
    );
    let resp = ex.response.as_ref().expect("response present");
    assert_eq!(resp.status, 200);
    assert!(String::from_utf8_lossy(&resp.body).contains("echo:GET /echo"));

    // The round trip is measured at the capture point. An absent value would mean the activity log
    // shows a blank duration for every proxied request — the common case, and the one place where
    // "how long did the target take" is asked most.
    assert!(
        ex.duration_ms.is_some(),
        "the proxy must measure the target round trip"
    );
}

#[tokio::test]
async fn applies_match_replace_on_response() {
    let origin = spawn_origin().await;
    let sink = Arc::new(VecSink(Mutex::new(Vec::new())));
    let listener = bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind proxy");
    let proxy_addr = listener.local_addr();

    let mr = MatchReplace::new();
    mr.set(vec![MatchReplaceRule {
        name: "upper-echo".to_owned(),
        match_pattern: "echo".to_owned(),
        replace_with: "ECHO".to_owned(),
        on_request: false,
        on_response: true,
    }]);
    let serve_sink = sink.clone();
    let serve_mr = mr.clone();
    tokio::spawn(async move {
        let _ = listener
            .serve(
                serve_sink,
                test_tls(),
                serve_mr,
                std::sync::Arc::new(proxy_core::NoIntercept),
            )
            .await;
    });

    let url = format!("http://{origin}/echo");
    let raw = proxy_request(proxy_addr, &url, &origin.to_string()).await;
    // The rule replaces ALL occurrences (battering-ram): "echo:GET /echo" -> "ECHO:GET /ECHO".
    assert!(raw.contains("ECHO:GET /ECHO"), "rewritten response: {raw}");
    assert!(
        !raw.contains("echo:GET"),
        "the original should not pass through: {raw}"
    );

    // The captured exchange also has the rewritten response.
    let mut captured = Vec::new();
    for _ in 0..50 {
        captured = sink.0.lock().unwrap().clone();
        if !captured.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let resp = captured[0].response.as_ref().expect("response");
    assert!(String::from_utf8_lossy(&resp.body).contains("ECHO:GET /ECHO"));
}

#[tokio::test]
async fn refuses_non_loopback_bind() {
    // Invariant 10: binding outside loopback is forbidden.
    let err = bind("0.0.0.0:0".parse().unwrap()).await;
    assert!(err.is_err(), "bind on 0.0.0.0 must be rejected");
}

/// Sink that also records what the HTTP parser refused — the surface `on_client_rejected` adds.
struct RejectSink {
    captured: Mutex<Vec<CapturedExchange>>,
    rejected: Mutex<Vec<(SocketAddr, String)>>,
}

impl ExchangeSink for RejectSink {
    fn record(&self, captured: CapturedExchange) {
        self.captured.lock().expect("sink mutex").push(captured);
    }

    fn on_client_rejected(&self, peer: SocketAddr, detail: &str) {
        self.rejected
            .lock()
            .expect("reject mutex")
            .push((peer, detail.to_owned()));
    }
}

/// A request-target hyper refuses to parse must not vanish silently.
///
/// `<` is not a legal character in a request-target, so hyper answers 400 and never calls the
/// service — `record` cannot see it. For an attack proxy that is precisely the case the operator
/// needs told: the malformed target is usually deliberate, and without a signal a refused request
/// is indistinguishable from one the target ignored.
#[tokio::test]
async fn malformed_request_target_is_surfaced_not_swallowed() {
    let sink = Arc::new(RejectSink {
        captured: Mutex::new(Vec::new()),
        rejected: Mutex::new(Vec::new()),
    });

    let listener = bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind proxy");
    let proxy_addr = listener.local_addr();
    let serve_sink = sink.clone();
    tokio::spawn(async move {
        let _ = listener
            .serve(
                serve_sink,
                test_tls(),
                proxy_core::MatchReplace::new(),
                std::sync::Arc::new(proxy_core::NoIntercept),
            )
            .await;
    });

    let mut stream = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    stream
        .write_all(b"GET http://127.0.0.1/search?q=<b> HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .expect("write req");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read resp");
    let raw = String::from_utf8_lossy(&buf).into_owned();
    assert!(raw.starts_with("HTTP/1.1 400"), "status line: {raw}");

    let mut rejected = Vec::new();
    for _ in 0..50 {
        rejected = sink.rejected.lock().unwrap().clone();
        if !rejected.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        rejected.len(),
        1,
        "the refusal must reach the sink exactly once"
    );
    assert_eq!(
        rejected[0].0.ip().to_string(),
        "127.0.0.1",
        "peer is carried through"
    );
    assert!(!rejected[0].1.is_empty(), "a reason is carried through");

    // And it is NOT recorded as an exchange: nothing was sent, so nothing was exchanged.
    assert!(
        sink.captured.lock().unwrap().is_empty(),
        "a refused request must not become an exchange"
    );
}

/// The counter-case that keeps the hook from becoming log noise: an ordinary client disconnect is
/// not a parse error, and must NOT be reported as a refusal.
#[tokio::test]
async fn client_hangup_is_not_reported_as_a_refusal() {
    let sink = Arc::new(RejectSink {
        captured: Mutex::new(Vec::new()),
        rejected: Mutex::new(Vec::new()),
    });

    let listener = bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind proxy");
    let proxy_addr = listener.local_addr();
    let serve_sink = sink.clone();
    tokio::spawn(async move {
        let _ = listener
            .serve(
                serve_sink,
                test_tls(),
                proxy_core::MatchReplace::new(),
                std::sync::Arc::new(proxy_core::NoIntercept),
            )
            .await;
    });

    // Connect, send half a request line, drop the connection.
    let mut stream = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    stream
        .write_all(b"GET http://127.0.0.1/")
        .await
        .expect("write");
    drop(stream);
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        sink.rejected.lock().unwrap().is_empty(),
        "a hang-up mid-request is connection churn, not a refusal the operator must see"
    );
}
