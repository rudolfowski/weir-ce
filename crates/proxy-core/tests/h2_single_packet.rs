//! E2 integration test: minimal HTTP/2 client (framer) + single-packet.
//! The h2c server (crate `h2`) counts streams; the `single_packet` client sends N
//! bodyless requests on a single connection, releasing the ending frames together.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use proxy_core::HttpRequest;
use proxy_core::TlsContext;
use tempfile::tempdir;
use tokio::net::TcpListener;

/// HTTP/2 cleartext server (prior-knowledge). Each stream -> `200 OK` with "ok".
async fn spawn_h2c() -> (SocketAddr, Arc<AtomicU32>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicU32::new(0));
    let hits_srv = hits.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let hits = hits_srv.clone();
            tokio::spawn(async move {
                let Ok(mut conn) = h2::server::handshake(tcp).await else {
                    return;
                };
                while let Some(Ok((_req, mut respond))) = conn.accept().await {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let resp = http::Response::builder().status(200).body(()).unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(bytes::Bytes::from_static(b"ok"), true);
                    }
                }
            });
        }
    });
    (addr, hits)
}

fn tls() -> Arc<TlsContext> {
    let dir = tempdir().expect("tempdir");
    TlsContext::new(dir.path(), Vec::new()).expect("tls")
}

fn req(addr: SocketAddr) -> HttpRequest {
    HttpRequest {
        method: "GET".to_owned(),
        target: format!("http://{addr}/race"),
        version: "HTTP/2".to_owned(),
        headers: Vec::new(),
        body: Vec::new(),
        raw: false,
    }
}

#[tokio::test]
async fn single_packet_h2c_all_200() {
    let (addr, hits) = spawn_h2c().await;
    let reqs: Vec<HttpRequest> = (0..10).map(|_| req(addr)).collect();

    let out = proxy_core::single_packet(&reqs, &tls())
        .await
        .expect("connection");

    assert_eq!(out.len(), 10);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        10,
        "server received 10 streams"
    );
    assert!(
        out.iter()
            .all(|r| matches!(r, Ok(resp) if resp.status == 200)),
        "all 200: {out:?}"
    );
    assert!(out
        .iter()
        .all(|r| matches!(r, Ok(resp) if resp.body == b"ok")));
}
