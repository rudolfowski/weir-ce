//! Integration test: full HTTPS MITM. The client sends CONNECT to the proxy, the proxy
//! presents a leaf cert signed by the local weir root CA, terminates TLS, connects over TLS to
//! the real (self-signed) target, and captures the plaintext request/response pairs.
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use proxy_core::CapturedExchange;
use proxy_core::{bind, ExchangeSink, TlsContext};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

struct VecSink(Mutex<Vec<CapturedExchange>>);

impl ExchangeSink for VecSink {
    fn record(&self, captured: CapturedExchange) {
        self.0.lock().expect("sink mutex").push(captured);
    }
}

fn install_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// HTTPS target server with a self-signed cert for "localhost". Returns (address, cert DER to trust).
async fn spawn_https_origin() -> (SocketAddr, CertificateDer<'static>) {
    let key = KeyPair::generate().expect("origin key");
    let params = CertificateParams::new(vec!["localhost".to_owned()]).expect("origin params");
    let cert = params.self_signed(&key).expect("origin cert");
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("origin server config");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let io = TokioIo::new(tls);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|req: Request<Incoming>| async move {
                            let method = req.method().clone();
                            let path = req.uri().path().to_owned();
                            let _ = req.into_body().collect().await;
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
                                "secret:{method} {path}"
                            )))))
                        }),
                    )
                    .await;
            });
        }
    });
    (addr, cert_der)
}

/// Client through the MITM: CONNECT to the proxy, then TLS trusting the weir root CA, then GET in the tunnel.
async fn mitm_get(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    weir_ca: CertificateDer<'static>,
    path: &str,
) -> (u16, String) {
    // 1. CONNECT.
    let mut tcp = TcpStream::connect(proxy).await.expect("connect proxy");
    let connect = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    tcp.write_all(connect.as_bytes())
        .await
        .expect("write connect");

    let mut acc: Vec<u8> = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let n = tcp.read(&mut buf).await.expect("read connect resp");
        assert!(n > 0, "proxy closed the connection before 200");
        acc.extend_from_slice(&buf[..n]);
        if acc.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&acc);
    assert!(head.starts_with("HTTP/1.1 200"), "CONNECT 200: {head}");

    // 2. TLS to the proxy, trusting the weir root CA.
    let mut roots = RootCertStore::empty();
    roots.add(weir_ca).expect("add weir ca");
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_config));
    let sni = ServerName::try_from(host.to_owned()).expect("sni");
    let tls = connector.connect(sni, tcp).await.expect("tls to proxy");

    // 3. HTTP in the tunnel.
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("host", format!("{host}:{port}"))
        .body(Full::new(Bytes::new()))
        .expect("build req");
    let resp = sender.send_request(req).await.expect("send req");
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.expect("collect body").to_bytes();
    (
        parts.status.as_u16(),
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

#[tokio::test]
async fn mitm_intercepts_https_and_captures_plaintext() {
    install_provider();

    let (origin, origin_cert) = spawn_https_origin().await;

    // TlsContext with a one-off root CA; trusts the target's self-signed cert via extra_roots.
    let dir = tempdir().expect("tempdir");
    let tls = TlsContext::new(dir.path(), vec![origin_cert]).expect("tls context");
    let weir_ca = tls.ca_cert_der().clone();

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
                tls,
                proxy_core::MatchReplace::new(),
                std::sync::Arc::new(proxy_core::NoIntercept),
            )
            .await;
    });

    let (status, body) = mitm_get(proxy_addr, "localhost", origin.port(), weir_ca, "/secret").await;
    assert_eq!(status, 200, "status through the MITM");
    assert!(body.contains("secret:GET /secret"), "body: {body}");

    // Plaintext captured inside the tunnel.
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
    assert_eq!(ex.host, "localhost");
    assert_eq!(ex.request.method, "GET");
    // Port preserved in the target (server on an ephemeral port, not 443).
    assert_eq!(
        ex.request.target,
        format!("https://localhost:{}/secret", origin.port())
    );
    let resp = ex.response.as_ref().expect("response");
    assert_eq!(resp.status, 200);
    assert!(String::from_utf8_lossy(&resp.body).contains("secret:GET /secret"));
}
