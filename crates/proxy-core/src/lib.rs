//! The proxy engine: MITM, TLS, a local root CA (rcgen) and the raw-send path.
//! Plain HTTP is forwarded; HTTPS is MITM'd — CONNECT tunneled, a leaf cert minted on the fly
//! signed by the local root CA, plaintext captured in the middle. Everything binds only
//! to loopback. The raw-send path comes later.
#![forbid(unsafe_code)]

mod ca;
mod client;
mod h2raw;
mod match_replace;
mod proxy;
mod upstream;
mod ws;

pub use ca::TlsContext;
pub use client::{
    connect_and_prime, send, send_capped, send_raw_sequence, send_raw_timed, target_host,
    PrimedConn,
};
pub use h2raw::single_packet;
pub use match_replace::MatchReplace;
pub use proxy::{bind, ExchangeSink, Interceptor, NoIntercept, ProxyListener};
pub use upstream::Upstream;
pub use ws::WsInjector;
// Re-export the transport DTOs the engine's public API speaks in (defined in the open-core
// `http-model` crate), so callers and integration tests can name them as `proxy_core::…`.
pub use http_model::{
    CapturedExchange, Header, HttpRequest, HttpResponse, MatchReplaceRule, WsDir, WsFrame,
    WsFrameSummary,
};

/// Proxy-layer errors — typed, never swallowed.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("refused to bind non-loopback address: {0}")]
    NonLoopbackBind(std::net::IpAddr),
    #[error("bind {addr}: {source}")]
    Bind {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("accept: {0}")]
    Accept(#[source] std::io::Error),
    #[error("connect {host}:{port}: {source}")]
    Connect {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },
    #[error("http: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("body: {0}")]
    Body(#[source] hyper::Error),
    #[error(
        "body exceeds relay buffer cap ({0} bytes) — raise WEIR_MAX_RELAY_BYTES (0 = unlimited)"
    )]
    BodyTooLarge(usize),
    #[error("io: {0}")]
    Io(#[source] std::io::Error),
    #[error("build request/response: {0}")]
    Build(#[from] hyper::http::Error),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("tls to client (MITM): {0}")]
    TlsClient(#[source] std::io::Error),
    #[error("tls to target (upstream): {0}")]
    TlsUpstream(#[source] std::io::Error),
    #[error("upstream proxy: {0}")]
    Upstream(String),
    #[error("certificate generation: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("ca io {path}: {source}")]
    CaIo {
        path: String,
        #[source]
        source: std::io::Error,
    },
}
