//! Forward proxy: plain HTTP + MITM for HTTPS.
//!
//! Plain HTTP: the client sends absolute-form, we pass it to the target, we capture the pair.
//! HTTPS (MITM): the client sends `CONNECT host:443`; we answer `200`, take over the raw TCP
//! (hyper upgrade), do a TLS handshake with the client using a leaf cert for the host (signed by the
//! local root CA), and connect to the real target over a separate TLS connection — plaintext is caught in
//! the middle and handed to [`ExchangeSink`]. This is the "polite" hyper path; raw-send comes later.
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Version};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::ca::{server_name, TlsContext};
use crate::match_replace::MatchReplace;
use crate::ws::{pump_ws_frames, WsInjector};
use crate::ProxyError;
use http_model::{CapturedExchange, Header, HttpRequest, HttpResponse, WsDir, WsFrame};

/// A sink for captured exchanges. Implement it to store or inspect traffic.
pub trait ExchangeSink: Send + Sync {
    fn record(&self, captured: CapturedExchange);

    /// A WS tunnel open, JUST before wiring up the frame pump — `target` is the `ws://`/`wss://`
    /// URL from the handshake. The impl (store) assigns a `conn_id` and publishes `StoreEvent::WsOpened`. Defaults
    /// to a no-op (id 0): sinks without WS support (e.g. in tests) still compile unchanged.
    fn on_ws_open(&self, _host: &str, _target: &str) -> u64 {
        0
    }

    /// A single parsed and unmasked WS frame — the pump calls this AFTER forwarding the bytes
    /// (the wire goes 1:1, the log is on a copy). Frame content is UNTRUSTED DATA.
    fn on_ws_frame(&self, _conn_id: u64, _frame: WsFrame) {}

    /// A WS tunnel close (a `close` frame, EOF, or a protocol error on either side).
    fn on_ws_close(&self, _conn_id: u64) {}

    /// Registers a handle for injecting frames into a LIVE WS tunnel — called by
    /// `pump_ws_frames` JUST before wiring up both pump directions, keyed by the same `conn_id` as
    /// `on_ws_frame`/`on_ws_close`. Defaults to a no-op: sinks without injection support (e.g. in
    /// tests) still compile unchanged.
    fn register_ws_injector(&self, _conn_id: u64, _injector: WsInjector) {}

    /// Removes the injection handle after the tunnel closes (alongside `on_ws_close`) — an injection into
    /// a dead tunnel should get a clear "no tunnel" error, not a silent write into a dead map.
    fn unregister_ws_injector(&self, _conn_id: u64) {}
}

/// The intercept point: the proxy CONSULTS every request just before sending it to the target. The
/// The implementation keeps a "hold" queue and waits for the operator/agent's decision. When intercept is off,
/// the impl returns `Some(req)` immediately (passthrough — zero overhead). The dependency direction is like
/// [`ExchangeSink`]: this crate defines the interface, the host implements it.
#[async_trait::async_trait]
pub trait Interceptor: Send + Sync {
    /// `Some(req)` = send (the request may have been edited); `None` = DROP (do not send).
    async fn hold_request(&self, host: &str, req: HttpRequest) -> Option<HttpRequest>;

    /// Consults the RESPONSE just before returning it to the client. `req` is context (the request
    /// that went out), read-only. `Some(resp)` = return (possibly edited); `None` = DROP (client → 502).
    /// When response intercept is off, the impl returns `Some(resp)` immediately (passthrough).
    async fn hold_response(
        &self,
        host: &str,
        req: &HttpRequest,
        resp: HttpResponse,
    ) -> Option<HttpResponse>;

    /// A cheap, SYNCHRONOUS gate: the WS pump asks this BEFORE parsing a frame on the hot
    /// path, so that with intercept off it stays on exactly the same zero-overhead
    /// path as passthrough (bytes forward verbatim, no parse-for-edit). OFF by default.
    fn ws_intercept_enabled(&self) -> bool {
        false
    }

    /// Holds a single WS frame for the operator/agent's decision — like `hold_request`,
    /// but for a WS tunnel instead of an HTTP request. `Some(edited)` = send (possibly edited —
    /// the pump RE-ENCODES it, since the payload length may have changed); `None` = DROP (nothing goes
    /// on in this direction for this frame). Defaults to passthrough (WS intercept off).
    async fn hold_ws_frame(&self, _conn_id: u64, _dir: WsDir, frame: WsFrame) -> Option<WsFrame> {
        Some(frame)
    }
}

/// Passthrough — holds nothing (the default when intercept is not wired up, e.g. in tests).
pub struct NoIntercept;

#[async_trait::async_trait]
impl Interceptor for NoIntercept {
    async fn hold_request(&self, _host: &str, req: HttpRequest) -> Option<HttpRequest> {
        Some(req)
    }
    async fn hold_response(
        &self,
        _host: &str,
        _req: &HttpRequest,
        resp: HttpResponse,
    ) -> Option<HttpResponse> {
        Some(resp)
    }
    // `ws_intercept_enabled`/`hold_ws_frame`: the trait's default impl (passthrough, OFF) —
    // fits NoIntercept unchanged.
}

/// The target scheme — decides whether upstream goes over TLS.
#[derive(Clone, Copy)]
enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

/// Shared connection-handling context.
struct ProxyCtx {
    sink: Arc<dyn ExchangeSink>,
    tls: Arc<TlsContext>,
    mr: MatchReplace,
    intercept: Arc<dyn Interceptor>,
}

/// The proxy listening socket. `bind` enforces loopback; `serve` takes over the accept loop.
pub struct ProxyListener {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl ProxyListener {
    /// The actual listen address (useful with port 0 — the OS assigns the number).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The accept loop: each client connection is handled in its own task. `tls` carries
    /// the root CA (for leaf certs) and the connector to targets.
    pub async fn serve(
        self,
        sink: Arc<dyn ExchangeSink>,
        tls: Arc<TlsContext>,
        mr: MatchReplace,
        intercept: Arc<dyn Interceptor>,
    ) -> Result<(), ProxyError> {
        let ctx = Arc::new(ProxyCtx {
            sink,
            tls,
            mr,
            intercept,
        });
        loop {
            let (stream, _peer) = self.listener.accept().await.map_err(ProxyError::Accept)?;
            let io = TokioIo::new(stream);
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let ctx = ctx.clone();
                    async move { handle_outer(req, ctx).await }
                });
                // .with_upgrades() is REQUIRED so CONNECT can take over the raw TCP.
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
                {
                    tracing::debug!(error = %e, "client connection error");
                }
            });
        }
    }
}

/// Binds the proxy. Refuses a non-loopback address — an open intercepting
/// proxy would be an open relay.
pub async fn bind(addr: SocketAddr) -> Result<ProxyListener, ProxyError> {
    if !addr.ip().is_loopback() {
        return Err(ProxyError::NonLoopbackBind(addr.ip()));
    }
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| ProxyError::Bind { addr, source })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| ProxyError::Bind { addr, source })?;
    Ok(ProxyListener {
        listener,
        local_addr,
    })
}

/// Handles a request on the outer (plain) connection: CONNECT → MITM tunnel, the rest → HTTP relay.
async fn handle_outer(
    req: Request<Incoming>,
    ctx: Arc<ProxyCtx>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() == Method::CONNECT {
        return Ok(handle_connect(req, ctx));
    }
    match relay_plain(req, &ctx).await {
        Ok(resp) => Ok(resp),
        Err(ProxyError::BadRequest(msg)) => Ok(simple_response(StatusCode::BAD_REQUEST, &msg)),
        Err(err) => {
            tracing::warn!(error = %err, "proxy error while hitting the target (plain)");
            Ok(simple_response(StatusCode::BAD_GATEWAY, &err.to_string()))
        }
    }
}

/// CONNECT: we answer 200 and take over the connection into the MITM tunnel in the background.
fn handle_connect(req: Request<Incoming>, ctx: Arc<ProxyCtx>) -> Response<Full<Bytes>> {
    let Some(authority) = req.uri().authority().cloned() else {
        return simple_response(StatusCode::BAD_REQUEST, "CONNECT bez authority");
    };
    let host = authority.host().to_owned();
    let port = authority.port_u16().unwrap_or(443);

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                if let Err(e) = mitm_tunnel(io, host, port, ctx).await {
                    tracing::debug!(error = %e, "MITM tunnel ended with an error");
                }
            }
            Err(e) => tracing::debug!(error = %e, "CONNECT upgrade failed"),
        }
    });

    // 200 => the client starts the TLS handshake in the tunnel.
    Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// After taking over the tunnel: TLS with the client (leaf cert), then we serve HTTP and relay to the target.
/// `client_io` is a tokio stream (`TokioIo<Upgraded>` implements `AsyncRead/Write`).
async fn mitm_tunnel<I>(
    client_io: I,
    host: String,
    port: u16,
    ctx: Arc<ProxyCtx>,
) -> Result<(), ProxyError>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let leaf_config = ctx.tls.leaf_config(&host)?;
    let acceptor = TlsAcceptor::from(leaf_config);
    let tls_stream = acceptor
        .accept(client_io)
        .await
        .map_err(ProxyError::TlsClient)?;
    let io = TokioIo::new(tls_stream);

    let host = Arc::new(host);
    let service = service_fn(move |req| {
        let ctx = ctx.clone();
        let host = host.clone();
        async move { handle_inner(req, host, port, ctx).await }
    });
    // `.with_upgrades()` is REQUIRED here too: WSS is an upgrade inside the MITM tunnel.
    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await?;
    Ok(())
}

/// A request inside the MITM tunnel — the target is fixed from CONNECT, scheme https.
async fn handle_inner(
    req: Request<Incoming>,
    host: Arc<String>,
    port: u16,
    ctx: Arc<ProxyCtx>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // WebSocket inside the MITM tunnel = WSS: a separate path instead of the buffered relay.
    let result = if is_websocket_upgrade(req.headers()) {
        relay_websocket(req, &host, port, Scheme::Https, &ctx).await
    } else {
        let (parts, body) = req.into_parts();
        relay_core(parts, body, &host, port, Scheme::Https, &ctx).await
    };
    match result {
        Ok(resp) => Ok(resp),
        Err(ProxyError::BadRequest(msg)) => Ok(simple_response(StatusCode::BAD_REQUEST, &msg)),
        Err(err) => {
            tracing::warn!(error = %err, "proxy error while hitting the target (mitm)");
            Ok(simple_response(StatusCode::BAD_GATEWAY, &err.to_string()))
        }
    }
}

/// Plain HTTP: we derive the target from the request (absolute-form or Host).
async fn relay_plain(
    req: Request<Incoming>,
    ctx: &ProxyCtx,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    let (host, port) = target_authority(req.uri(), req.headers())?;
    // WebSocket: a separate path — we do NOT buffer the body, we tunnel after the handshake.
    if is_websocket_upgrade(req.headers()) {
        return relay_websocket(req, &host, port, Scheme::Http, ctx).await;
    }
    let (parts, body) = req.into_parts();
    relay_core(parts, body, &host, port, Scheme::Http, ctx).await
}

/// Upper cap on body bytes buffered in RAM on the relay path (request/response). A hostile target —
/// or simply a huge transfer — must not be able to grow memory without bound. 100 MiB by default;
/// `WEIR_MAX_RELAY_BYTES` overrides it (0 = no limit). A body over the limit → `BodyTooLarge` → 502.
fn max_relay_bytes() -> usize {
    static CAP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CAP.get_or_init(|| {
        std::env::var("WEIR_MAX_RELAY_BYTES")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(100 * 1024 * 1024)
    })
}

/// Collects a body into bytes with a hard limit: accumulates DATA frames and aborts with
/// `BodyTooLarge` once the total exceeds the cap. `max = 0` → no limit (as before).
async fn collect_capped(mut body: Incoming) -> Result<Bytes, ProxyError> {
    let max = max_relay_bytes();
    if max == 0 {
        return Ok(body.collect().await.map_err(ProxyError::Body)?.to_bytes());
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(ProxyError::Body)?;
        if let Ok(data) = frame.into_data() {
            if buf.len() + data.len() > max {
                return Err(ProxyError::BodyTooLarge(max));
            }
            buf.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(buf))
}

/// The relay core: buffers the request, sends it to the target (TCP or TLS), captures the pair and returns
/// the response to the client. Shared by the plain and MITM paths.
async fn relay_core(
    parts: hyper::http::request::Parts,
    body: Incoming,
    host: &str,
    port: u16,
    scheme: Scheme,
    ctx: &ProxyCtx,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());

    let req_body = collect_capped(body).await?;

    // Build the request, then apply match & replace. The modified version
    // goes both to the target and to history — consistent with what actually went out.
    // Keep the port in the target when non-standard (e.g. CTF targets on :8080/:21002) —
    // otherwise replay/race/fuzz would connect on 80/443. We omit the standard port
    // for clean URLs.
    let default_port = match scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    };
    let authority = if port == default_port {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    let mut request = HttpRequest {
        method: parts.method.as_str().to_owned(),
        target: format!("{}://{}{}", scheme.as_str(), authority, path_and_query),
        version: version_str(parts.version),
        headers: capture_headers(&parts.headers),
        body: req_body.to_vec(),
        raw: false,
    };
    ctx.mr.apply_request(&mut request);

    // The intercept point: just before sending we consult the request. The operator/agent may
    // EDIT it (returning `Some(edited)`) or REJECT it (`None` → we don't send, don't log). When
    // intercept is off, the impl returns `Some(req)` immediately (passthrough).
    let request = match ctx.intercept.hold_request(host, request).await {
        Some(edited) => edited,
        None => return Ok(dropped_response()),
    };

    // The outgoing request (possibly modified). The connection goes to the ORIGINAL
    // host/port — match/replace does not redirect (as in Burp). Absolute URI: hyper h1
    // sends origin-form (+ Host) anyway, and h2 needs the authority on `:authority`.
    let mut out = Request::builder()
        .method(request.method.as_str())
        .uri(request.target.as_str());
    for h in &request.headers {
        if is_hop_by_hop(&h.name.to_ascii_lowercase())
            || h.name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        out = out.header(&h.name, &h.value);
    }
    let out_req = out.body(Full::new(Bytes::from(request.body.clone())))?;

    let upstream = send_upstream(host, port, scheme, out_req, ctx).await?;
    let (rparts, rbody) = upstream.into_parts();
    let resp_body = collect_capped(rbody).await?;

    let mut response = HttpResponse {
        status: rparts.status.as_u16(),
        version: version_str(rparts.version),
        headers: capture_headers(&rparts.headers),
        body: resp_body.to_vec(),
    };
    ctx.mr.apply_response(&mut response);

    // The response intercept point: just before returning to the client. The operator/agent may
    // EDIT it (`Some(edited)`) or REJECT it (`None` → the client gets 502). Passthrough when off.
    let response = match ctx.intercept.hold_response(host, &request, response).await {
        Some(edited) => edited,
        None => return Ok(dropped_response()),
    };

    // The captured exchange (without an ID). We do NOT log bodies.
    ctx.sink.record(CapturedExchange {
        host: host.to_owned(),
        request,
        response: Some(response.clone()),
    });

    // The response to the client (possibly modified).
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut cb = Response::builder().status(status);
    for h in &response.headers {
        if is_hop_by_hop(&h.name.to_ascii_lowercase())
            || h.name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        cb = cb.header(&h.name, &h.value);
    }
    Ok(cb.body(Full::new(Bytes::from(response.body)))?)
}

/// The response returned to the client when a request was REJECTED at intercept. The request did
/// not go to the target and was not logged. A visible signal instead of a hanging connection.
fn dropped_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(
            b"weir: request dropped by operator (intercept)",
        )))
        .expect("static dropped response")
}

/// Whether the request is a WebSocket handshake (RFC 6455): `Upgrade: websocket` + an `upgrade` token in
/// `Connection` (case-insensitive; `Connection` is sometimes a list, e.g. `keep-alive, Upgrade`). A pure
/// predicate — no I/O, directly testable.
fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let upgrade_is_ws = headers
        .get_all(hyper::header::UPGRADE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("websocket"));
    let conn_has_upgrade = headers
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    upgrade_is_ws && conn_has_upgrade
}

/// WebSocket: relays the handshake to the target, then after `101 Switching Protocols` takes over
/// BOTH sides (`hyper::upgrade::on`) and pumps FRAMES bidirectionally (`pump_ws_frames` — a parser
/// for RFC 6455 in place of a bare `copy_bidirectional`; with optional frame intercept/edit
/// via `ctx.intercept`). Unlike `relay_core` it does NOT buffer the body — WS is a
/// long-lived frame stream. We deliberately PASS THROUGH the WS headers (`upgrade`, `connection`,
/// `sec-websocket-*`) (otherwise the target won't accept the upgrade). The handshake lands in history as GET/101;
/// the frames themselves go to the live feed via `ExchangeSink::on_ws_frame` (no durable persistence).
async fn relay_websocket(
    mut req: Request<Incoming>,
    host: &str,
    port: u16,
    scheme: Scheme,
    ctx: &ProxyCtx,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    // OnUpgrade on the client side — we take it BEFORE sending 101 (it resolves later, once hyper
    // writes our 101 response to the client).
    let client_upgrade = hyper::upgrade::on(&mut req);

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let client_headers = capture_headers(req.headers());

    // Handshake to the target: origin-form, headers 1:1 except content-length (no body). We do NOT strip
    // hop-by-hop — `upgrade`/`connection`/`sec-websocket-*` carry the upgrade semantics.
    let mut hb = Request::builder()
        .method(Method::GET)
        .uri(path_and_query.as_str());
    for h in &client_headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        hb = hb.header(&h.name, &h.value);
    }
    let handshake = hb.body(Empty::<Bytes>::new())?;

    // Connection to the target (direct or via an upstream proxy). We negotiate WS over h1 — the connector
    // ALPN `http/1.1` (not h2; WS-over-h2/RFC 8441 out of scope).
    let tcp = ctx.tls.dial(host, port).await?;
    let mut resp = match scheme {
        Scheme::Http => ws_handshake_over(TokioIo::new(tcp), handshake).await?,
        Scheme::Https => {
            let sni = server_name(host)?;
            let stream = ctx
                .tls
                .connector()
                .connect(sni, tcp)
                .await
                .map_err(ProxyError::TlsUpstream)?;
            ws_handshake_over(TokioIo::new(stream), handshake).await?
        }
    };

    let ws_scheme = match scheme {
        Scheme::Http => "ws",
        Scheme::Https => "wss",
    };
    let default_port = match scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    };
    let authority = if port == default_port {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    // Kept separate from `req_model.target` — `req_model` travels to `ctx.sink.record()` (below,
    // in BOTH branches), while `ws_target` is still needed AFTER this point for `on_ws_open`.
    let ws_target = format!("{ws_scheme}://{authority}{path_and_query}");
    let req_model = HttpRequest {
        method: "GET".to_owned(),
        target: ws_target.clone(),
        version: "HTTP/1.1".to_owned(),
        headers: client_headers,
        body: Vec::new(),
        raw: false,
    };

    // The target did not accept the upgrade (e.g. 400/426) — forward the response to the client buffered, like
    // a normal relay, and log the exchange.
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        let status = resp.status();
        let headers = capture_headers(resp.headers());
        let version = version_str(resp.version());
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(ProxyError::Body)?
            .to_bytes();
        let response = HttpResponse {
            status: status.as_u16(),
            version,
            headers,
            body: body.to_vec(),
        };
        ctx.sink.record(CapturedExchange {
            host: host.to_owned(),
            request: req_model,
            response: Some(response.clone()),
        });
        let mut cb = Response::builder().status(status);
        for h in &response.headers {
            if is_hop_by_hop(&h.name.to_ascii_lowercase())
                || h.name.eq_ignore_ascii_case("content-length")
            {
                continue;
            }
            cb = cb.header(&h.name, &h.value);
        }
        return Ok(cb.body(Full::new(Bytes::from(response.body)))?);
    }

    // OnUpgrade on the target side (101 already received; conn.with_upgrades hands back the IO).
    let target_upgrade = hyper::upgrade::on(&mut resp);

    // The 101 response to the client from the target headers (Sec-WebSocket-Accept etc.). Handshake to history.
    let resp_headers = capture_headers(resp.headers());
    ctx.sink.record(CapturedExchange {
        host: host.to_owned(),
        request: req_model,
        response: Some(HttpResponse {
            status: 101,
            version: "HTTP/1.1".to_owned(),
            headers: resp_headers.clone(),
            body: Vec::new(),
        }),
    });
    let mut cb = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for h in &resp_headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        cb = cb.header(&h.name, &h.value);
    }
    let client_resp = cb.body(Full::new(Bytes::new()))?;

    // Handshake complete — from now it's a frame tunnel, not a request/response. `conn_id`
    // ties all frames of this connection together in the live-feed event (`StoreEvent::WsFrame`).
    let conn_id = ctx.sink.on_ws_open(host, &ws_target);

    // Pump: once both sides finish the upgrade, we tunnel FRAMES (not raw bytes) until one side
    // closes — see `pump_ws_frames` (an RFC 6455 parser instead of `copy_bidirectional`).
    let host_owned = host.to_owned();
    let sink = ctx.sink.clone();
    let intercept = ctx.intercept.clone();
    tokio::spawn(async move {
        match tokio::try_join!(client_upgrade, target_upgrade) {
            Ok((client_up, target_up)) => {
                let c = TokioIo::new(client_up);
                let t = TokioIo::new(target_up);
                pump_ws_frames(c, t, conn_id, sink, intercept, host_owned).await;
            }
            Err(e) => {
                tracing::debug!(host = %host_owned, error = %e, "WS upgrade failed");
                sink.on_ws_close(conn_id);
            }
        }
    });

    Ok(client_resp)
}

/// WS handshake to the target over one h1 connection. `conn.with_upgrades()` is REQUIRED so that after `101`
/// hyper hands the raw IO to `hyper::upgrade::on(resp)`. Returns the target's response (with a live OnUpgrade).
async fn ws_handshake_over<I>(
    io: I,
    req: Request<Empty<Bytes>>,
) -> Result<Response<Incoming>, ProxyError>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!(error = %e, "WS connection to the target closed with an error");
        }
    });
    let resp = sender.send_request(req).await?;
    Ok(resp)
}

/// Opens a connection to the target (TCP or TCP+TLS), sends the request and returns the response.
async fn send_upstream(
    host: &str,
    port: u16,
    scheme: Scheme,
    out_req: Request<Full<Bytes>>,
    ctx: &ProxyCtx,
) -> Result<Response<Incoming>, ProxyError> {
    // Connection to the target — direct or via an upstream proxy (`TlsContext::dial`).
    let tcp = ctx.tls.dial(host, port).await?;

    match scheme {
        Scheme::Http => send_over(TokioIo::new(tcp), out_req).await,
        Scheme::Https => {
            let sni = server_name(host)?;
            // h2_connector negotiates ALPN h2 (falling back to h1). After the handshake we pick the protocol by
            // the actually negotiated ALPN — h2-to-target, otherwise HTTP/1.1 as before.
            let stream = ctx
                .tls
                .h2_connector()
                .connect(sni, tcp)
                .await
                .map_err(ProxyError::TlsUpstream)?;
            let is_h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
            tracing::debug!(%host, alpn = if is_h2 { "h2" } else { "http/1.1" }, "upstream negocjacja");
            if is_h2 {
                // Some servers advertise h2 via ALPN but then reject actual h2 — e.g. GOAWAY with
                // HTTP_1_1_REQUIRED — expecting the client to fall back to HTTP/1.1 (browsers do).
                // Keep a copy of the request; if the h2 attempt fails BEFORE a response (so the
                // request was never processed → safe to replay), redial with the http/1.1 connector
                // and retry over h1.
                let retry = out_req.clone();
                match send_over_h2(TokioIo::new(stream), out_req).await {
                    Ok(resp) => Ok(resp),
                    Err(e) => {
                        tracing::debug!(%host, error = %e, "upstream h2 failed — falling back to HTTP/1.1");
                        let tcp = ctx.tls.dial(host, port).await?;
                        let sni = server_name(host)?;
                        let stream = ctx
                            .tls
                            .connector()
                            .connect(sni, tcp)
                            .await
                            .map_err(ProxyError::TlsUpstream)?;
                        send_over(TokioIo::new(stream), retry).await
                    }
                }
            } else {
                send_over(TokioIo::new(stream), out_req).await
            }
        }
    }
}

pub(crate) async fn send_over<I>(
    io: I,
    out_req: Request<Full<Bytes>>,
) -> Result<Response<Incoming>, ProxyError>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "connection to the target closed with an error");
        }
    });
    let resp = sender.send_request(out_req).await?;
    Ok(resp)
}

/// Like [`send_over`], but over HTTP/2. The target negotiated ALPN `h2`; hyper builds the pseudo-headers
/// (`:method`/`:scheme`/`:authority`/`:path`) from the request's absolute URI. Body in `Full` (no streaming).
pub(crate) async fn send_over_h2<I>(
    io: I,
    mut out_req: Request<Full<Bytes>>,
) -> Result<Response<Incoming>, ProxyError>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    // In h2 the authority is carried by the `:authority` pseudo-header (hyper generates it from the absolute URI).
    // For an h1 client the `Host` header would then be redundant — and strict servers (e.g. Google) reset
    // such a stream with `PROTOCOL_ERROR`. When converting h1→h2 an intermediary does NOT forward `Host` (RFC 9113
    // §8.3.1: authority goes to `:authority`). The h1-to-target path leaves `Host` unchanged.
    out_req.headers_mut().remove(hyper::header::HOST);
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "h2 connection to the target closed with an error");
        }
    });
    let resp = sender.send_request(out_req).await?;
    Ok(resp)
}

/// Determines the target (host, port): absolute-form from the URI first (proxy mode), then falls back to Host.
fn target_authority(uri: &hyper::Uri, headers: &HeaderMap) -> Result<(String, u16), ProxyError> {
    if let Some(host) = uri.host() {
        let port = uri.port_u16().unwrap_or(80);
        return Ok((host.to_owned(), port));
    }
    if let Some(hv) = headers.get(hyper::header::HOST) {
        let raw = hv
            .to_str()
            .map_err(|_| ProxyError::BadRequest("Host header is not ASCII".to_owned()))?;
        let (h, p) = split_host_port(raw);
        return Ok((h.to_owned(), p));
    }
    Err(ProxyError::BadRequest(
        "no target: neither absolute-URI nor Host header".to_owned(),
    ))
}

fn split_host_port(s: &str) -> (&str, u16) {
    match s.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().unwrap_or(80)),
        None => (s, 80),
    }
}

/// Hop-by-hop headers (RFC 7230 §6.1) — we do not forward them.
pub(crate) fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-authenticate"
            | "proxy-authorization"
    )
}

/// A 1:1 header dump (with duplicates) for capture — no normalization.
pub(crate) fn capture_headers(headers: &HeaderMap) -> Vec<Header> {
    headers
        .iter()
        .map(|(name, value)| Header {
            name: name.as_str().to_owned(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect()
}

pub(crate) fn version_str(v: Version) -> String {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
    .to_owned()
}

fn simple_response(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(format!("weir: {msg}\n"))))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"weir: error\n"))))
}

#[cfg(test)]
mod tests {
    use super::is_websocket_upgrade;
    use hyper::header::{CONNECTION, UPGRADE};
    use hyper::HeaderMap;

    fn hm(pairs: &[(&hyper::header::HeaderName, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in pairs {
            h.append((*name).clone(), value.parse().unwrap());
        }
        h
    }

    #[test]
    fn detects_plain_websocket_handshake() {
        let h = hm(&[(&UPGRADE, "websocket"), (&CONNECTION, "Upgrade")]);
        assert!(is_websocket_upgrade(&h));
    }

    #[test]
    fn detects_case_insensitive() {
        let h = hm(&[(&UPGRADE, "WebSocket"), (&CONNECTION, "upgrade")]);
        assert!(is_websocket_upgrade(&h));
    }

    #[test]
    fn connection_may_be_a_token_list() {
        // Browsers send e.g. `Connection: keep-alive, Upgrade`.
        let h = hm(&[
            (&UPGRADE, "websocket"),
            (&CONNECTION, "keep-alive, Upgrade"),
        ]);
        assert!(is_websocket_upgrade(&h));
    }

    #[test]
    fn rejects_without_upgrade_header() {
        let h = hm(&[(&CONNECTION, "Upgrade")]);
        assert!(!is_websocket_upgrade(&h));
    }

    #[test]
    fn rejects_without_connection_upgrade() {
        let h = hm(&[(&UPGRADE, "websocket")]);
        assert!(!is_websocket_upgrade(&h));
    }

    #[test]
    fn rejects_non_websocket_upgrade() {
        // Another upgrade (e.g. h2c) is not a WebSocket.
        let h = hm(&[(&UPGRADE, "h2c"), (&CONNECTION, "Upgrade")]);
        assert!(!is_websocket_upgrade(&h));
    }

    #[test]
    fn plain_request_is_not_upgrade() {
        let h = hm(&[(&CONNECTION, "keep-alive")]);
        assert!(!is_websocket_upgrade(&h));
    }
}
