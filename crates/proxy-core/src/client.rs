//! Sending a single request to the target — the raw/replay send path. Two paths:
//! - "polite" (hyper): normalizes, convenient for plain replay.
//! - raw-send: writes the request bytes EXACTLY per the model (duplicate headers, odd casing,
//!   conflicting Content-Length/Transfer-Encoding) — for request smuggling and desync.
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::ca::{server_name, TlsContext};
use crate::proxy::{capture_headers, is_hop_by_hop, send_over, version_str};
use crate::ProxyError;
use http_model::{Header, HttpRequest, HttpResponse};

#[derive(Clone, Copy)]
enum Scheme {
    Http,
    Https,
}

struct Target {
    scheme: Scheme,
    host: String,
    port: u16,
    path: String,
}

fn parse_target(target: &str) -> Result<Target, ProxyError> {
    let uri = target
        .parse::<hyper::Uri>()
        .map_err(|_| ProxyError::BadRequest(format!("bad target: {target}")))?;
    let scheme = match uri.scheme_str() {
        Some("http") => Scheme::Http,
        Some("https") => Scheme::Https,
        _ => {
            return Err(ProxyError::BadRequest(format!(
                "target must be http(s): {target}"
            )))
        }
    };
    let host = uri
        .host()
        .ok_or_else(|| ProxyError::BadRequest(format!("target without a host: {target}")))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(match scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    });
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    Ok(Target {
        scheme,
        host,
        port,
        path,
    })
}

/// Target host from the URL — for a scope/allow-list check BEFORE sending (preflight).
pub fn target_host(target: &str) -> Result<String, ProxyError> {
    Ok(parse_target(target)?.host)
}

/// Sends `request` to the target named in `request.target`. `request.raw` selects the raw-send path.
/// The response body is buffered in full (no cap) — replay/fuzzer callers already bound their own
/// concurrency/targets; for an ALWAYS-ON autonomous caller (the monitor), use [`send_capped`]
/// instead so a huge/slow in-scope body can never be fully buffered before it's bounded.
pub async fn send(request: &HttpRequest, tls: &TlsContext) -> Result<HttpResponse, ProxyError> {
    let t = parse_target(&request.target)?;
    if request.raw {
        send_raw(request, &t, tls).await
    } else {
        send_polite(request, &t, tls, None).await
    }
}

/// Like [`send`], but for the "polite" (non-raw) path only, and bounds the RESPONSE BODY read to
/// `max_body` bytes: reading STOPS as soon as the cap is hit instead of collecting the whole body
/// first and truncating after — the fix for an OOM on a huge/slow in-scope body when this is
/// called unattended (the monitor scheduler, `MONITOR_MAX_SNAPSHOT_BYTES` per tick target). The
/// returned body may be shorter than `max_body` (a smaller response) or truncated to exactly it
/// (a larger one) — same "truncated snapshot" contract the monitor already applies post-hoc.
pub async fn send_capped(
    request: &HttpRequest,
    tls: &TlsContext,
    max_body: usize,
) -> Result<HttpResponse, ProxyError> {
    let t = parse_target(&request.target)?;
    send_polite(request, &t, tls, Some(max_body)).await
}

async fn send_polite(
    request: &HttpRequest,
    t: &Target,
    tls: &TlsContext,
    max_body: Option<usize>,
) -> Result<HttpResponse, ProxyError> {
    let mut builder = Request::builder()
        .method(request.method.as_str())
        .uri(t.path.as_str());
    for h in &request.headers {
        if is_hop_by_hop(&h.name.to_ascii_lowercase())
            || h.name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        builder = builder.header(&h.name, &h.value);
    }
    let out = builder.body(Full::new(Bytes::from(request.body.clone())))?;

    let tcp = tls.dial(&t.host, t.port).await?;
    let resp = match t.scheme {
        Scheme::Http => send_over(TokioIo::new(tcp), out).await?,
        Scheme::Https => {
            let sni = server_name(&t.host)?;
            let stream = tls
                .connector()
                .connect(sni, tcp)
                .await
                .map_err(ProxyError::TlsUpstream)?;
            send_over(TokioIo::new(stream), out).await?
        }
    };
    let (parts, body) = resp.into_parts();
    let bytes = collect_body_capped(body, max_body).await?;
    Ok(HttpResponse {
        status: parts.status.as_u16(),
        version: version_str(parts.version),
        headers: capture_headers(&parts.headers),
        body: bytes,
    })
}

/// Reads `body` to completion (`max_body = None`, the existing unbounded [`send`] behavior) or, when
/// capped, frame-by-frame — accumulating at most `max_body` bytes and then STOPPING (no further
/// `.frame()` polls), rather than collecting everything and truncating afterward. That is the whole
/// point of the cap: a hostile/huge upstream body must never be fully buffered in memory first.
async fn collect_body_capped(
    mut body: hyper::body::Incoming,
    max_body: Option<usize>,
) -> Result<Vec<u8>, ProxyError> {
    let Some(cap) = max_body else {
        return Ok(body
            .collect()
            .await
            .map_err(ProxyError::Body)?
            .to_bytes()
            .to_vec());
    };
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(ProxyError::Body)?;
        if let Some(data) = frame.data_ref() {
            out.extend_from_slice(data);
            if out.len() >= cap {
                out.truncate(cap);
                break;
            }
        }
    }
    Ok(out)
}

async fn send_raw(
    request: &HttpRequest,
    t: &Target,
    tls: &TlsContext,
) -> Result<HttpResponse, ProxyError> {
    let buf = build_raw_bytes(request, &t.path);
    let mut stream = connect_stream(t, tls).await?;
    let raw = raw_exchange(&mut *stream, &buf).await?;
    Ok(parse_raw_response(&raw))
}

/// Raw send (byte-for-byte) with timing and a configurable idle timeout.
/// For request-smuggling detection: a response delay (the back-end waits for the rest of the
/// request) = a desync signal. Returns (time_ms, response).
pub async fn send_raw_timed(
    request: &HttpRequest,
    tls: &TlsContext,
    idle: Duration,
) -> Result<(u64, HttpResponse), ProxyError> {
    let t = parse_target(&request.target)?;
    let buf = build_raw_bytes(request, &t.path);
    let mut stream = connect_stream(&t, tls).await?;
    let start = Instant::now();
    {
        let s: &mut dyn DuplexStream = &mut *stream;
        s.write_all(&buf).await.map_err(ProxyError::Io)?;
        s.flush().await.map_err(ProxyError::Io)?;
    }
    let raw = read_raw_response(&mut *stream, idle).await?;
    let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok((elapsed, parse_raw_response(&raw)))
}

/// Short window we wait, after the last request's own response, for EXTRA responses the server
/// pipelined onto the same connection — i.e. the responses a request-smuggling desync produces
/// (the smuggled request's reply). Usually they are already buffered from reading the primary
/// response, so this only elapses on a clean connection with nothing more to send.
const RAW_DRAIN_IDLE: Duration = Duration::from_millis(400);

/// Sends multiple raw requests on ONE keep-alive connection and returns every framed HTTP response
/// read back — this is what exploits request smuggling: request #1 poisons the connection (CL/TE
/// desync), and the SMUGGLED request's reply comes back as an extra pipelined response. Bytes go out
/// verbatim — the caller frames chunked bodies with CRLF. Connection host/port/scheme come
/// from the FIRST request; every request should target the same origin (it is one connection).
///
/// Responses are framed per RFC 7230 (Content-Length / chunked / no-body statuses), so each is
/// returned SEPARATELY instead of merged into one idle-terminated blob, and the read returns as soon
/// as a response is complete instead of always waiting out `idle`. The returned count may EXCEED the
/// request count: any surplus entries are the pipelined (smuggled) responses, in wire order.
pub async fn send_raw_sequence(
    requests: &[HttpRequest],
    tls: &TlsContext,
    idle: Duration,
) -> Result<Vec<HttpResponse>, ProxyError> {
    let Some(first) = requests.first() else {
        return Ok(Vec::new());
    };
    let t = parse_target(&first.target)?;
    let mut stream = connect_stream(&t, tls).await?;
    let mut reader = ResponseReader::new(&mut *stream);
    let mut out = Vec::with_capacity(requests.len());
    for req in requests {
        let path = parse_target(&req.target)?.path;
        let buf = build_raw_bytes(req, &path);
        reader.send(&buf).await?;
        match reader.next(idle).await? {
            Some(frame) => out.push(parse_raw_response(&frame)),
            // No response for this request (connection went away / server stayed silent). Surface an
            // empty status-0 exchange rather than dropping it, so counts still line up 1:1.
            None => out.push(parse_raw_response(&[])),
        }
    }
    // Drain any responses the server pipelined beyond the ones we already read — the smuggled
    // replies. Almost always already buffered, so this returns at once; the idle only elapses on a
    // quiet keep-alive connection with nothing left.
    while let Some(frame) = reader.next(RAW_DRAIN_IDLE).await? {
        out.push(parse_raw_response(&frame));
    }
    Ok(out)
}

/// Byte-for-byte serialization of the request — with no normalization:
/// duplicate headers, odd casing, conflicting CL/TE pass through as-is.
fn build_raw_bytes(request: &HttpRequest, path: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(request.method.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(path.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(request.version.as_bytes());
    buf.extend_from_slice(b"\r\n");
    for h in &request.headers {
        buf.extend_from_slice(h.name.as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(h.value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(&request.body);
    buf
}

/// Any bidirectional stream (TCP or TLS), boxable to a single type.
trait DuplexStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> DuplexStream for T {}
type BoxStream = Box<dyn DuplexStream>;

/// Opens a connection to the target (TCP + optionally TLS) and returns a unified stream.
async fn connect_stream(t: &Target, tls: &TlsContext) -> Result<BoxStream, ProxyError> {
    let tcp = tls.dial(&t.host, t.port).await?;
    tcp.set_nodelay(true).ok();
    match t.scheme {
        Scheme::Http => Ok(Box::new(tcp)),
        Scheme::Https => {
            let sni = server_name(&t.host)?;
            let stream = tls
                .connector()
                .connect(sni, tcp)
                .await
                .map_err(ProxyError::TlsUpstream)?;
            Ok(Box::new(stream))
        }
    }
}

/// A "primed" connection for the last-byte-sync race (E1): the connection is
/// open and EVERYTHING but the withheld tail `withheld` has already been sent. The server
/// waits for the request to finish — only [`PrimedConn::send_last`] releases it.
pub struct PrimedConn {
    stream: BoxStream,
    withheld: Vec<u8>,
}

/// Connects to the target and sends the whole request EXCEPT the last `withhold` bytes
/// (min 1), leaving the server waiting. For a synchronized release of
/// many connections "at once" (reducing network jitter in a race).
pub async fn connect_and_prime(
    request: &HttpRequest,
    tls: &TlsContext,
    withhold: usize,
) -> Result<PrimedConn, ProxyError> {
    let t = parse_target(&request.target)?;
    let buf = build_raw_bytes(request, &t.path);
    let withhold = withhold.clamp(1, buf.len().max(1));
    let split = buf.len().saturating_sub(withhold);
    let (prime, withheld) = buf.split_at(split);

    let mut stream = connect_stream(&t, tls).await?;
    {
        let s: &mut dyn DuplexStream = &mut *stream;
        s.write_all(prime).await.map_err(ProxyError::Io)?;
        s.flush().await.map_err(ProxyError::Io)?;
    }
    Ok(PrimedConn {
        stream,
        withheld: withheld.to_vec(),
    })
}

impl PrimedConn {
    /// Sends the withheld tail — the "shot" (should be called on all
    /// connections in a tight loop so they go out close in time).
    pub async fn send_last(&mut self) -> Result<(), ProxyError> {
        let s: &mut dyn DuplexStream = &mut *self.stream;
        s.write_all(&self.withheld).await.map_err(ProxyError::Io)?;
        s.flush().await.map_err(ProxyError::Io)
    }

    /// Reads the response (best-effort, until EOF/idle ~3s) and parses it.
    pub async fn read_response(mut self) -> Result<HttpResponse, ProxyError> {
        let raw = read_raw_response(&mut *self.stream, Duration::from_secs(3)).await?;
        Ok(parse_raw_response(&raw))
    }
}

/// Sends raw bytes and reads the response best-effort (until EOF or ~3s idle).
async fn raw_exchange<S>(stream: &mut S, request: &[u8]) -> Result<Vec<u8>, ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    stream.write_all(request).await.map_err(ProxyError::Io)?;
    stream.flush().await.map_err(ProxyError::Io)?;
    read_raw_response(stream, Duration::from_secs(3)).await
}

/// Reads the response best-effort: until EOF or `idle` inactivity (cap 8 MiB).
async fn read_raw_response<S>(stream: &mut S, idle: Duration) -> Result<Vec<u8>, ProxyError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    const MAX: usize = 8 * 1024 * 1024;
    loop {
        match timeout(idle, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                out.extend_from_slice(&chunk[..n]);
                if out.len() >= MAX {
                    break;
                }
            }
            Ok(Err(e)) => return Err(ProxyError::Io(e)),
            Err(_) => break, // idle — assume end of the response
        }
    }
    Ok(out)
}

/// Cap on bytes buffered while framing a single raw response (matches `read_raw_response`).
const RAW_MAX: usize = 8 * 1024 * 1024;

/// Reads HTTP/1.1 responses off a raw stream one COMPLETE response at a time, keeping any bytes
/// already read past a response boundary buffered for the next call. Framing follows RFC 7230:
/// `Transfer-Encoding: chunked` wins over `Content-Length`; 1xx/204/304 carry no body; with neither
/// CL nor TE the response is delimited by connection close (read to EOF/idle). This lets the raw-send
/// path surface each pipelined response separately — the extra responses a request-smuggling desync
/// produces come back as their own entries instead of being merged into one blob or lost.
struct ResponseReader<'s, S: ?Sized> {
    stream: &'s mut S,
    buf: Vec<u8>,
    eof: bool,
}

impl<'s, S: AsyncRead + Unpin + ?Sized> ResponseReader<'s, S> {
    fn new(stream: &'s mut S) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            eof: false,
        }
    }

    /// Reads more bytes into `buf`, waiting at most `idle`. Returns `false` on EOF, on an idle
    /// timeout with nothing new, or once the buffer hits `RAW_MAX` (treat as end-of-response).
    async fn fill(&mut self, idle: Duration) -> Result<bool, ProxyError> {
        if self.eof || self.buf.len() >= RAW_MAX {
            return Ok(false);
        }
        let mut chunk = [0u8; 8192];
        match timeout(idle, self.stream.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                self.eof = true;
                Ok(false)
            }
            Ok(Ok(n)) => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(true)
            }
            Ok(Err(e)) => Err(ProxyError::Io(e)),
            Err(_) => Ok(false), // idle
        }
    }

    /// Reads exactly one framed response. `idle` bounds waiting for the first bytes and each read.
    /// Returns `None` when the connection is idle/closed with no (further) response buffered. A
    /// response whose body is under-delivered before EOF is returned best-effort (as much as arrived).
    async fn next(&mut self, idle: Duration) -> Result<Option<Vec<u8>>, ProxyError> {
        // 1. Read until the header terminator is present.
        let header_end = loop {
            if let Some(p) = find_subslice(&self.buf, b"\r\n\r\n") {
                break p + 4;
            }
            if !self.fill(idle).await? {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                // Bytes but no complete head (truncated) — hand back what we have.
                return Ok(Some(std::mem::take(&mut self.buf)));
            }
        };

        // 2. Determine the body length from the head.
        let (status, chunked, content_len) = scan_head(&self.buf[..header_end]);
        let body_start = header_end;
        let total = if (100..200).contains(&status) || status == 204 || status == 304 {
            header_end // no message body for these statuses
        } else if chunked {
            loop {
                if let Some(end) = chunked_body_end(&self.buf, body_start) {
                    break end;
                }
                if !self.fill(idle).await? {
                    break self.buf.len(); // truncated chunked body — best-effort
                }
            }
        } else if let Some(n) = content_len {
            let need = body_start.saturating_add(n);
            loop {
                if self.buf.len() >= need {
                    break need;
                }
                if !self.fill(idle).await? {
                    break self.buf.len(); // short body — best-effort
                }
            }
        } else {
            // No CL and no TE: the response runs to connection close. It can't be followed by a
            // pipelined response, so consume everything left.
            while self.fill(idle).await? {}
            self.buf.len()
        };

        let frame = self.buf.drain(..total.min(self.buf.len())).collect();
        Ok(Some(frame))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + ?Sized> ResponseReader<'_, S> {
    /// Writes (and flushes) request bytes on the same connection between reads.
    async fn send(&mut self, bytes: &[u8]) -> Result<(), ProxyError> {
        self.stream.write_all(bytes).await.map_err(ProxyError::Io)?;
        self.stream.flush().await.map_err(ProxyError::Io)
    }
}

/// Extracts (status, is-chunked, content-length) from a response head (bytes up to and including the
/// blank line). `Transfer-Encoding: chunked` is reported independently; the caller lets it win over CL.
fn scan_head(head: &[u8]) -> (u16, bool, Option<usize>) {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let mut chunked = false;
    let mut content_len = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if name == "transfer-encoding" {
            if value.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        } else if name == "content-length" {
            content_len = value.trim().parse::<usize>().ok();
        }
    }
    (status, chunked, content_len)
}

/// Given a buffer and the offset where a chunked body starts, returns the index just past the
/// terminating `0\r\n\r\n` when the whole chunked body is present, or `None` if more bytes are needed.
fn chunked_body_end(buf: &[u8], mut i: usize) -> Option<usize> {
    loop {
        // Chunk-size line: `<hex>[;ext]\r\n`.
        let line_end = find_subslice(buf.get(i..)?, b"\r\n")? + i;
        let hex = buf[i..line_end].split(|&b| b == b';').next().unwrap_or(&[]);
        let size = usize::from_str_radix(std::str::from_utf8(hex).ok()?.trim(), 16).ok()?;
        if size == 0 {
            // Last chunk: optional trailers then a blank line. The terminator is the `\r\n` after the
            // `0` plus the final `\r\n` — i.e. a `\r\n\r\n` starting at `line_end`.
            return Some(find_subslice(buf.get(line_end..)?, b"\r\n\r\n")? + line_end + 4);
        }
        // Data + its trailing CRLF.
        i = line_end + 2 + size + 2;
        if i > buf.len() {
            return None;
        }
    }
}

/// Best-effort parsing of the raw response. On failure returns status 0 and the whole thing as the body
/// (still useful for raw tests — we don't want to "fix" odd responses here).
fn parse_raw_response(raw: &[u8]) -> HttpResponse {
    let Some(split) = find_subslice(raw, b"\r\n\r\n") else {
        return HttpResponse {
            status: 0,
            version: String::new(),
            headers: Vec::new(),
            body: raw.to_vec(),
        };
    };
    let head = &raw[..split];
    let body = raw[split + 4..].to_vec();

    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default().to_owned();
    let status = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let headers = lines
        .filter_map(|line| {
            line.split_once(':').map(|(n, v)| Header {
                name: n.trim().to_owned(),
                value: v.trim().to_owned(),
            })
        })
        .collect();

    HttpResponse {
        status,
        version,
        headers,
        body,
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds `bytes` through a duplex pipe (closed after writing → EOF) and collects every framed
    /// response the reader yields, exactly as `send_raw_sequence` would off a real connection.
    async fn frames(bytes: &[u8]) -> Vec<Vec<u8>> {
        let (mut write_half, mut read_half) = tokio::io::duplex(1 << 20);
        let data = bytes.to_vec();
        let writer = tokio::spawn(async move {
            write_half.write_all(&data).await.unwrap();
            // dropping `write_half` here signals EOF to the reader
        });
        let mut reader = ResponseReader::new(&mut read_half);
        let mut out = Vec::new();
        while let Some(f) = reader.next(Duration::from_millis(300)).await.unwrap() {
            out.push(f);
        }
        writer.await.unwrap();
        out
    }

    #[tokio::test]
    async fn frames_a_single_content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let got = frames(raw).await;
        assert_eq!(got.len(), 1, "one CL-delimited response");
        assert_eq!(got[0], raw, "frame is the whole response, byte-for-byte");
    }

    #[tokio::test]
    async fn splits_two_pipelined_content_length_responses() {
        // The smuggling shape: two responses back-to-back on one connection must come out as two
        // frames, NOT one merged blob — the second is the "smuggled" reply.
        let r1 = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let r2 = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\nsecret";
        let mut wire = r1.to_vec();
        wire.extend_from_slice(r2);
        let got = frames(&wire).await;
        assert_eq!(got.len(), 2, "two separate framed responses");
        assert_eq!(got[0], r1);
        assert_eq!(got[1], r2);
        assert_eq!(parse_raw_response(&got[1]).status, 403);
        assert_eq!(parse_raw_response(&got[1]).body, b"secret");
    }

    #[tokio::test]
    async fn frames_chunked_then_a_pipelined_response() {
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let r2 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let mut wire = chunked.to_vec();
        wire.extend_from_slice(r2);
        let got = frames(&wire).await;
        assert_eq!(
            got.len(),
            2,
            "chunked response framed, pipelined one split off"
        );
        assert_eq!(
            got[0], chunked,
            "chunked frame ends exactly at 0\\r\\n\\r\\n"
        );
        assert_eq!(got[1], r2);
    }

    #[tokio::test]
    async fn chunked_wins_over_a_bogus_content_length() {
        // Conflicting CL + TE (the desync primitive itself): TE:chunked must decide framing.
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let got = frames(raw).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], raw);
    }

    #[tokio::test]
    async fn no_body_status_carries_no_body() {
        // 204/304 have no message body even without Content-Length — the next bytes are a new response.
        let r1 = b"HTTP/1.1 204 No Content\r\n\r\n";
        let r2 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut wire = r1.to_vec();
        wire.extend_from_slice(r2);
        let got = frames(&wire).await;
        assert_eq!(
            got.len(),
            2,
            "204 body-less, so the following bytes frame separately"
        );
        assert_eq!(got[0], r1);
        assert_eq!(got[1], r2);
    }

    #[tokio::test]
    async fn close_delimited_response_reads_to_eof() {
        // No CL, no TE → the body runs until connection close. Nothing can be pipelined after it.
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody until the socket closes";
        let got = frames(raw).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], raw);
    }

    #[tokio::test]
    async fn truncated_body_returned_best_effort() {
        // Server promises 100 bytes then hangs up after 5 — hand back what arrived, don't hang or error.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort";
        let got = frames(raw).await;
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0], raw,
            "best-effort: as much of the body as was delivered"
        );
    }

    #[tokio::test]
    async fn empty_stream_yields_no_frames() {
        assert!(frames(b"").await.is_empty());
    }

    /// Origin that always answers with a body far bigger than any cap under test, then closes.
    async fn spawn_big_body_origin(body_len: usize) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind origin");
        let addr = listener.local_addr().expect("origin addr");
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 1024];
                    loop {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let body = "x".repeat(body_len);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    fn get_request(addr: std::net::SocketAddr) -> HttpRequest {
        HttpRequest {
            method: "GET".to_owned(),
            target: format!("http://{addr}/big"),
            version: "HTTP/1.1".to_owned(),
            headers: vec![Header {
                name: "Host".to_owned(),
                value: addr.to_string(),
            }],
            body: Vec::new(),
            raw: false,
        }
    }

    /// The OOM fix (0027 monitor): `send_capped` must never buffer more than `max_body` bytes of
    /// an oversized response, while the existing uncapped `send` on the very same origin still
    /// reads the whole thing — proving the cap actually bounds the READ, not just a post-hoc
    /// truncate of an already-fully-buffered body.
    #[tokio::test]
    async fn send_capped_stops_reading_at_the_cap() {
        let full_len = 64 * 1024;
        let addr = spawn_big_body_origin(full_len).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let tls = TlsContext::new(dir.path(), Vec::new()).expect("tls context");
        let req = get_request(addr);

        let cap = 1024usize;
        let capped = send_capped(&req, &tls, cap).await.expect("capped send");
        assert_eq!(
            capped.body.len(),
            cap,
            "capped read must stop exactly at the cap, never buffer the whole body"
        );

        let full = send(&req, &tls).await.expect("uncapped send");
        assert_eq!(
            full.body.len(),
            full_len,
            "send (max_body=None) keeps today's unbounded behavior"
        );
    }
}
