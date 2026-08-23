//! A minimal HTTP/2 client with frame-level control — for the **single-packet
//! attack**.
//!
//! High-level libraries (hyper/`h2`) decide themselves when to flush frames,
//! so they don't guarantee "send the finishing frames of N streams in ONE packet".
//! So we assemble frames by hand (HPACK from the `hpack` crate) and drive
//! by writing to the socket:
//! 1. preface + SETTINGS + WINDOW_UPDATE (opening the connection window),
//! 2. for each request: HEADERS (END_HEADERS, **without** END_STREAM) — prime,
//! 3. release: an empty DATA(END_STREAM) for each stream glued into ONE
//!    `write_all` → one TCP packet → the server sees N requests at once (the race window).
//!
//! Supports h2 over TLS (ALPN `h2`, https) and h2c prior-knowledge (http). A body in
//! the template is not supported in this version (single-packet is for bodiless
//! requests — the typical race case); requests with a body → error on the stream.
use std::collections::HashMap;
use std::time::Duration;

use hpack::{Decoder, Encoder};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::ca::{server_name, TlsContext};
use crate::ProxyError;
use http_model::{Header, HttpRequest, HttpResponse};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types.
const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_CONTINUATION: u8 = 0x9;

// Flags.
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

const IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-stream accumulation cap (body AND the header block). A hostile target could stream
/// infinite DATA or flood CONTINUATIONs without END_HEADERS → OOM. Over the cap we kill the
/// stream with an error (status/timing were already collected). Generous 8 MiB — like the cap in `client.rs`.
const MAX_H2_ACCUM: usize = 8 * 1024 * 1024;

/// Single-frame cap (bounds `vec![0u8; len]`). A compliant server sticks to
/// SETTINGS_MAX_FRAME_SIZE anyway (16 KiB by default); 1 MiB cuts off a rogue server without breaking legit traffic.
const MAX_H2_FRAME: usize = 1 << 20;

trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}
type BoxDuplex = Box<dyn Duplex>;

/// The single-packet result: either a whole-connection error (nobody fired), or
/// a vector of per-stream results in request order.
pub async fn single_packet(
    reqs: &[HttpRequest],
    tls: &TlsContext,
) -> Result<Vec<Result<HttpResponse, String>>, ProxyError> {
    if reqs.is_empty() {
        return Ok(Vec::new());
    }
    let (host, port, https) = parse_authority(&reqs[0].target)?;
    let mut stream = connect(&host, port, https, tls).await?;

    // 1. Preface + SETTINGS (INITIAL_WINDOW_SIZE large, PUSH off) + WINDOW_UPDATE
    //    on the connection (open the window so responses don't stall on flow control).
    let mut out = Vec::new();
    out.extend_from_slice(PREFACE);
    let settings = [
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH = 0
        0x00, 0x04, 0x3f, 0xff, 0xff, 0xff, // INITIAL_WINDOW_SIZE ~1GiB
    ];
    push_frame(&mut out, FRAME_SETTINGS, 0, 0, &settings);
    push_frame(
        &mut out,
        FRAME_WINDOW_UPDATE,
        0,
        0,
        &0x3fff_0000u32.to_be_bytes(),
    );
    stream.write_all(&out).await.map_err(ProxyError::Io)?;
    stream.flush().await.map_err(ProxyError::Io)?;

    // 2. Prime: HEADERS on each stream (without END_STREAM). One encoder per
    //    connection (a shared HPACK dynamic table).
    let mut encoder = Encoder::new();
    let mut stream_ids: Vec<u32> = Vec::with_capacity(reqs.len());
    let mut prime = Vec::new();
    let mut bad: HashMap<u32, String> = HashMap::new();
    for (i, req) in reqs.iter().enumerate() {
        let sid = (i as u32) * 2 + 1;
        stream_ids.push(sid);
        if !req.body.is_empty() {
            bad.insert(
                sid,
                "single-packet nie wspiera body w tej wersji".to_string(),
            );
            continue;
        }
        let block = encode_headers(&mut encoder, req, &host, port, https);
        push_frame(&mut prime, FRAME_HEADERS, FLAG_END_HEADERS, sid, &block);
    }
    stream.write_all(&prime).await.map_err(ProxyError::Io)?;
    stream.flush().await.map_err(ProxyError::Io)?;

    // 3. Release: an empty DATA(END_STREAM) for each good stream,
    //    glued into ONE write → one packet.
    let mut release = Vec::new();
    for &sid in &stream_ids {
        if !bad.contains_key(&sid) {
            push_frame(&mut release, FRAME_DATA, FLAG_END_STREAM, sid, &[]);
        }
    }
    stream.write_all(&release).await.map_err(ProxyError::Io)?;
    stream.flush().await.map_err(ProxyError::Io)?;

    // 4. Read frames and collect responses per stream.
    let responses = read_responses(&mut stream, &stream_ids, &bad).await?;

    // Arrange the results in request order.
    let out = stream_ids
        .iter()
        .map(|sid| match responses.get(sid) {
            Some(Ok(resp)) => Ok(resp.clone()),
            Some(Err(e)) => Err(e.clone()),
            None => Err("no response (stream not finished)".to_string()),
        })
        .collect();
    Ok(out)
}

fn parse_authority(target: &str) -> Result<(String, u16, bool), ProxyError> {
    let uri = target
        .parse::<hyper::Uri>()
        .map_err(|_| ProxyError::BadRequest(format!("bad target: {target}")))?;
    let https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
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
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    Ok((host, port, https))
}

async fn connect(
    host: &str,
    port: u16,
    https: bool,
    tls: &TlsContext,
) -> Result<BoxDuplex, ProxyError> {
    let tcp = tls.dial(host, port).await?;
    tcp.set_nodelay(true).ok();
    if !https {
        // h2c prior-knowledge — we just start speaking h2 over TCP.
        return Ok(Box::new(tcp));
    }
    let sni = server_name(host)?;
    let stream = tls
        .h2_connector()
        .connect(sni, tcp)
        .await
        .map_err(ProxyError::TlsUpstream)?;
    let alpn = stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
    if alpn.as_deref() != Some(b"h2") {
        return Err(ProxyError::BadRequest(format!(
            "server did not negotiate HTTP/2 (ALPN={:?})",
            alpn.as_deref().map(String::from_utf8_lossy)
        )));
    }
    Ok(Box::new(stream))
}

/// HPACK-encode the pseudo-headers + request headers. Skips H1-specific headers.
fn encode_headers(
    encoder: &mut Encoder,
    req: &HttpRequest,
    host: &str,
    port: u16,
    https: bool,
) -> Vec<u8> {
    let uri = req.target.parse::<hyper::Uri>().ok();
    let path = uri
        .as_ref()
        .and_then(|u| u.path_and_query())
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let scheme = if https { "https" } else { "http" };
    let authority = if (https && port == 443) || (!https && port == 80) {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };

    let mut headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b":method".to_vec(), req.method.as_bytes().to_vec()),
        (b":scheme".to_vec(), scheme.as_bytes().to_vec()),
        (b":path".to_vec(), path.into_bytes()),
        (b":authority".to_vec(), authority.into_bytes()),
    ];
    for h in &req.headers {
        let name = h.name.to_ascii_lowercase();
        // Host → :authority; we skip H1 connection headers and pseudo-headers.
        if matches!(
            name.as_str(),
            "host"
                | "connection"
                | "proxy-connection"
                | "keep-alive"
                | "transfer-encoding"
                | "upgrade"
        ) || name.starts_with(':')
        {
            continue;
        }
        headers.push((name.into_bytes(), h.value.as_bytes().to_vec()));
    }
    encoder.encode(headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())))
}

fn push_frame(buf: &mut Vec<u8>, typ: u8, flags: u8, stream: u32, payload: &[u8]) {
    let len = payload.len() as u32;
    buf.push((len >> 16) as u8);
    buf.push((len >> 8) as u8);
    buf.push(len as u8);
    buf.push(typ);
    buf.push(flags);
    buf.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    buf.extend_from_slice(payload);
}

struct Pending {
    status: Option<u16>,
    body: Vec<u8>,
    header_block: Vec<u8>,
    done: bool,
    error: Option<String>,
}

async fn read_responses<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    stream_ids: &[u32],
    bad: &HashMap<u32, String>,
) -> Result<HashMap<u32, Result<HttpResponse, String>>, ProxyError> {
    let mut pend: HashMap<u32, Pending> = HashMap::new();
    let mut out: HashMap<u32, Result<HttpResponse, String>> = HashMap::new();
    for (&sid, err) in bad {
        out.insert(sid, Err(err.clone()));
    }
    let mut remaining = stream_ids.iter().filter(|s| !bad.contains_key(s)).count();
    let mut decoder = Decoder::new();

    while remaining > 0 {
        let frame = match timeout(IDLE_TIMEOUT, read_frame(stream)).await {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => return Err(ProxyError::Io(e)),
            Err(_) => break, // idle — we finish with what we have
        };
        let (typ, flags, sid, payload) = frame;
        match typ {
            FRAME_SETTINGS if flags & FLAG_ACK == 0 => {
                // ACK the server settings.
                let mut ack = Vec::new();
                push_frame(&mut ack, FRAME_SETTINGS, FLAG_ACK, 0, &[]);
                stream.write_all(&ack).await.map_err(ProxyError::Io)?;
                stream.flush().await.map_err(ProxyError::Io)?;
            }
            FRAME_PING if flags & FLAG_ACK == 0 => {
                let mut pong = Vec::new();
                push_frame(&mut pong, FRAME_PING, FLAG_ACK, 0, &payload);
                stream.write_all(&pong).await.map_err(ProxyError::Io)?;
                stream.flush().await.map_err(ProxyError::Io)?;
            }
            FRAME_GOAWAY => break,
            FRAME_RST_STREAM => {
                if stream_ids.contains(&sid) && !out.contains_key(&sid) {
                    out.insert(sid, Err("RST_STREAM od serwera".to_string()));
                    pend.remove(&sid);
                    remaining = remaining.saturating_sub(1);
                }
            }
            FRAME_HEADERS | FRAME_CONTINUATION => {
                let entry = pend.entry(sid).or_insert_with(Pending::new);
                // Header-block accumulation cap — a CONTINUATION flood without END_HEADERS → OOM.
                let over = entry.header_block.len() + payload.len() > MAX_H2_ACCUM;
                if over {
                    entry.error = Some("h2: header block exceeded the limit".to_string());
                    entry.header_block = Vec::new();
                } else {
                    entry.header_block.extend_from_slice(&payload);
                    if flags & FLAG_END_HEADERS != 0 {
                        match decoder.decode(&entry.header_block) {
                            Ok(hs) => {
                                for (n, v) in hs {
                                    if n == b":status" {
                                        entry.status = std::str::from_utf8(&v)
                                            .ok()
                                            .and_then(|s| s.parse().ok());
                                    }
                                }
                            }
                            Err(_) => entry.error = Some("HPACK error in the response".to_string()),
                        }
                        entry.header_block.clear();
                    }
                }
                if over || flags & FLAG_END_STREAM != 0 {
                    finish(sid, &mut pend, &mut out, &mut remaining);
                }
            }
            FRAME_DATA => {
                let entry = pend.entry(sid).or_insert_with(Pending::new);
                // Body accumulation cap — infinite DATA from a hostile target → OOM.
                let over = entry.body.len() + payload.len() > MAX_H2_ACCUM;
                if over {
                    entry.error = Some("h2: response body exceeded the limit".to_string());
                } else {
                    entry.body.extend_from_slice(&payload);
                }
                // Renew the window (connection + stream) so large bodies don't stall — but NOT after
                // exceeding the cap (we don't invite more bytes we'd reject anyway).
                if !over && !payload.is_empty() {
                    let inc = (payload.len() as u32).to_be_bytes();
                    let mut wu = Vec::new();
                    push_frame(&mut wu, FRAME_WINDOW_UPDATE, 0, 0, &inc);
                    push_frame(&mut wu, FRAME_WINDOW_UPDATE, 0, sid, &inc);
                    stream.write_all(&wu).await.map_err(ProxyError::Io)?;
                    stream.flush().await.map_err(ProxyError::Io)?;
                }
                if over || flags & FLAG_END_STREAM != 0 {
                    finish(sid, &mut pend, &mut out, &mut remaining);
                }
            }
            _ => {} // WINDOW_UPDATE od serwera, PRIORITY itd. — ignorujemy
        }
    }

    // Streams without END_STREAM (timeout) — return what we have (if they have a status).
    for (&sid, p) in pend.iter() {
        out.entry(sid).or_insert_with(|| p.clone().into_result());
    }
    Ok(out)
}

fn finish(
    sid: u32,
    pend: &mut HashMap<u32, Pending>,
    out: &mut HashMap<u32, Result<HttpResponse, String>>,
    remaining: &mut usize,
) {
    if let Some(p) = pend.remove(&sid) {
        out.insert(sid, p.into_result());
        *remaining = remaining.saturating_sub(1);
    }
}

impl Pending {
    fn new() -> Self {
        Pending {
            status: None,
            body: Vec::new(),
            header_block: Vec::new(),
            done: false,
            error: None,
        }
    }
    fn clone(&self) -> Self {
        Pending {
            status: self.status,
            body: self.body.clone(),
            header_block: Vec::new(),
            done: self.done,
            error: self.error.clone(),
        }
    }
    fn into_result(self) -> Result<HttpResponse, String> {
        if let Some(e) = self.error {
            return Err(e);
        }
        match self.status {
            Some(status) => Ok(HttpResponse {
                status,
                version: "HTTP/2".to_owned(),
                headers: Vec::<Header>::new(),
                body: self.body,
            }),
            None => Err("no :status in the response".to_string()),
        }
    }
}

/// Reads one frame: a 9-byte header + payload.
async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<(u8, u8, u32, Vec<u8>)> {
    let mut hdr = [0u8; 9];
    stream.read_exact(&mut hdr).await?;
    let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | (hdr[2] as usize);
    let typ = hdr[3];
    let flags = hdr[4];
    let sid = u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]);
    if len > MAX_H2_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "h2: rozmiar ramki przekracza limit",
        ));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await?;
    }
    Ok((typ, flags, sid, payload))
}
