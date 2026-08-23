//! A WebSocket frame parser (RFC 6455) and a bidirectional pump. Replaces the transparent
//! `copy_bidirectional` (used before): we now read full frames. When WS intercept is off (the default),
//! we forward them BYTE-FOR-BYTE (the client mask must reach the server untouched — we don't
//! re-encode), and on a (unmasked) COPY we build the log via [`ExchangeSink`]. When intercept is
//! ON, DATA frames (text/binary) first go to [`crate::Interceptor`] — the operator/
//! agent may edit or drop them before the (possibly edited) frame is RE-ENCODED and
//! sent. Frame content is UNTRUSTED DATA.
use std::sync::Arc;
use std::sync::OnceLock;

use rustls::crypto::SecureRandom;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::{ExchangeSink, Interceptor};
use http_model::{WsDir, WsFrame};

// Opcodes, RFC 6455 §11.8.
const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_CLOSE: u8 = 0x8;

/// Control frames have the high bit of the opcode nibble set (0x8–0xF); they must not be
/// fragmented (RFC 6455 §5.5).
fn is_control_opcode(opcode: u8) -> bool {
    opcode & 0x8 != 0
}

/// Cap on a single frame length we're willing to buffer before even reading the payload —
/// a defense against a header-declared gigantic length (allocation DoS). 64 MiB with
/// headroom over typical WS messages; real larger payloads are rare anyway.
const MAX_WS_FRAME_PAYLOAD: u64 = 64 * 1024 * 1024;

/// WS parser/pump errors — internal to `proxy-core`, each ends the tunnel (log + teardown).
#[derive(Debug, thiserror::Error)]
pub(crate) enum WsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("truncated WS frame (too few bytes)")]
    Truncated,
    #[error("WS frame too large: {0} B (limit {MAX_WS_FRAME_PAYLOAD} B)")]
    TooLarge(u64),
    #[error("WS protocol violation: {0}")]
    Protocol(String),
}

/// A parsed frame (on a copy of the bytes that already went through byte-for-byte) — the header
/// read and the payload unmasked if the frame carried a mask.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedFrame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

/// A purely synchronous parser of one COMPLETE frame from a buffer (no I/O — directly testable).
/// Handles FIN+opcode, the MASK bit + a 4-byte key, and the payload length in all three
/// forms (7-bit, 16-bit `126`, 64-bit `127`). A short/truncated buffer → error, never a panic.
fn parse_frame(buf: &[u8]) -> Result<ParsedFrame, WsError> {
    if buf.len() < 2 {
        return Err(WsError::Truncated);
    }
    let fin = buf[0] & 0x80 != 0;
    let opcode = buf[0] & 0x0f;
    let masked = buf[1] & 0x80 != 0;
    let len7 = buf[1] & 0x7f;
    let mut idx = 2usize;

    let payload_len: usize = match len7 {
        126 => {
            let end = idx + 2;
            let bytes = buf.get(idx..end).ok_or(WsError::Truncated)?;
            idx = end;
            u16::from_be_bytes([bytes[0], bytes[1]]) as usize
        }
        127 => {
            let end = idx + 8;
            let bytes = buf.get(idx..end).ok_or(WsError::Truncated)?;
            idx = end;
            let n = u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            usize::try_from(n).map_err(|_| WsError::TooLarge(n))?
        }
        n => n as usize,
    };

    let mask_key = if masked {
        let end = idx + 4;
        let bytes = buf.get(idx..end).ok_or(WsError::Truncated)?;
        idx = end;
        Some([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        None
    };

    let end = idx.checked_add(payload_len).ok_or(WsError::Truncated)?;
    let mut payload = buf.get(idx..end).ok_or(WsError::Truncated)?.to_vec();
    if let Some(key) = mask_key {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= key[i % 4];
        }
    }
    Ok(ParsedFrame {
        fin,
        opcode,
        payload,
    })
}

/// Encodes a WS frame back to wire bytes (RFC 6455 §5.2) — used ONLY under intercept
/// because only then do we no longer have the original 1:1 bytes to forward (an edit may have
/// changed the payload length). Handles all three length forms (7-bit, 16-bit `126`, 64-bit `127`).
/// Masking is the CALLER'S DECISION — see [`pump_direction`] (RFC 6455 §5.1: the client MUST
/// mask, the server MUST NOT), here we only randomize the key when `mask=true`.
fn encode_frame(fin: bool, opcode: u8, payload: &[u8], mask: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(payload.len() + 14); // header max. 2+8+4 = 14B
    buf.push((if fin { 0x80 } else { 0 }) | (opcode & 0x0f));

    let mask_bit = if mask { 0x80 } else { 0 };
    let len = payload.len();
    if len < 126 {
        buf.push(mask_bit | len as u8);
    } else if len <= 0xffff {
        buf.push(mask_bit | 126);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(mask_bit | 127);
        buf.extend_from_slice(&(len as u64).to_be_bytes());
    }

    if mask {
        let key = random_mask_key();
        buf.extend_from_slice(&key);
        buf.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    } else {
        buf.extend_from_slice(payload);
    }
    buf
}

/// A 4-byte mask key for a re-encoded frame sent as a WS client (RFC 6455 §5.1 requires a mask
/// on this leg). It need not be cryptographically strong — this is a FRAMING requirement, not a security
/// one — it just needs to change between frames. We reuse `ring` (already in the dependency tree via
/// `rustls`, feature `ring` — see `ca.rs`), instead of adding a new dependency just for 4 random
/// bytes; we take the provider once (lazily) and keep it in a `OnceLock`, so we don't rebuild it
/// for every frame.
fn random_mask_key() -> [u8; 4] {
    static RNG: OnceLock<&'static dyn SecureRandom> = OnceLock::new();
    let rng = *RNG.get_or_init(|| rustls::crypto::aws_lc_rs::default_provider().secure_random);
    let mut key = [0u8; 4];
    // `fill` fails only on the practically-never-seen exhaustion of system entropy — on
    // error we stay with all zeros (the frame is still RFC-valid, just predictably
    // masked; this isn't a security boundary anyway).
    let _ = rng.fill(&mut key);
    key
}

/// Reads one complete WS frame from the stream: header (2B) + extended length (0/2/8B) +
/// mask (0/4B) + payload — ALL goes into one buffer, because exactly those bytes (untouched,
/// still masked if client-side) forward on to the other side in [`pump_direction`].
///
/// `Ok(None)` = a clean close ON A FRAME BOUNDARY (0 bytes available at the start of the read).
/// A break mid-frame (even 1 byte read, then EOF) is an error, not `None` —
/// otherwise a truncated stream would look like a graceful close.
async fn read_ws_frame_bytes<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, WsError> {
    let mut first = [0u8; 1];
    let n = r.read(&mut first).await?;
    if n == 0 {
        return Ok(None);
    }
    let mut buf = vec![first[0]];
    let mut second = [0u8; 1];
    r.read_exact(&mut second).await?;
    buf.push(second[0]);

    let len7 = second[0] & 0x7f;
    let masked = second[0] & 0x80 != 0;

    let payload_len: u64 = match len7 {
        126 => {
            let mut ext = [0u8; 2];
            r.read_exact(&mut ext).await?;
            buf.extend_from_slice(&ext);
            u16::from_be_bytes(ext) as u64
        }
        127 => {
            let mut ext = [0u8; 8];
            r.read_exact(&mut ext).await?;
            buf.extend_from_slice(&ext);
            u64::from_be_bytes(ext)
        }
        n => n as u64,
    };
    if payload_len > MAX_WS_FRAME_PAYLOAD {
        return Err(WsError::TooLarge(payload_len));
    }
    if masked {
        let mut mask = [0u8; 4];
        r.read_exact(&mut mask).await?;
        buf.extend_from_slice(&mask);
    }
    let start = buf.len();
    buf.resize(start + payload_len as usize, 0);
    r.read_exact(&mut buf[start..]).await?;
    Ok(Some(buf))
}

/// The write half of a socket (client or target), shared between the pump (`pump_direction`) and
/// the injection path ([`WsInjector`]) behind a `Mutex` — it serializes writes so an
/// injected frame never interleaves halfway with a frame going through the normal relay. The type is
/// CONCRETE (not generic over `W: AsyncWrite`), because `WsInjector` should be a single,
/// non-generic type, kept in a `conn_id -> WsInjector` map in the host.
type SharedWriter = Arc<Mutex<Box<dyn AsyncWrite + Send + Unpin>>>;

/// A handle to inject ANY WS frame into a LIVE tunnel — one
/// [`SharedWriter`] per direction, so injection and the normal relay write to the SAME
/// socket under the same lock (never interleaved bytes on the wire). Registered by
/// [`ExchangeSink::register_ws_injector`] right after the tunnel opens (see `pump_ws_frames`),
/// removed after it closes.
#[derive(Clone)]
pub struct WsInjector {
    to_client: SharedWriter,
    to_server: SharedWriter,
}

impl WsInjector {
    /// Encodes and sends ONE frame in the given direction. Masking depends on the direction (RFC 6455
    /// §5.1) — exactly like re-encoding an edited frame in `pump_direction`:
    /// `ClientToServer` → we write to the SERVER (weir is a WS client there → MUST mask);
    /// `ServerToClient` → we write to the CLIENT (weir is a WS server there → MUST NOT mask).
    /// A write error (e.g. the tunnel already closed) returns as `io::Error`, never a panic.
    pub async fn inject(
        &self,
        dir: WsDir,
        opcode: u8,
        fin: bool,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let bytes = encode_frame(fin, opcode, payload, dir == WsDir::ClientToServer);
        let w = match dir {
            WsDir::ClientToServer => &self.to_server,
            WsDir::ServerToClient => &self.to_client,
        };
        w.lock().await.write_all(&bytes).await
    }
}

/// Tracks an in-progress fragmented WS message (RFC 6455 §5.4) in ONE direction, so a
/// `continuation` frame (opcode `0x0`) is logged with the opcode of the MESSAGE (text/binary) it
/// continues, instead of a bare `0x0`. Control frames may interleave with fragmentation
/// (RFC 6455 allows it explicitly) and cannot themselves be fragmented.
#[derive(Debug, Default)]
struct FragmentTracker {
    pending: Option<u8>,
}

impl FragmentTracker {
    /// Returns the effective opcode to log for THIS frame, or a protocol error when the fragment
    /// sequence is invalid.
    fn observe(&mut self, opcode: u8, fin: bool) -> Result<u8, WsError> {
        if is_control_opcode(opcode) {
            if !fin {
                return Err(WsError::Protocol(
                    "control frame must not be fragmented (FIN=0)".to_owned(),
                ));
            }
            return Ok(opcode); // control frames don't touch the data fragmentation state
        }
        if opcode == OPCODE_CONTINUATION {
            let pending = self.pending.ok_or_else(|| {
                WsError::Protocol("continuation without a preceding start frame".to_owned())
            })?;
            if fin {
                self.pending = None;
            }
            Ok(pending)
        } else {
            if self.pending.is_some() {
                return Err(WsError::Protocol(
                    "new WS message during unfinished fragmentation".to_owned(),
                ));
            }
            if !fin {
                self.pending = Some(opcode);
            }
            Ok(opcode)
        }
    }
}

/// The bidirectional pump: after `hyper::upgrade::on` on BOTH sides, we tunnel frames instead of
/// raw bytes. Each direction is a separate task — no shared state to roll back on
/// `select!`, so a frame read never loses already-consumed bytes (cancellation-safety).
/// It ends when BOTH directions reach the end (a `close` frame/EOF/error) — like `copy_bidirectional`,
/// it supports half-close: the direction that finished first closes the write to the other side and waits.
/// `interceptor` is the same handle as for HTTP requests/responses — it also adds
/// `hold_ws_frame`, OFF by default (passthrough, zero overhead — see `pump_direction`).
pub(crate) async fn pump_ws_frames<C, T>(
    client: C,
    target: T,
    conn_id: u64,
    sink: Arc<dyn ExchangeSink>,
    interceptor: Arc<dyn Interceptor>,
    host: String,
) where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (c_read, c_write) = tokio::io::split(client);
    let (t_read, t_write) = tokio::io::split(target);

    // Shared write halves: each pump gets a handle under which injection (`WsInjector`)
    // ALSO writes — the `Mutex` guarantees they never interleave.
    let c_write: SharedWriter = Arc::new(Mutex::new(Box::new(c_write)));
    let t_write: SharedWriter = Arc::new(Mutex::new(Box::new(t_write)));

    let injector = WsInjector {
        to_client: c_write.clone(),
        to_server: t_write.clone(),
    };
    sink.register_ws_injector(conn_id, injector);

    let c2t = tokio::spawn(pump_direction(
        c_read,
        t_write,
        conn_id,
        WsDir::ClientToServer,
        sink.clone(),
        interceptor.clone(),
    ));
    let t2c = tokio::spawn(pump_direction(
        t_read,
        c_write,
        conn_id,
        WsDir::ServerToClient,
        sink.clone(),
        interceptor,
    ));

    let (c2t_frames, t2c_frames) = tokio::join!(c2t, t2c);
    tracing::debug!(
        host = %host,
        conn_id,
        c2t_frames = c2t_frames.unwrap_or(0),
        t2c_frames = t2c_frames.unwrap_or(0),
        "WS tunnel closed"
    );
    sink.unregister_ws_injector(conn_id);
    sink.on_ws_close(conn_id);
}

/// One direction of the pump. Ends on a `close` frame, EOF or a parse/protocol error; then it
/// gracefully closes the write to the other side (half-close), so it doesn't hang the opposite direction.
/// Returns the number of forwarded frames (for the diagnostic log).
///
/// Two paths:
/// - **Intercept OFF** (`!interceptor.ws_intercept_enabled()`, the default):
///   bytes FORWARD exactly as they arrived, BEFORE we parse anything from them — we build the log
///   on a (unmasked) copy, after forwarding. Zero parse-for-edit overhead.
/// - **Intercept ON**: we parse BEFORE sending. Control frames (ping/pong/close) still
///   forward without holding — pausing a `close` would block the tunnel teardown, and ping/pong
///   usually have short timeouts on the other side; that's a safer choice than intercepting
///   everything. Only DATA frames (text/binary/continuation) go to `hold_ws_frame` — the operator/
///   agent may edit or drop them. The sent (possibly edited) frame is RE-ENCODED
///   (`encode_frame`), not forwarded `raw` byte-for-byte, because an edit may have changed the payload length.
async fn pump_direction<R>(
    mut reader: R,
    writer: SharedWriter,
    conn_id: u64,
    dir: WsDir,
    sink: Arc<dyn ExchangeSink>,
    interceptor: Arc<dyn Interceptor>,
) -> u64
where
    R: AsyncRead + Unpin,
{
    let mut tracker = FragmentTracker::default();
    let mut frames = 0u64;
    loop {
        let raw = match read_ws_frame_bytes(&mut reader).await {
            Ok(Some(buf)) => buf,
            Ok(None) => break,
            Err(e) => {
                tracing::debug!(conn_id, ?dir, error = %e, "WS tunnel: frame read error");
                break;
            }
        };

        if !interceptor.ws_intercept_enabled() {
            // OFF (zero overhead): the wire FORWARDS exactly the bytes that arrived —
            // the client mask must reach the server untouched, we don't re-encode.
            if let Err(e) = writer.lock().await.write_all(&raw).await {
                tracing::debug!(conn_id, ?dir, error = %e, "WS tunnel: frame write error");
                break;
            }
            frames += 1;

            let parsed = match parse_frame(&raw) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(conn_id, ?dir, error = %e, "tunel WS: ramka nie do sparsowania");
                    break;
                }
            };
            let effective_opcode = match tracker.observe(parsed.opcode, parsed.fin) {
                Ok(op) => op,
                Err(e) => {
                    tracing::debug!(conn_id, ?dir, error = %e, "WS tunnel: protocol violation");
                    break;
                }
            };
            let is_close = parsed.opcode == OPCODE_CLOSE;
            sink.on_ws_frame(
                conn_id,
                WsFrame {
                    conn_id,
                    dir,
                    opcode: effective_opcode,
                    fin: parsed.fin,
                    payload: parsed.payload,
                },
            );
            if is_close {
                break; // close frame forwarded and logged — this direction ends
            }
            continue;
        }

        // ON: parse BEFORE sending, so the operator/agent can hold/edit/drop
        // the frame before anything goes on the wire.
        let parsed = match parse_frame(&raw) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(conn_id, ?dir, error = %e, "tunel WS: ramka nie do sparsowania");
                break;
            }
        };
        let effective_opcode = match tracker.observe(parsed.opcode, parsed.fin) {
            Ok(op) => op,
            Err(e) => {
                tracing::debug!(conn_id, ?dir, error = %e, "WS tunnel: protocol violation");
                break;
            }
        };
        let frame = WsFrame {
            conn_id,
            dir,
            opcode: effective_opcode,
            fin: parsed.fin,
            payload: parsed.payload,
        };

        if is_control_opcode(parsed.opcode) {
            // Control frames are NOT held, even when intercept is on — see the pump doc
            // above. They forward byte-for-byte, as in OFF mode.
            if let Err(e) = writer.lock().await.write_all(&raw).await {
                tracing::debug!(conn_id, ?dir, error = %e, "WS tunnel: frame write error");
                break;
            }
            frames += 1;
            let is_close = parsed.opcode == OPCODE_CLOSE;
            sink.on_ws_frame(conn_id, frame);
            if is_close {
                break;
            }
            continue;
        }

        // A DATA frame — consults `hold_ws_frame` (like `hold_request` for HTTP): `Some(edited)` =
        // send (possibly edited), `None` = drop.
        let was_continuation = parsed.opcode == OPCODE_CONTINUATION;
        let log_frame = frame.clone(); // for the log in the Drop branch — `hold_ws_frame` consumes `frame`
        match interceptor.hold_ws_frame(conn_id, dir, frame).await {
            Some(edited) => {
                // A `continuation` frame must stay a continuation ON THE WIRE (opcode 0x0), regardless
                // of the `opcode` field in `WsFrame` (already resolved to the MESSAGE opcode for
                // logging/editing, see the `WsFrame` doc) — otherwise we'd break fragmentation on the
                // receiver's side (two "start" frames in a row). For NON-continuation frames the
                // `opcode` edit is fully honored (e.g. swapping text↔binary).
                let wire_opcode = if was_continuation {
                    OPCODE_CONTINUATION
                } else {
                    edited.opcode
                };
                // Masking depends on the DIRECTION (RFC 6455 §5.1): weir is a WS client on the leg to
                // the server (mask required), and a WS server on the leg to the client (mask forbidden).
                let mask = dir == WsDir::ClientToServer;
                let encoded = encode_frame(edited.fin, wire_opcode, &edited.payload, mask);
                if let Err(e) = writer.lock().await.write_all(&encoded).await {
                    tracing::debug!(conn_id, ?dir, error = %e, "WS tunnel: frame write error");
                    break;
                }
                frames += 1;
                sink.on_ws_frame(conn_id, edited);
            }
            None => {
                // DROP: nothing goes on in this direction for this frame — we still log it (the operator
                // sees on the live feed that something disappeared, instead of a silent gap).
                sink.on_ws_frame(conn_id, log_frame);
            }
        }
    }
    let _ = writer.lock().await.shutdown().await;
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds raw RFC 6455 frame bytes directly from fields — for parser/read tests, without
    /// relying on the production code on the other side.
    fn build_frame(fin: bool, opcode: u8, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push((if fin { 0x80 } else { 0 }) | opcode);
        let len = payload.len();
        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        if len < 126 {
            buf.push(mask_bit | len as u8);
        } else if len <= 0xffff {
            buf.push(mask_bit | 126);
            buf.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            buf.push(mask_bit | 127);
            buf.extend_from_slice(&(len as u64).to_be_bytes());
        }
        if let Some(key) = mask {
            buf.extend_from_slice(&key);
            let masked: Vec<u8> = payload
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % 4])
                .collect();
            buf.extend_from_slice(&masked);
        } else {
            buf.extend_from_slice(payload);
        }
        buf
    }

    // --- parse_frame -----------------------------------------------------

    #[test]
    fn parses_unmasked_text_frame() {
        let buf = build_frame(true, 0x1, None, b"hello");
        let f = parse_frame(&buf).expect("parse");
        assert!(f.fin);
        assert_eq!(f.opcode, 0x1);
        assert_eq!(f.payload, b"hello");
    }

    #[test]
    fn parses_masked_text_frame_and_unmasks() {
        let buf = build_frame(true, 0x1, Some([0x11, 0x22, 0x33, 0x44]), b"hello world");
        let f = parse_frame(&buf).expect("parse");
        assert_eq!(f.payload, b"hello world");
    }

    #[test]
    fn parses_masked_binary_frame() {
        let payload: Vec<u8> = (0..64).collect();
        let buf = build_frame(true, 0x2, Some([0xaa, 0xbb, 0xcc, 0xdd]), &payload);
        let f = parse_frame(&buf).expect("parse");
        assert_eq!(f.opcode, 0x2);
        assert_eq!(f.payload, payload);
    }

    #[test]
    fn parses_16bit_extended_length() {
        let payload = vec![0x42u8; 300]; // > 125, forces form 126
        let buf = build_frame(true, 0x2, None, &payload);
        assert_eq!(buf[1] & 0x7f, 126);
        let f = parse_frame(&buf).expect("parse");
        assert_eq!(f.payload.len(), 300);
    }

    #[test]
    fn parses_64bit_extended_length() {
        let payload = vec![0x7u8; 70_000]; // > 65535, forces form 127
        let buf = build_frame(true, 0x2, Some([1, 2, 3, 4]), &payload);
        assert_eq!(buf[1] & 0x7f, 127);
        let f = parse_frame(&buf).expect("parse");
        assert_eq!(f.payload.len(), 70_000);
        assert_eq!(f.payload, payload);
    }

    #[test]
    fn parses_ping_pong_close() {
        for opcode in [0x8u8, 0x9, 0xa] {
            let buf = build_frame(true, opcode, Some([9, 9, 9, 9]), b"abc");
            let f = parse_frame(&buf).expect("parse");
            assert_eq!(f.opcode, opcode);
            assert_eq!(f.payload, b"abc");
        }
    }

    #[test]
    fn parses_fragmented_message_frames_individually() {
        let start = build_frame(false, 0x1, None, b"hel");
        let cont = build_frame(true, 0x0, None, b"lo");
        let f1 = parse_frame(&start).expect("parse start");
        let f2 = parse_frame(&cont).expect("parse cont");
        assert!(!f1.fin);
        assert_eq!(f1.opcode, 0x1);
        assert!(f2.fin);
        assert_eq!(f2.opcode, 0x0);
    }

    #[test]
    fn truncated_buffer_is_error_not_panic() {
        assert!(matches!(parse_frame(&[]), Err(WsError::Truncated)));
        assert!(matches!(parse_frame(&[0x81]), Err(WsError::Truncated)));
        // Declares 126 (2B of extended length) but does not provide them.
        assert!(matches!(
            parse_frame(&[0x81, 0xfe]),
            Err(WsError::Truncated)
        ));
        // Declares a mask but does not provide it.
        assert!(matches!(
            parse_frame(&[0x81, 0x85]),
            Err(WsError::Truncated)
        ));
        // Declares a payload longer than actually provided.
        let mut buf = build_frame(true, 0x1, None, b"hello");
        buf.truncate(buf.len() - 2);
        assert!(matches!(parse_frame(&buf), Err(WsError::Truncated)));
    }

    // --- encode_frame -------------------------------------------------------

    #[test]
    fn encode_frame_round_trips_unmasked_short() {
        let encoded = encode_frame(true, 0x1, b"hello", false);
        assert_eq!(encoded[1] & 0x80, 0, "unmasked must have the MASK bit = 0");
        let f = parse_frame(&encoded).expect("parse");
        assert!(f.fin);
        assert_eq!(f.opcode, 0x1);
        assert_eq!(f.payload, b"hello");
    }

    #[test]
    fn encode_frame_round_trips_masked_short() {
        let encoded = encode_frame(true, 0x2, b"hello world", true);
        assert_eq!(encoded[1] & 0x80, 0x80, "masked must have the MASK bit = 1");
        let f = parse_frame(&encoded).expect("parse");
        assert_eq!(f.opcode, 0x2);
        assert_eq!(f.payload, b"hello world");
    }

    #[test]
    fn encode_frame_preserves_fin_bit() {
        let encoded = encode_frame(false, 0x1, b"part", false);
        let f = parse_frame(&encoded).expect("parse");
        assert!(!f.fin);
    }

    #[test]
    fn encode_frame_16bit_extended_length_round_trips() {
        let payload = vec![0x5u8; 300]; // > 125, forces form 126
        let encoded = encode_frame(true, 0x2, &payload, false);
        assert_eq!(encoded[1] & 0x7f, 126);
        let f = parse_frame(&encoded).expect("parse");
        assert_eq!(f.payload, payload);
    }

    #[test]
    fn encode_frame_64bit_extended_length_round_trips_masked() {
        let payload = vec![0x9u8; 70_000]; // > 65535, forces form 127
        let encoded = encode_frame(true, 0x2, &payload, true);
        assert_eq!(encoded[1] & 0x7f, 127);
        let f = parse_frame(&encoded).expect("parse");
        assert_eq!(f.payload, payload);
    }

    #[test]
    fn encode_frame_unmasked_has_no_mask_key_bytes() {
        let encoded = encode_frame(true, 0x1, b"abc", false);
        assert_eq!(encoded.len(), 2 + 3, "header(2) + payload(3), no mask key");
    }

    #[test]
    fn encode_frame_masked_includes_mask_key_bytes() {
        let encoded = encode_frame(true, 0x1, b"abc", true);
        assert_eq!(encoded.len(), 2 + 4 + 3, "header(2) + mask(4) + payload(3)");
    }

    #[test]
    fn encode_frame_mask_key_varies_between_calls() {
        // The key need not be cryptographically strong, but it must CHANGE — otherwise every
        // edited frame would have the same mask key (a trivial XOR to guess).
        let a = encode_frame(true, 0x1, b"same payload", true);
        let b = encode_frame(true, 0x1, b"same payload", true);
        assert_ne!(
            a, b,
            "two masked frames with the same payload should differ in mask key"
        );
    }

    /// Simulates an edit: the original frame (7-bit length form) grows to a size forcing the
    /// 16-bit form — checks that the encoder correctly switches the length form for the EDITED,
    /// not the original payload.
    #[test]
    fn encode_frame_edited_length_change_switches_length_form() {
        let original = build_frame(true, 0x1, Some([1, 2, 3, 4]), b"short");
        assert_eq!(original[1] & 0x7f, 5); // 7-bit forma
        let edited_payload = vec![b'x'; 500];
        let encoded = encode_frame(true, 0x1, &edited_payload, false);
        assert_eq!(encoded[1] & 0x7f, 126);
        let f = parse_frame(&encoded).expect("parse");
        assert_eq!(f.payload, edited_payload);
    }

    // --- FragmentTracker ---------------------------------------------------

    #[test]
    fn fragment_tracker_resolves_continuation_to_start_opcode() {
        let mut t = FragmentTracker::default();
        assert_eq!(t.observe(0x1, false).expect("start"), 0x1);
        assert_eq!(t.observe(0x0, false).expect("cont1"), 0x1);
        assert_eq!(t.observe(0x0, true).expect("cont-fin"), 0x1);
        // Message complete — the next one may start fresh.
        assert_eq!(t.observe(0x2, true).expect("next msg"), 0x2);
    }

    #[test]
    fn fragment_tracker_allows_control_frames_interleaved() {
        let mut t = FragmentTracker::default();
        assert_eq!(t.observe(0x1, false).expect("start"), 0x1);
        assert_eq!(t.observe(0x9, true).expect("ping mid-fragment"), 0x9);
        assert_eq!(t.observe(0x0, true).expect("cont-fin"), 0x1);
    }

    #[test]
    fn fragment_tracker_rejects_continuation_without_start() {
        let mut t = FragmentTracker::default();
        assert!(matches!(t.observe(0x0, true), Err(WsError::Protocol(_))));
    }

    #[test]
    fn fragment_tracker_rejects_unclosed_new_message() {
        let mut t = FragmentTracker::default();
        assert_eq!(t.observe(0x1, false).expect("start"), 0x1);
        assert!(matches!(t.observe(0x2, false), Err(WsError::Protocol(_))));
    }

    #[test]
    fn fragment_tracker_rejects_fragmented_control_frame() {
        let mut t = FragmentTracker::default();
        assert!(matches!(t.observe(0x8, false), Err(WsError::Protocol(_))));
    }

    // --- read_ws_frame_bytes (async) ---------------------------------------

    #[tokio::test]
    async fn read_frame_bytes_clean_eof_at_boundary() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        let out = read_ws_frame_bytes(&mut cursor).await.expect("read");
        assert!(out.is_none());
    }

    #[tokio::test]
    async fn read_frame_bytes_round_trips_exact_wire_bytes() {
        let original = build_frame(true, 0x1, Some([1, 2, 3, 4]), b"hello proxy");
        let mut cursor = std::io::Cursor::new(original.clone());
        let out = read_ws_frame_bytes(&mut cursor)
            .await
            .expect("read")
            .expect("some frame");
        assert_eq!(
            out, original,
            "must return EXACTLY what came off the network"
        );
    }

    #[tokio::test]
    async fn read_frame_bytes_truncated_mid_frame_is_error() {
        let mut full = build_frame(true, 0x1, None, b"hello");
        full.truncate(full.len() - 2); // truncated mid-payload
        let mut cursor = std::io::Cursor::new(full);
        let err = read_ws_frame_bytes(&mut cursor).await;
        assert!(
            err.is_err(),
            "a truncated frame is an error, not None nor a panic"
        );
    }

    #[tokio::test]
    async fn read_frame_bytes_single_byte_then_eof_is_error() {
        // One header byte, then close — this is NOT a clean close on a frame boundary.
        let mut cursor = std::io::Cursor::new(vec![0x81u8]);
        let err = read_ws_frame_bytes(&mut cursor).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn read_frame_bytes_rejects_oversized_declared_length() {
        let mut buf = vec![0x82u8, 127];
        buf.extend_from_slice(&(MAX_WS_FRAME_PAYLOAD + 1).to_be_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_ws_frame_bytes(&mut cursor).await;
        assert!(matches!(err, Err(WsError::TooLarge(_))));
    }

    // --- WsInjector ---------------------------------------------------------

    /// Builds a `SharedWriter` over one half of a `tokio::io::duplex` pair — tests read the sent
    /// bytes from the OTHER half, exactly as `read_ws_frame_bytes` would read them from a real
    /// socket.
    fn shared_writer_over(half: tokio::io::DuplexStream) -> SharedWriter {
        Arc::new(Mutex::new(Box::new(half)))
    }

    #[tokio::test]
    async fn injector_masks_client_to_server_but_not_server_to_client() {
        let (mut to_server_rx, to_server_tx) = tokio::io::duplex(1024);
        let (mut to_client_rx, to_client_tx) = tokio::io::duplex(1024);
        let injector = WsInjector {
            to_client: shared_writer_over(to_client_tx),
            to_server: shared_writer_over(to_server_tx),
        };

        injector
            .inject(WsDir::ClientToServer, 0x1, true, b"hello")
            .await
            .expect("inject client->server");
        injector
            .inject(WsDir::ServerToClient, 0x1, true, b"world")
            .await
            .expect("inject server->client");

        // Client→server: weir is a WS client there, the frame MUST carry a mask (RFC 6455 §5.1).
        let raw_to_server = read_ws_frame_bytes(&mut to_server_rx)
            .await
            .expect("read")
            .expect("some frame");
        assert_eq!(
            raw_to_server[1] & 0x80,
            0x80,
            "client->server must have MASK=1"
        );
        let parsed = parse_frame(&raw_to_server).expect("parse");
        assert_eq!(parsed.opcode, 0x1);
        assert!(parsed.fin);
        assert_eq!(parsed.payload, b"hello");

        // Server→client: weir is a WS server there, a mask is FORBIDDEN.
        let raw_to_client = read_ws_frame_bytes(&mut to_client_rx)
            .await
            .expect("read")
            .expect("some frame");
        assert_eq!(
            raw_to_client[1] & 0x80,
            0,
            "server->client must not have MASK=1"
        );
        let parsed = parse_frame(&raw_to_client).expect("parse");
        assert_eq!(parsed.payload, b"world");
    }

    #[tokio::test]
    async fn injector_write_error_surfaces_not_panics() {
        let (to_server_rx, to_server_tx) = tokio::io::duplex(1024);
        let (_to_client_rx, to_client_tx) = tokio::io::duplex(1024);
        // Close the receiving side — the next write to the other half must return an error
        // (tunnel "closed"), never a panic.
        drop(to_server_rx);
        let injector = WsInjector {
            to_client: shared_writer_over(to_client_tx),
            to_server: shared_writer_over(to_server_tx),
        };

        let mut last = Ok(());
        for _ in 0..10 {
            last = injector
                .inject(WsDir::ClientToServer, 0x1, true, b"x")
                .await;
            if last.is_err() {
                break;
            }
        }
        assert!(
            last.is_err(),
            "a write to a closed channel must return an error"
        );
    }
}
