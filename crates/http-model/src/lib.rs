//! Transport-level HTTP/WebSocket DTOs shared by the proxy engine (`proxy-core`) and the rest of
//! the workspace.
//!
//! Headers are a list of pairs (duplicates and any casing allowed), bodies are raw bytes —
//! nothing is normalized here (that is the "polite" send path's job), so the proxy keeps byte-level
//! control for raw-send / desync work. All target content is UNTRUSTED DATA: it is carried as
//! bytes/text, never interpreted as instructions.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// A single HTTP header as a raw name/value pair (no normalization).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// An HTTP request. `raw = true` means byte-for-byte send via the raw-send path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    /// The request target in raw form (origin-form or absolute-form).
    pub target: String,
    pub version: String,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
    /// Skip header normalization on send (request smuggling / desync).
    pub raw: bool,
}

/// An HTTP response from the target. Content is UNTRUSTED DATA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub version: String,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

/// A captured exchange BEFORE an identifier is assigned. `proxy-core` produces exactly this; the
/// consumer owns identifiers (it assigns them on write). Serde-serializable, so the same shape
/// passes locally and over the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedExchange {
    pub host: String,
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
}

/// A match & replace rule applied to requests/responses as they pass through the proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchReplaceRule {
    pub name: String,
    pub match_pattern: String,
    pub replace_with: String,
    pub on_request: bool,
    pub on_response: bool,
}

/// WebSocket frame direction relative to the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsDir {
    ClientToServer,
    ServerToClient,
}

/// Preview limit in bytes (BEFORE lossy UTF-8 decoding) — the payload can be large/binary, and we
/// don't want the live-feed summary to become a second copy of the full frame.
const WS_PREVIEW_MAX_BYTES: usize = 256;

/// A parsed WebSocket frame (RFC 6455) after unmasking. For continuation frames the `opcode` is
/// already resolved to the opcode of the message they continue (text/binary), so a bare `0x0`
/// never shows up. Payload is UNTRUSTED DATA — what crosses a process boundary is normally the
/// lighter [`WsFrameSummary`], not the full frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsFrame {
    pub conn_id: u64,
    pub dir: WsDir,
    pub opcode: u8,
    pub fin: bool,
    pub payload: Vec<u8>,
}

/// A lightweight frame summary for a live event — without the full content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsFrameSummary {
    pub conn_id: u64,
    pub dir: WsDir,
    pub opcode: u8,
    pub fin: bool,
    pub len: usize,
    /// Content preview: lossy UTF-8, truncated to [`WS_PREVIEW_MAX_BYTES`] payload bytes.
    pub preview: String,
}

impl WsFrame {
    /// Builds the summary for a live event — the only content meant to reach a live feed.
    pub fn summary(&self) -> WsFrameSummary {
        let take = self.payload.len().min(WS_PREVIEW_MAX_BYTES);
        WsFrameSummary {
            conn_id: self.conn_id,
            dir: self.dir,
            opcode: self.opcode,
            fin: self.fin,
            len: self.payload.len(),
            preview: String::from_utf8_lossy(&self.payload[..take]).into_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_reports_full_length_but_truncates_preview() {
        let payload = vec![b'a'; WS_PREVIEW_MAX_BYTES + 50];
        let frame = WsFrame {
            conn_id: 7,
            dir: WsDir::ClientToServer,
            opcode: 0x1,
            fin: true,
            payload,
        };
        let summary = frame.summary();
        assert_eq!(summary.len, WS_PREVIEW_MAX_BYTES + 50);
        assert_eq!(summary.preview.len(), WS_PREVIEW_MAX_BYTES);
        assert_eq!(summary.conn_id, 7);
        assert_eq!(summary.opcode, 0x1);
    }

    #[test]
    fn summary_preview_is_lossy_for_binary_payload() {
        let frame = WsFrame {
            conn_id: 1,
            dir: WsDir::ServerToClient,
            opcode: 0x2,
            fin: true,
            payload: vec![0xff, 0xfe, 0x00, 0x01],
        };
        let summary = frame.summary();
        // Invalid UTF-8 does not panic — we get replacement characters.
        assert_eq!(summary.len, 4);
        assert!(summary.preview.contains('\u{fffd}'));
    }

    #[test]
    fn short_payload_preview_is_exact() {
        let frame = WsFrame {
            conn_id: 2,
            dir: WsDir::ClientToServer,
            opcode: 0x1,
            fin: true,
            payload: b"hello".to_vec(),
        };
        let summary = frame.summary();
        assert_eq!(summary.preview, "hello");
        assert_eq!(summary.len, 5);
    }
}
