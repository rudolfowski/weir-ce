//! Upstream proxy chains: route ALL of weir's outbound traffic through another proxy —
//! HTTP CONNECT (Burp / corporate) or SOCKS5 (Tor). `dial` returns a bare `TcpStream` that is a TUNNEL
//! to the target; the higher layer (TLS/HTTP) runs on it unchanged, so the chain is transparent to
//! relay and raw-send. No auth in v0 (Tor/Burp locally don't require it).
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::ProxyError;

/// A configured upstream proxy. `host:port` is the address of the PROXY itself (not the target).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    /// HTTP forward proxy: a tunnel via `CONNECT host:port` (works for http and https targets).
    HttpConnect { host: String, port: u16 },
    /// SOCKS5 with proxy-side DNS resolution (`socks5h`) — the right choice for Tor.
    Socks5 { host: String, port: u16 },
}

impl Upstream {
    /// Parses a proxy URL: `http://h:p` / `https://h:p` → HTTP CONNECT; `socks5://h:p` /
    /// `socks5h://h:p` → SOCKS5. Empty/None-like → `None`. Without a scheme assumes `http://`.
    pub fn parse(url: &str) -> Option<Upstream> {
        let url = url.trim();
        if url.is_empty() {
            return None;
        }
        let (scheme, rest) = match url.split_once("://") {
            Some((s, r)) => (s.to_ascii_lowercase(), r),
            None => ("http".to_owned(), url),
        };
        // Strip any path/credentials — we take only host:port.
        let hostport = rest.split(['/', '?']).next().unwrap_or(rest);
        let hostport = hostport.rsplit('@').next().unwrap_or(hostport); // skip user:pass@
        let (host, port) = split_host_port(hostport, default_port(&scheme))?;
        match scheme.as_str() {
            "http" | "https" => Some(Upstream::HttpConnect { host, port }),
            "socks5" | "socks5h" | "socks" => Some(Upstream::Socks5 { host, port }),
            _ => None,
        }
    }

    /// The canonical URL (for reporting to callers).
    pub fn url(&self) -> String {
        match self {
            Upstream::HttpConnect { host, port } => format!("http://{host}:{port}"),
            Upstream::Socks5 { host, port } => format!("socks5h://{host}:{port}"),
        }
    }
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        "socks5" | "socks5h" | "socks" => 1080,
        _ => 8080,
    }
}

fn split_host_port(s: &str, default: u16) -> Option<(String, u16)> {
    // IPv6 in brackets: [::1]:9050
    if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once(']')?;
        let port = p
            .strip_prefix(':')
            .and_then(|x| x.parse().ok())
            .unwrap_or(default);
        return Some((h.to_owned(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => Some((h.to_owned(), p.parse().ok()?)),
        _ => Some((s.to_owned(), default)),
    }
}

/// Opens a tunnel to `target_host:target_port` through the configured upstream. Returns a `TcpStream`
/// that is already the tunnel — you can do TLS/HTTP on it as on a direct connection.
pub async fn dial_through(
    up: &Upstream,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, ProxyError> {
    match up {
        Upstream::HttpConnect { host, port } => {
            http_connect(host, *port, target_host, target_port).await
        }
        Upstream::Socks5 { host, port } => {
            socks5_connect(host, *port, target_host, target_port).await
        }
    }
}

async fn connect_proxy(host: &str, port: u16) -> Result<TcpStream, ProxyError> {
    TcpStream::connect((host, port))
        .await
        .map_err(|e| ProxyError::Upstream(format!("connecting to proxy {host}:{port}: {e}")))
}

/// HTTP `CONNECT target:port` → expects 2xx, then the stream is the tunnel.
async fn http_connect(
    phost: &str,
    pport: u16,
    thost: &str,
    tport: u16,
) -> Result<TcpStream, ProxyError> {
    let mut tcp = connect_proxy(phost, pport).await?;
    let req = format!("CONNECT {thost}:{tport} HTTP/1.1\r\nHost: {thost}:{tport}\r\n\r\n");
    tcp.write_all(req.as_bytes())
        .await
        .map_err(|e| ProxyError::Upstream(format!("CONNECT write: {e}")))?;

    // Read response headers up to CRLFCRLF (byte by byte — little data, the tunnel stays raw).
    let mut buf = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    loop {
        let n = tcp
            .read(&mut b)
            .await
            .map_err(|e| ProxyError::Upstream(format!("CONNECT read: {e}")))?;
        if n == 0 {
            return Err(ProxyError::Upstream(
                "proxy closed the connection during CONNECT".into(),
            ));
        }
        buf.push(b[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(ProxyError::Upstream(
                "CONNECT: proxy response too long".into(),
            ));
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status_ok = head
        .split_once("\r\n")
        .map(|(line, _)| line)
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .map(|c| (200..300).contains(&c))
        .unwrap_or(false);
    if !status_ok {
        let line = head.lines().next().unwrap_or("").to_owned();
        return Err(ProxyError::Upstream(format!(
            "CONNECT odrzucony przez proxy: {line}"
        )));
    }
    Ok(tcp)
}

/// SOCKS5 (no-auth) CONNECT with a domain address (socks5h — proxy-side DNS, good for Tor).
async fn socks5_connect(
    phost: &str,
    pport: u16,
    thost: &str,
    tport: u16,
) -> Result<TcpStream, ProxyError> {
    let mut tcp = connect_proxy(phost, pport).await?;
    // Greeting: VER=5, NMETHODS=1, METHOD=0 (no-auth).
    tcp.write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| ProxyError::Upstream(format!("socks greeting: {e}")))?;
    let mut m = [0u8; 2];
    tcp.read_exact(&mut m)
        .await
        .map_err(|e| ProxyError::Upstream(format!("socks method read: {e}")))?;
    if m[0] != 0x05 || m[1] != 0x00 {
        return Err(ProxyError::Upstream(format!(
            "socks: proxy nie akceptuje no-auth (ver={:#x} method={:#x})",
            m[0], m[1]
        )));
    }
    // CONNECT request: VER=5, CMD=1, RSV=0, ATYP=3(domain), LEN, domain, PORT(be).
    let host_bytes = thost.as_bytes();
    if host_bytes.len() > 255 {
        return Err(ProxyError::Upstream("socks: nazwa hosta > 255".into()));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&tport.to_be_bytes());
    tcp.write_all(&req)
        .await
        .map_err(|e| ProxyError::Upstream(format!("socks connect write: {e}")))?;

    // Response: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.
    let mut head = [0u8; 4];
    tcp.read_exact(&mut head)
        .await
        .map_err(|e| ProxyError::Upstream(format!("socks reply read: {e}")))?;
    if head[1] != 0x00 {
        return Err(ProxyError::Upstream(format!(
            "socks: CONNECT odrzucony (rep={:#x})",
            head[1]
        )));
    }
    // Consume BND.ADDR per ATYP + 2 port bytes.
    let addr_len = match head[3] {
        0x01 => 4,  // IPv4
        0x04 => 16, // IPv6
        0x03 => {
            let mut l = [0u8; 1];
            tcp.read_exact(&mut l)
                .await
                .map_err(|e| ProxyError::Upstream(format!("socks bnd len: {e}")))?;
            l[0] as usize
        }
        other => {
            return Err(ProxyError::Upstream(format!(
                "socks: nieznany ATYP {other:#x}"
            )))
        }
    };
    let mut skip = vec![0u8; addr_len + 2];
    tcp.read_exact(&mut skip)
        .await
        .map_err(|e| ProxyError::Upstream(format!("socks bnd addr: {e}")))?;
    Ok(tcp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_and_socks() {
        assert_eq!(
            Upstream::parse("http://127.0.0.1:8081"),
            Some(Upstream::HttpConnect {
                host: "127.0.0.1".into(),
                port: 8081
            })
        );
        assert_eq!(
            Upstream::parse("socks5://127.0.0.1:9050"),
            Some(Upstream::Socks5 {
                host: "127.0.0.1".into(),
                port: 9050
            })
        );
        assert_eq!(
            Upstream::parse("socks5h://tor:9050"),
            Some(Upstream::Socks5 {
                host: "tor".into(),
                port: 9050
            })
        );
        // no scheme → http
        assert_eq!(
            Upstream::parse("proxy:3128"),
            Some(Upstream::HttpConnect {
                host: "proxy".into(),
                port: 3128
            })
        );
    }

    #[test]
    fn parse_defaults_and_empty() {
        assert_eq!(Upstream::parse("  "), None);
        assert_eq!(
            Upstream::parse("http://host"),
            Some(Upstream::HttpConnect {
                host: "host".into(),
                port: 8080
            })
        );
        assert_eq!(
            Upstream::parse("socks5://host"),
            Some(Upstream::Socks5 {
                host: "host".into(),
                port: 1080
            })
        );
    }

    #[test]
    fn url_roundtrip() {
        assert_eq!(
            Upstream::parse("http://127.0.0.1:8081").unwrap().url(),
            "http://127.0.0.1:8081"
        );
        assert_eq!(
            Upstream::parse("socks5://127.0.0.1:9050").unwrap().url(),
            "socks5h://127.0.0.1:9050"
        );
    }

    #[test]
    fn ipv6_host_port() {
        assert_eq!(
            Upstream::parse("socks5://[::1]:9050"),
            Some(Upstream::Socks5 {
                host: "::1".into(),
                port: 9050
            })
        );
    }
}
