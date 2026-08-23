//! A local root CA + minting leaf certs on the fly and TLS configuration.
//! The root CA is generated once and kept on disk; the private key NEVER leaves the machine, and
//! the key file with restrictive permissions. For each target host we mint a leaf cert
//! signed by the root, cached by host name.
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::upstream::Upstream;
use crate::ProxyError;
use tokio::net::TcpStream;

/// Cap on the leaf-cert cache entries (host → ServerConfig). Protects against memory/CPU
/// exhaustion from forced minting for many unique hosts.
const MAX_LEAF_CACHE: usize = 1024;

const CA_KEY_FILE: &str = "weir-ca-key.pem";
const CA_CERT_PEM_FILE: &str = "weir-ca-cert.pem";
const CA_CERT_DER_FILE: &str = "weir-ca-cert.der";

/// TLS context: the root CA (to sign leaves), a per-host config cache and the upstream
/// TLS connector to targets. Shared by all connections (Arc).
pub struct TlsContext {
    issuer: Issuer<'static, KeyPair>,
    ca_cert_der: CertificateDer<'static>,
    ca_cert_pem: String,
    ca_cert_path: PathBuf,
    leaf_cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
    connector: TlsConnector,
    h2_connector: TlsConnector,
    /// Upstream proxy: when `Some`, ALL outbound connections (relay + raw-send) go through
    /// it (HTTP CONNECT / SOCKS5). Swappable at runtime — faces can set/clear it.
    upstream: RwLock<Option<Upstream>>,
}

impl TlsContext {
    /// Loads the root CA from `ca_dir`, or generates a new one on first run. `extra_roots`
    /// adds trust anchors for verifying targets (e.g. a self-signed target in a test, or pinning).
    pub fn new(
        ca_dir: impl AsRef<Path>,
        extra_roots: Vec<CertificateDer<'static>>,
    ) -> Result<Arc<Self>, ProxyError> {
        // Install a single process-wide default crypto provider (aws-lc-rs) for the whole process.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let dir = ca_dir.as_ref();
        fs::create_dir_all(dir).map_err(|source| ProxyError::CaIo {
            path: dir.display().to_string(),
            source,
        })?;
        // The CA dir holds the root private key — owner only (0700). `create_dir_all`
        // creates with umask (usually 0755, world-listable), so we tighten it afterward.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|source| {
                ProxyError::CaIo {
                    path: dir.display().to_string(),
                    source,
                }
            })?;
        }

        let key_path = dir.join(CA_KEY_FILE);
        let cert_pem_path = dir.join(CA_CERT_PEM_FILE);
        let cert_der_path = dir.join(CA_CERT_DER_FILE);

        let (issuer, ca_cert_der, ca_cert_pem) = if key_path.exists() && cert_der_path.exists() {
            load_ca(&key_path, &cert_pem_path, &cert_der_path)?
        } else {
            generate_ca(&key_path, &cert_pem_path, &cert_der_path)?
        };

        let connector = build_connector(&extra_roots, vec![b"http/1.1".to_vec()])?;
        // ALPN prefers h2, falling back to http/1.1 — for the single-packet path.
        let h2_connector =
            build_connector(&extra_roots, vec![b"h2".to_vec(), b"http/1.1".to_vec()])?;
        if !verify_upstream() {
            tracing::warn!(
                "upstream certificate verification is DISABLED — the intercepting proxy accepts any \
                 target cert (self-signed / private CA / incomplete chain). Set WEIR_VERIFY_UPSTREAM=1 \
                 to enforce strict verification."
            );
        }

        Ok(Arc::new(TlsContext {
            issuer,
            ca_cert_der,
            ca_cert_pem,
            ca_cert_path: cert_pem_path,
            leaf_cache: Mutex::new(HashMap::new()),
            connector,
            h2_connector,
            upstream: RwLock::new(None),
        }))
    }

    /// Root CA in PEM (to install in the browser/system).
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Path to the root CA file (PEM) — for the install message.
    pub fn ca_cert_path(&self) -> &Path {
        &self.ca_cert_path
    }

    /// Root CA in DER (a trust anchor for MITM clients, e.g. in tests).
    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_cert_der
    }

    /// TLS connector to targets (upstream), ALPN `http/1.1`.
    pub fn connector(&self) -> &TlsConnector {
        &self.connector
    }

    /// TLS connector with ALPN `h2` (fallback `http/1.1`) — for the single-packet race.
    pub fn h2_connector(&self) -> &TlsConnector {
        &self.h2_connector
    }

    /// Sets (or clears) the upstream proxy for ALL outbound connections.
    pub fn set_upstream(&self, up: Option<Upstream>) {
        *self.upstream.write().expect("upstream lock") = up;
    }

    /// The canonical URL of the configured upstream; `None` = direct connections.
    pub fn upstream_url(&self) -> Option<String> {
        self.upstream
            .read()
            .expect("upstream lock")
            .as_ref()
            .map(|u| u.url())
    }

    /// Opens TCP to `host:port` — directly or tunneled through the upstream proxy. All
    /// outbound paths (relay + raw-send) call this instead of `TcpStream::connect`, so the chain is
    /// uniform for all of weir's traffic.
    pub async fn dial(&self, host: &str, port: u16) -> Result<TcpStream, ProxyError> {
        let up = self.upstream.read().expect("upstream lock").clone();
        match up {
            None => TcpStream::connect((host, port))
                .await
                .map_err(|source| ProxyError::Connect {
                    host: host.to_owned(),
                    port,
                    source,
                }),
            Some(up) => crate::upstream::dial_through(&up, host, port).await,
        }
    }

    /// TLS server config with a leaf cert for `host` (minted on the fly, cached).
    pub fn leaf_config(&self, host: &str) -> Result<Arc<ServerConfig>, ProxyError> {
        if let Some(cfg) = self
            .leaf_cache
            .lock()
            .expect("leaf cache")
            .get(host)
            .cloned()
        {
            return Ok(cfg);
        }

        let leaf_key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_cert = params.signed_by(&leaf_key, &self.issuer)?;

        let leaf_der = leaf_cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf_der], key_der)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);

        {
            let mut cache = self.leaf_cache.lock().expect("leaf cache");
            // Memory/CPU limiter: a hostile site visited by the operator could force minting
            // for thousands of unique subdomains (each = a P-256 keygen + a persistent cache entry). Over
            // the cap we clear the whole cache (lazy re-minting) — simple, without an
            // LRU dependency. The cap is high, so normal browsing never hits it.
            if cache.len() >= MAX_LEAF_CACHE && !cache.contains_key(host) {
                cache.clear();
            }
            cache.insert(host.to_owned(), cfg.clone());
        }
        Ok(cfg)
    }
}

/// Root CA parameters — deterministic, so after loading from disk the `Issuer` can be reconstructed
/// without parsing the cert (the same DN and key usages as at generation).
fn ca_params() -> Result<CertificateParams, ProxyError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "weir local CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "weir");
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    Ok(params)
}

fn generate_ca(
    key_path: &Path,
    cert_pem_path: &Path,
    cert_der_path: &Path,
) -> Result<(Issuer<'static, KeyPair>, CertificateDer<'static>, String), ProxyError> {
    let ca_key = KeyPair::generate()?;
    let params = ca_params()?;
    let ca_cert = params.self_signed(&ca_key)?;

    let ca_cert_pem = ca_cert.pem();
    let ca_cert_der = ca_cert.der().clone();

    write_private(key_path, ca_key.serialize_pem().as_bytes())?;
    write_file(cert_pem_path, ca_cert_pem.as_bytes())?;
    write_file(cert_der_path, ca_cert_der.as_ref())?;

    tracing::info!(cert = %cert_pem_path.display(), "generated a new weir root CA");
    let issuer = Issuer::new(params, ca_key);
    Ok((issuer, ca_cert_der, ca_cert_pem))
}

fn load_ca(
    key_path: &Path,
    cert_pem_path: &Path,
    cert_der_path: &Path,
) -> Result<(Issuer<'static, KeyPair>, CertificateDer<'static>, String), ProxyError> {
    let key_pem = read_file(key_path)?;
    let ca_key = KeyPair::from_pem(&key_pem)?;
    let der_bytes = fs::read(cert_der_path).map_err(|source| ProxyError::CaIo {
        path: cert_der_path.display().to_string(),
        source,
    })?;
    let ca_cert_der = CertificateDer::from(der_bytes);
    // The cert PEM is only for display/install — if missing, reconstruct from DER? We keep the PEM.
    let ca_cert_pem = read_file(cert_pem_path).unwrap_or_default();

    let issuer = Issuer::new(ca_params()?, ca_key);
    Ok((issuer, ca_cert_der, ca_cert_pem))
}

/// TLS connector to targets: anchors from webpki-roots + optional `extra_roots`,
/// with the given ALPN (`http/1.1` for the polite/raw path, `h2` for single-packet).
fn build_connector(
    extra_roots: &[CertificateDer<'static>],
    alpn: Vec<Vec<u8>>,
) -> Result<TlsConnector, ProxyError> {
    let mut cfg = if verify_upstream() {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for extra in extra_roots {
            roots.add(extra.clone())?;
        }
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        // Intercepting proxy: by default we do NOT verify the target cert (like Burp/Caido).
        // Pentest/CTF targets routinely use a self-signed cert, a private CA, or send an
        // incomplete chain — strict verification would make the tool unusable. We still verify the
        // handshake signature (the peer must hold the presented cert's key); only the trust chain
        // is skipped.
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert::new()))
            .with_no_client_auth()
    };
    cfg.alpn_protocols = alpn;
    Ok(TlsConnector::from(Arc::new(cfg)))
}

/// Whether to verify the target (upstream) cert. Default is NO (intercepting proxy);
/// `WEIR_VERIFY_UPSTREAM=1` turns on strict webpki verification for those who want it.
fn verify_upstream() -> bool {
    std::env::var("WEIR_VERIFY_UPSTREAM")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Verifier that accepts any server cert (skips the trust chain) but still checks the handshake
/// signature against the presented cert — the standard "dangerously accept invalid certs" pattern
/// for an intercepting proxy. Signatures are checked with the aws-lc-rs provider (consistent with
/// the rest).
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl AcceptAnyServerCert {
    fn new() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        }
    }
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// SNI name for the upstream target.
pub(crate) fn server_name(host: &str) -> Result<ServerName<'static>, ProxyError> {
    ServerName::try_from(host.to_owned())
        .map_err(|_| ProxyError::BadRequest(format!("bad host name (SNI): {host}")))
}

fn read_file(path: &Path) -> Result<String, ProxyError> {
    fs::read_to_string(path).map_err(|source| ProxyError::CaIo {
        path: path.display().to_string(),
        source,
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), ProxyError> {
    fs::write(path, bytes).map_err(|source| ProxyError::CaIo {
        path: path.display().to_string(),
        source,
    })
}

/// Writes the root private-key file with restrictive permissions (0600 on unix).
///
/// On unix we create the file ATOMICALLY with mode 0600 before any bytes go in — `fs::write`
/// would first create it with umask (usually 0644, world-readable) and `set_permissions` would
/// tighten it only AFTER writing: between those steps the root key would sit on disk readable by
/// every local user (TOCTOU). `create_new` also refuses to overwrite.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ProxyError> {
    #[cfg(unix)]
    let result = {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|source| ProxyError::CaIo {
                path: path.display().to_string(),
                source,
            })?;
        file.write_all(bytes).map_err(|source| ProxyError::CaIo {
            path: path.display().to_string(),
            source,
        })
    };
    // On non-unix there is no POSIX mode — a plain write; owner ACLs must be added separately.
    #[cfg(not(unix))]
    let result = write_file(path, bytes);
    result
}
