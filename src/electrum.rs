//! Electrum protocol client: newline-delimited JSON-RPC over TCP or TLS.
//!
//! One long-lived connection is shared by everything. It reconnects with
//! backoff; every successful (re)connection bumps `epoch` so that callers know
//! their subscriptions were lost and must be renewed.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, broadcast, mpsc, oneshot, watch};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{self, pki_types::ServerName};
use tracing::{debug, info, warn};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const WAIT_CONNECTED_TIMEOUT: Duration = Duration::from_secs(30);
const PING_INTERVAL: Duration = Duration::from_secs(60);
const MAX_IN_FLIGHT: usize = 48;

#[derive(Debug)]
pub enum ElectrumError {
    /// The server answered with a JSON-RPC error.
    Server(String),
    /// No answer: not connected, connection dropped, or timed out.
    Transport(String),
}

impl std::error::Error for ElectrumError {}

impl std::fmt::Display for ElectrumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ElectrumError::Server(m) => write!(f, "electrum server error: {m}"),
            ElectrumError::Transport(m) => write!(f, "electrum connection error: {m}"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ConnStatus {
    pub connected: bool,
    /// Incremented on every successful connection.
    pub epoch: u64,
    pub server_version: Option<String>,
    pub genesis_hash: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub method: String,
    pub params: Value,
}

type Pending = HashMap<u64, oneshot::Sender<Result<Value, ElectrumError>>>;

struct Inner {
    host: String,
    port: u16,
    tls: Option<(TlsConnector, ServerName<'static>)>,
    next_id: AtomicU64,
    pending: Mutex<Pending>,
    writer: Mutex<Option<mpsc::UnboundedSender<String>>>,
    status: watch::Sender<ConnStatus>,
    notifications: broadcast::Sender<Notification>,
    in_flight: Semaphore,
}

#[derive(Clone)]
pub struct ElectrumClient {
    inner: Arc<Inner>,
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

impl ElectrumClient {
    pub fn new(url: &str, ca_file: Option<&Path>, insecure: bool) -> anyhow::Result<Self> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| anyhow!("electrum URL must look like tcp://host:port or ssl://host:port"))?;
        let use_tls = match scheme {
            "tcp" => false,
            "ssl" | "tls" => true,
            other => bail!("unsupported electrum URL scheme '{other}' (use tcp or ssl)"),
        };
        let (host, port) = match rest.trim_end_matches('/').rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().context("invalid electrum port")?),
            None => (rest.to_string(), if use_tls { 50002 } else { 50001 }),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
        let tls = if use_tls {
            let config = tls_config(ca_file, insecure)?;
            let name = ServerName::try_from(host.clone()).context("invalid TLS server name")?;
            Some((TlsConnector::from(Arc::new(config)), name))
        } else {
            None
        };
        let (status, _) = watch::channel(ConnStatus::default());
        let (notifications, _) = broadcast::channel(4096);
        Ok(ElectrumClient {
            inner: Arc::new(Inner {
                host,
                port,
                tls,
                next_id: AtomicU64::new(1),
                pending: Mutex::new(HashMap::new()),
                writer: Mutex::new(None),
                status,
                notifications,
                in_flight: Semaphore::new(MAX_IN_FLIGHT),
            }),
        })
    }

    /// Display form of the server address, for the UI.
    pub fn endpoint(&self) -> String {
        let scheme = if self.inner.tls.is_some() { "ssl" } else { "tcp" };
        format!("{scheme}://{}:{}", self.inner.host, self.inner.port)
    }

    pub fn status(&self) -> watch::Receiver<ConnStatus> {
        self.inner.status.subscribe()
    }

    pub fn notifications(&self) -> broadcast::Receiver<Notification> {
        self.inner.notifications.subscribe()
    }

    /// Start the connection loop in the background.
    pub fn spawn(&self) {
        let this = self.clone();
        tokio::spawn(async move { this.run().await });
    }

    /// Send a request and wait for its result, waiting for a connection if needed.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, ElectrumError> {
        let mut status = self.status();
        let wait = status.wait_for(|s| s.connected);
        match tokio::time::timeout(WAIT_CONNECTED_TIMEOUT, wait).await {
            Ok(Ok(_)) => {}
            _ => return Err(ElectrumError::Transport("not connected".into())),
        }
        let _permit = self.inner.in_flight.acquire().await.expect("semaphore never closed");
        self.request(method, params).await
    }

    async fn request(&self, method: &str, params: Value) -> Result<Value, ElectrumError> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string() + "\n";
        let (tx, rx) = oneshot::channel();
        self.inner.pending.lock().unwrap().insert(id, tx);
        let sent = match &*self.inner.writer.lock().unwrap() {
            Some(w) => w.send(line).is_ok(),
            None => false,
        };
        if !sent {
            self.inner.pending.lock().unwrap().remove(&id);
            return Err(ElectrumError::Transport("not connected".into()));
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(ElectrumError::Transport("connection closed".into())),
            Err(_) => {
                self.inner.pending.lock().unwrap().remove(&id);
                Err(ElectrumError::Transport(format!("{method} timed out")))
            }
        }
    }

    async fn run(self) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let started = std::time::Instant::now();
            let err = match self.connect().await {
                Ok(stream) => self.session(stream).await,
                Err(e) => e,
            };
            *self.inner.writer.lock().unwrap() = None;
            for (_, tx) in self.inner.pending.lock().unwrap().drain() {
                let _ = tx.send(Err(ElectrumError::Transport("connection lost".into())));
            }
            warn!("electrum {}: {err:#}", self.endpoint());
            self.inner.status.send_modify(|s| {
                s.connected = false;
                s.last_error = Some(format!("{err:#}"));
            });
            if started.elapsed() > Duration::from_secs(60) {
                backoff = Duration::from_secs(1);
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }

    async fn connect(&self) -> anyhow::Result<Box<dyn Stream>> {
        let addr = (self.inner.host.as_str(), self.inner.port);
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .context("connect timed out")?
            .context("connect failed")?;
        tcp.set_nodelay(true).ok();
        match &self.inner.tls {
            None => Ok(Box::new(tcp)),
            Some((connector, name)) => {
                let tls = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name.clone(), tcp))
                    .await
                    .context("TLS handshake timed out")?
                    .context("TLS handshake failed")?;
                Ok(Box::new(tls))
            }
        }
    }

    /// Run one connection until it fails; returns the reason.
    async fn session(&self, stream: Box<dyn Stream>) -> anyhow::Error {
        let (read_half, mut write_half) = tokio::io::split(stream);
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        *self.inner.writer.lock().unwrap() = Some(tx);

        let writer = async move {
            while let Some(line) = rx.recv().await {
                write_half.write_all(line.as_bytes()).await?;
                write_half.flush().await?;
            }
            Ok::<_, std::io::Error>(())
        };

        let inner = self.inner.clone();
        let reader = async move {
            let mut lines = BufReader::with_capacity(1 << 16, read_half);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                if lines.read_until(b'\n', &mut buf).await? == 0 {
                    return Err(anyhow!("server closed the connection"));
                }
                match serde_json::from_slice::<Value>(&buf) {
                    Ok(Value::Array(msgs)) => msgs.into_iter().for_each(|m| dispatch(&inner, m)),
                    Ok(msg) => dispatch(&inner, msg),
                    Err(e) => debug!("ignoring unparsable message: {e}"),
                }
            }
            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        };

        let this = self.clone();
        let handshake_and_ping = async move {
            let version = this
                .request("server.version", json!([concat!("honeybee/", env!("CARGO_PKG_VERSION")), "1.4"]))
                .await
                .map_err(|e| anyhow!("handshake: {e}"))?;
            let server_version = version.get(0).and_then(Value::as_str).unwrap_or("unknown").to_string();
            let features = this.request("server.features", json!([])).await.unwrap_or(Value::Null);
            let genesis = features.get("genesis_hash").and_then(Value::as_str).map(str::to_string);
            info!("connected to {} ({server_version})", this.endpoint());
            this.inner.status.send_modify(|s| {
                s.connected = true;
                s.epoch += 1;
                s.server_version = Some(server_version);
                s.genesis_hash = genesis;
                s.last_error = None;
            });
            loop {
                tokio::time::sleep(PING_INTERVAL).await;
                this.request("server.ping", json!([])).await.map_err(|e| anyhow!("ping: {e}"))?;
            }
            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        };

        tokio::select! {
            r = writer => r.err().map(anyhow::Error::from).unwrap_or_else(|| anyhow!("writer stopped")),
            r = reader => r.err().unwrap_or_else(|| anyhow!("reader stopped")),
            r = handshake_and_ping => r.err().unwrap_or_else(|| anyhow!("ping loop stopped")),
        }
    }
}

fn dispatch(inner: &Inner, msg: Value) {
    if let Some(id) = msg.get("id").and_then(Value::as_u64) {
        let Some(tx) = inner.pending.lock().unwrap().remove(&id) else { return };
        let result = match msg.get("error") {
            Some(err) if !err.is_null() => {
                let text = err.get("message").and_then(Value::as_str).map(str::to_string);
                Err(ElectrumError::Server(text.unwrap_or_else(|| err.to_string())))
            }
            _ => Ok(msg.get("result").cloned().unwrap_or(Value::Null)),
        };
        let _ = tx.send(result);
    } else if let Some(method) = msg.get("method").and_then(Value::as_str) {
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let _ = inner.notifications.send(Notification { method: method.to_string(), params });
    }
}

fn tls_config(ca_file: Option<&Path>, insecure: bool) -> anyhow::Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder =
        rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()?;
    if insecure {
        warn!("TLS certificate verification for the electrum server is DISABLED");
        return Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth());
    }
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for e in &native.errors {
        warn!("loading system certificates: {e}");
    }
    roots.add_parsable_certificates(native.certs);
    if let Some(path) = ca_file {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let mut added = 0;
        for cert in CertificateDer::pem_file_iter(path).with_context(|| format!("reading {}", path.display()))? {
            roots.add(cert.context("parsing CA file")?)?;
            added += 1;
        }
        if added == 0 {
            bail!("no certificates found in {}", path.display());
        }
    }
    Ok(builder.with_root_certificates(roots).with_no_client_auth())
}

/// Accepts any server certificate (still checks handshake signatures).
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
