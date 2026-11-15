//! Hysteria2 client: TCP connections carried over QUIC (TLS 1.3).
//!
//! Protocol (https://v2.hysteria.network/docs/developers/Protocol/):
//! 1. QUIC + TLS with ALPN `h3`.
//! 2. HTTP/3 `POST https://hysteria/auth` with `Hysteria-Auth` (password),
//!    `Hysteria-CC-RX` (our receive rate, bytes/s, 0 = unknown) and
//!    `Hysteria-Padding`. Status 233 means authenticated.
//! 3. Each TCP connection is a new bidirectional QUIC stream starting with
//!    varint 0x401, varint length + `host:port`, varint length + padding. The
//!    server answers u8 status (0 = OK), varint length + message, varint
//!    length + padding, then relays raw bytes.
//!
//! The server certificate is checked against a pinned SHA-256 or the web PKI;
//! skipping verification is possible but explicit.
//!
//! The [`tuic`] module is the TUIC v5 client, on the same QUIC settings.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use bytes::Bytes;
use rand_core::{OsRng, RngCore};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

pub mod tuic;

const TCP_REQUEST_ID: u64 = 0x401;
const AUTH_STATUS_OK: u16 = 233;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// How the server certificate is checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertCheck {
    /// Normal web PKI validation of `server_name`.
    WebPki,
    /// Accept exactly the certificate with this SHA-256 (self-signed servers).
    PinSha256([u8; 32]),
    /// Accept any certificate. The connection is encrypted but not
    /// authenticated: anyone on the path could impersonate the server.
    Insecure,
}

#[derive(Clone, Debug)]
pub struct Hy2Config {
    pub server: SocketAddr,
    /// TLS server name (SNI); also checked by `CertCheck::WebPki`.
    pub server_name: String,
    pub password: String,
    pub cert: CertCheck,
    /// Our download capacity in Mbit/s, sent as `Hysteria-CC-RX`. With 0 the
    /// server uses a standard congestion controller (BBR).
    pub down_mbps: u32,
}

/// One authenticated QUIC connection, reused for every TCP stream.
struct Session {
    conn: quinn::Connection,
    /// Present when the server relays UDP (`Hysteria-UDP: true`).
    udp: Option<Arc<UdpDemux>>,
    /// Keeps the HTTP/3 layer alive: dropping the last handle closes the
    /// connection.
    _h3: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    _driver: tokio::task::JoinHandle<()>,
}

pub struct Hy2Client {
    cfg: Hy2Config,
    endpoint: quinn::Endpoint,
    session: Mutex<Option<Session>>,
}

impl Hy2Client {
    pub fn new(cfg: Hy2Config) -> Result<Self> {
        let bind: SocketAddr = if cfg.server.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
        // Pinned to the physical interface while TUN mode is on.
        let socket = supernet_netstack::sysnet::udp_bind(bind).context("创建 QUIC 端点")?;
        let mut endpoint =
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, Arc::new(quinn::TokioRuntime)).context("创建 QUIC 端点")?;
        endpoint.set_default_client_config(client_config(&cfg.cert)?);
        Ok(Self { cfg, endpoint, session: Mutex::new(None) })
    }

    /// Open a TCP connection to `target` (`host:port`) through the server.
    pub async fn connect_tcp(&self, target: &str) -> Result<Hy2Stream> {
        let conn = self.connection().await?;
        let opened = tokio::time::timeout(HANDSHAKE_TIMEOUT, open_tcp(&conn, target)).await;
        match opened {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => {
                // A broken connection is replaced on the next call.
                if conn.close_reason().is_some() {
                    self.session.lock().await.take();
                }
                Err(e)
            }
            Err(_) => bail!("Hysteria2 连接 {target} 超时"),
        }
    }

    /// Start a UDP session relayed by the server.
    pub async fn udp_session(&self) -> Result<Hy2Udp> {
        let (conn, demux) = self.connection_with_udp().await?;
        let demux = demux.context("服务器未开启 UDP 转发")?;
        let max = conn.max_datagram_size().context("服务器不支持 QUIC 数据报，无法转发 UDP")?;
        let (id, rx) = demux.register();
        Ok(Hy2Udp { conn, demux, id, rx, max, next_packet: std::sync::atomic::AtomicU16::new(0) })
    }

    /// The current QUIC connection, (re)connecting and authenticating if needed.
    async fn connection(&self) -> Result<quinn::Connection> {
        Ok(self.connection_with_udp().await?.0)
    }

    async fn connection_with_udp(&self) -> Result<(quinn::Connection, Option<Arc<UdpDemux>>)> {
        let mut session = self.session.lock().await;
        if let Some(s) = session.as_ref() {
            if s.conn.close_reason().is_none() {
                return Ok((s.conn.clone(), s.udp.clone()));
            }
        }
        let fresh = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.handshake())
            .await
            .map_err(|_| anyhow::anyhow!("Hysteria2 握手超时（{}）", self.cfg.server))??;
        let out = (fresh.conn.clone(), fresh.udp.clone());
        *session = Some(fresh);
        Ok(out)
    }

    async fn handshake(&self) -> Result<Session> {
        let conn = self
            .endpoint
            .connect(self.cfg.server, &self.cfg.server_name)?
            .await
            .with_context(|| format!("QUIC 连接 {}", self.cfg.server))?;
        let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .context("建立 HTTP/3")?;
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let rx = u64::from(self.cfg.down_mbps) * 1_000_000 / 8;
        let request = http::Request::post("https://hysteria/auth")
            .header("Hysteria-Auth", &self.cfg.password)
            .header("Hysteria-CC-RX", rx.to_string())
            .header("Hysteria-Padding", padding(256))
            .body(())?;
        let mut stream = send.send_request(request).await.context("发送认证请求")?;
        stream.finish().await.context("发送认证请求")?;
        let response = stream.recv_response().await.context("读取认证结果")?;
        if response.status().as_u16() != AUTH_STATUS_OK {
            conn.close(0u32.into(), b"");
            bail!("Hysteria2 认证失败（服务器返回 HTTP {}），请检查密码", response.status().as_u16());
        }
        let udp_enabled = response
            .headers()
            .get("Hysteria-UDP")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        let udp = udp_enabled.then(|| UdpDemux::start(conn.clone()));
        tracing::info!("hysteria2: authenticated to {} (udp: {udp_enabled})", self.cfg.server);
        Ok(Session { conn, udp, _h3: send, _driver: driver })
    }

    /// Round-trip time of the current connection, if there is one.
    pub async fn rtt(&self) -> Option<Duration> {
        self.session.lock().await.as_ref().map(|s| s.conn.rtt())
    }
}

/// Routes incoming UDP datagrams to their session and reassembles fragments.
struct UdpDemux {
    sessions: std::sync::Mutex<std::collections::HashMap<u32, tokio::sync::mpsc::Sender<(String, Vec<u8>)>>>,
    next_id: std::sync::atomic::AtomicU32,
    task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

struct Partial {
    parts: Vec<Option<Vec<u8>>>,
    addr: String,
    since: std::time::Instant,
}

impl UdpDemux {
    fn start(conn: quinn::Connection) -> Arc<UdpDemux> {
        let demux = Arc::new(UdpDemux {
            sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
            next_id: std::sync::atomic::AtomicU32::new(OsRng.next_u32() & 0x7FFF_FFFF),
            task: std::sync::Mutex::new(None),
        });
        let weak = Arc::downgrade(&demux);
        let task = tokio::spawn(async move {
            let mut partials: std::collections::HashMap<(u32, u16), Partial> = std::collections::HashMap::new();
            while let Ok(datagram) = conn.read_datagram().await {
                let Some(demux) = weak.upgrade() else { break };
                let Some(msg) = parse_udp_message(&datagram) else { continue };
                let whole = if msg.frag_count <= 1 {
                    Some((msg.addr, msg.payload.to_vec()))
                } else {
                    partials.retain(|_, p| p.since.elapsed() < Duration::from_secs(5));
                    let entry = partials.entry((msg.session, msg.packet)).or_insert_with(|| Partial {
                        parts: vec![None; msg.frag_count as usize],
                        addr: msg.addr.clone(),
                        since: std::time::Instant::now(),
                    });
                    if let Some(slot) = entry.parts.get_mut(msg.frag_id as usize) {
                        *slot = Some(msg.payload.to_vec());
                    }
                    if entry.parts.iter().all(Option::is_some) {
                        let p = partials.remove(&(msg.session, msg.packet)).expect("present");
                        Some((p.addr, p.parts.into_iter().flatten().flatten().collect()))
                    } else {
                        None
                    }
                };
                if let Some(packet) = whole {
                    let tx = demux.sessions.lock().unwrap_or_else(|e| e.into_inner()).get(&msg.session).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.try_send(packet);
                    }
                }
            }
        });
        *demux.task.lock().unwrap_or_else(|e| e.into_inner()) = Some(task);
        demux
    }

    fn register(&self) -> (u32, tokio::sync::mpsc::Receiver<(String, Vec<u8>)>) {
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).insert(id, tx);
        (id, rx)
    }

    fn unregister(&self, id: u32) {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    }
}

impl Drop for UdpDemux {
    fn drop(&mut self) {
        if let Some(t) = self.task.lock().unwrap_or_else(|e| e.into_inner()).take() {
            t.abort();
        }
    }
}

struct UdpMessage<'a> {
    session: u32,
    packet: u16,
    frag_id: u8,
    frag_count: u8,
    addr: String,
    payload: &'a [u8],
}

/// session u32, packet u16, fragment id u8, fragment count u8,
/// varint address length, address, payload.
fn parse_udp_message(b: &[u8]) -> Option<UdpMessage<'_>> {
    let session = u32::from_be_bytes(b.get(0..4)?.try_into().ok()?);
    let packet = u16::from_be_bytes(b.get(4..6)?.try_into().ok()?);
    let frag_id = *b.get(6)?;
    let frag_count = *b.get(7)?;
    let (addr_len, used) = varint_from_slice(b.get(8..)?)?;
    let start = 8 + used;
    let end = start.checked_add(addr_len as usize)?;
    let addr = String::from_utf8(b.get(start..end)?.to_vec()).ok()?;
    Some(UdpMessage { session, packet, frag_id, frag_count, addr, payload: b.get(end..)? })
}

fn varint_from_slice(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    let mut v = u64::from(first & 0x3F);
    for i in 1..len {
        v = (v << 8) | u64::from(*b.get(i)?);
    }
    Some((v, len))
}

/// A UDP session through a Hysteria2 server. Addresses are `host:port`.
pub struct Hy2Udp {
    conn: quinn::Connection,
    demux: Arc<UdpDemux>,
    id: u32,
    rx: tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    max: usize,
    next_packet: std::sync::atomic::AtomicU16,
}

impl Hy2Udp {
    pub fn send_to(&self, payload: &[u8], addr: &str) -> Result<()> {
        let packet = self.next_packet.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut header = Vec::with_capacity(16 + addr.len());
        header.extend_from_slice(&self.id.to_be_bytes());
        header.extend_from_slice(&packet.to_be_bytes());
        header.extend_from_slice(&[0, 0]); // fragment id / count, filled per piece
        put_varint(&mut header, addr.len() as u64);
        header.extend_from_slice(addr.as_bytes());
        let room = self.max.checked_sub(header.len()).filter(|r| *r > 0).context("地址过长")?;
        let pieces: Vec<&[u8]> = if payload.is_empty() { vec![&[][..]] } else { payload.chunks(room).collect() };
        if pieces.len() > 255 {
            bail!("UDP 包过大");
        }
        for (i, piece) in pieces.iter().enumerate() {
            let mut msg = header.clone();
            msg[6] = i as u8;
            msg[7] = pieces.len() as u8;
            msg.extend_from_slice(piece);
            self.conn.send_datagram(Bytes::from(msg)).context("发送 UDP 数据报")?;
        }
        Ok(())
    }

    /// Next datagram from the server: (payload, source `host:port`).
    pub async fn recv_from(&mut self) -> Option<(Vec<u8>, String)> {
        self.rx.recv().await.map(|(addr, data)| (data, addr))
    }
}

impl Drop for Hy2Udp {
    fn drop(&mut self) {
        self.demux.unregister(self.id);
    }
}

async fn open_tcp(conn: &quinn::Connection, target: &str) -> Result<Hy2Stream> {
    let (mut send, mut recv) = conn.open_bi().await.context("打开 QUIC 流")?;
    let pad = padding(64);
    let mut request = Vec::with_capacity(16 + target.len() + pad.len());
    put_varint(&mut request, TCP_REQUEST_ID);
    put_varint(&mut request, target.len() as u64);
    request.extend_from_slice(target.as_bytes());
    put_varint(&mut request, pad.len() as u64);
    request.extend_from_slice(pad.as_bytes());
    send.write_all(&request).await.context("发送连接请求")?;

    let status = recv.read_u8().await.context("读取连接结果")?;
    let msg_len = read_varint(&mut recv).await?;
    if msg_len > 4096 {
        bail!("服务器回复格式错误");
    }
    let mut msg = vec![0u8; msg_len as usize];
    recv.read_exact(&mut msg).await?;
    let pad_len = read_varint(&mut recv).await?;
    if pad_len > 65_536 {
        bail!("服务器回复格式错误");
    }
    let mut pad = vec![0u8; pad_len as usize];
    recv.read_exact(&mut pad).await?;
    if status != 0 {
        bail!("服务器无法连接 {target}：{}", String::from_utf8_lossy(&msg));
    }
    Ok(Hy2Stream { send, recv })
}

/// A TCP connection carried by one QUIC stream.
pub struct Hy2Stream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for Hy2Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hy2Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, data).map_err(io::Error::from)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// QUIC client settings shared by Hysteria2 and TUIC: TLS 1.3, ALPN `h3`,
/// the certificate check, large windows and BBR.
pub(crate) fn client_config(cert: &CertCheck) -> Result<quinn::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 配置")?;
    let mut tls = match cert {
        CertCheck::WebPki => {
            let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        CertCheck::PinSha256(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned { pin: Some(*pin), provider }))
            .with_no_client_auth(),
        CertCheck::Insecure => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned { pin: None, provider }))
            .with_no_client_auth(),
    };
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).context("QUIC TLS 配置")?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .max_idle_timeout(Some(Duration::from_secs(30).try_into()?))
        // Long, lossy paths need large windows to keep data in flight.
        .stream_receive_window(quinn::VarInt::from_u32(8 * 1024 * 1024))
        .receive_window(quinn::VarInt::from_u32(20 * 1024 * 1024))
        .send_window(16 * 1024 * 1024)
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    client.transport_config(Arc::new(transport));
    Ok(client)
}

/// Certificate check by SHA-256 pin (`pin: Some`) or no check (`pin: None`).
/// Handshake signatures are still verified, so the server must hold the key.
#[derive(Debug)]
struct Pinned {
    pin: Option<[u8; 32]>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.pin {
            None => Ok(ServerCertVerified::assertion()),
            Some(pin) if Sha256::digest(end_entity.as_ref()).as_slice() == pin => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::General("服务器证书与固定的 SHA-256 不符".into())),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Fetch the server's certificate SHA-256 (trust on first use, for pinning).
pub async fn fetch_cert_sha256(server: SocketAddr, server_name: &str) -> Result<[u8; 32]> {
    #[derive(Debug)]
    struct Capture(std::sync::Mutex<Option<[u8; 32]>>, Arc<rustls::crypto::CryptoProvider>);
    impl ServerCertVerifier for Capture {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            *self.0.lock().unwrap() = Some(Sha256::digest(end_entity.as_ref()).into());
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(m, c, d, &self.1.signature_verification_algorithms)
        }
        fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(m, c, d, &self.1.signature_verification_algorithms)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.1.signature_verification_algorithms.supported_schemes()
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let capture = Arc::new(Capture(std::sync::Mutex::new(None), provider.clone()));
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(capture.clone())
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let bind: SocketAddr = if server.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls)?)));
    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, endpoint.connect(server, server_name)?)
        .await
        .context("连接超时")?
        .context("QUIC 握手")?;
    conn.close(0u32.into(), b"");
    let digest = capture.0.lock().unwrap().context("服务器没有提供证书")?;
    Ok(digest)
}

fn padding(max: usize) -> String {
    let len = 16 + (OsRng.next_u32() as usize % max.max(1));
    (0..len).map(|_| char::from(b'a' + (OsRng.next_u32() % 26) as u8)).collect()
}

fn put_varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=63 => out.push(v as u8),
        64..=16_383 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        16_384..=1_073_741_823 => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes()),
    }
}

async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> Result<u64> {
    let first = r.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut v = u64::from(first & 0x3F);
    for _ in 1..len {
        v = (v << 8) | u64::from(r.read_u8().await?);
    }
    Ok(v)
}

/// Lower-case hex of a SHA-256, as used in share links.
pub fn hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a 64-hex-digit SHA-256 (colons allowed).
pub fn parse_hex_sha256(s: &str) -> Result<[u8; 32]> {
    let clean: String = s.chars().filter(|c| *c != ':').collect();
    if clean.len() != 64 {
        bail!("证书指纹应为 64 位十六进制");
    }
    let mut out = [0u8; 32];
    for (i, chunk) in clean.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16).context("证书指纹应为十六进制")?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
