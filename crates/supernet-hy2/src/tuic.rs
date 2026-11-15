//! TUIC v5 client (https://github.com/tuic-protocol/tuic/blob/dev/SPEC.md).
//!
//! Over one QUIC connection (TLS 1.3, ALPN `h3`):
//! - `Authenticate` on a unidirectional stream: UUID and a 32-byte token,
//!   the TLS keying material exported with the UUID as label and the
//!   password as context. The password itself is never sent.
//! - `Connect` opens a bidirectional stream per TCP connection: the header,
//!   then raw bytes both ways.
//! - UDP in "native" mode: `Packet` commands as QUIC datagrams, fragmented
//!   when larger than a datagram; `Dissociate` ends an association.
//! - `Heartbeat` datagrams keep the relay alive while UDP is in use.
//!
//! Every command starts with version 0x05 and the command type. Addresses:
//! type (0xff none, 0x00 domain, 0x01 IPv4, 0x02 IPv6), the address (a
//! domain is length-prefixed), port (big-endian).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use bytes::Bytes;
use tokio::sync::{mpsc, Mutex};

use crate::{client_config, CertCheck, Hy2Stream, HANDSHAKE_TIMEOUT};

const VERSION: u8 = 0x05;
const CMD_AUTHENTICATE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_PACKET: u8 = 0x02;
const CMD_DISSOCIATE: u8 = 0x03;
const CMD_HEARTBEAT: u8 = 0x04;
const HEARTBEAT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct TuicConfig {
    pub server: SocketAddr,
    /// TLS server name (SNI); also checked by `CertCheck::WebPki`.
    pub server_name: String,
    pub uuid: [u8; 16],
    pub password: String,
    pub cert: CertCheck,
}

/// Parse `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
pub fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || s.len() != 36 {
        bail!("UUID 格式不对（应为 8-4-4-4-12 位十六进制）");
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16).context("UUID 应为十六进制")?;
    }
    Ok(out)
}

struct Session {
    conn: quinn::Connection,
    udp: Arc<Demux>,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        for t in &self._tasks {
            t.abort();
        }
    }
}

pub struct TuicClient {
    cfg: TuicConfig,
    endpoint: quinn::Endpoint,
    session: Mutex<Option<Session>>,
}

impl TuicClient {
    pub fn new(cfg: TuicConfig) -> Result<Self> {
        let bind: SocketAddr = if cfg.server.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
        // Pinned to the physical interface while TUN mode is on.
        let socket = supernet_netstack::sysnet::udp_bind(bind).context("创建 QUIC 端点")?;
        let mut endpoint =
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, Arc::new(quinn::TokioRuntime)).context("创建 QUIC 端点")?;
        endpoint.set_default_client_config(client_config(&cfg.cert)?);
        Ok(Self { cfg, endpoint, session: Mutex::new(None) })
    }

    /// Open a TCP connection to `target` (`host:port`) through the server.
    /// TUIC has no reply: a refused target shows up as the stream ending.
    pub async fn connect_tcp(&self, target: &str) -> Result<Hy2Stream> {
        let (conn, _) = self.connection().await?;
        let mut header = vec![VERSION, CMD_CONNECT];
        put_addr(&mut header, target)?;
        let opened = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let (mut send, recv) = conn.open_bi().await.context("打开 QUIC 流")?;
            send.write_all(&header).await.context("发送连接请求")?;
            anyhow::Ok(Hy2Stream { send, recv })
        })
        .await;
        match opened {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => {
                if conn.close_reason().is_some() {
                    self.session.lock().await.take();
                }
                Err(e)
            }
            Err(_) => bail!("TUIC 连接 {target} 超时"),
        }
    }

    /// Start a UDP association relayed by the server.
    pub async fn udp_session(&self) -> Result<TuicUdp> {
        let (conn, demux) = self.connection().await?;
        let max = conn.max_datagram_size().context("服务器不支持 QUIC 数据报，无法转发 UDP")?;
        let (assoc, rx) = demux.register();
        Ok(TuicUdp { conn, demux, assoc, rx, max, next_packet: AtomicU16::new(0) })
    }

    /// Round-trip time of the current connection, if there is one.
    pub async fn rtt(&self) -> Option<Duration> {
        self.session.lock().await.as_ref().map(|s| s.conn.rtt())
    }

    async fn connection(&self) -> Result<(quinn::Connection, Arc<Demux>)> {
        let mut session = self.session.lock().await;
        if let Some(s) = session.as_ref() {
            if s.conn.close_reason().is_none() {
                return Ok((s.conn.clone(), s.udp.clone()));
            }
        }
        let fresh = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.handshake())
            .await
            .map_err(|_| anyhow::anyhow!("TUIC 握手超时（{}）", self.cfg.server))??;
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
        let mut token = [0u8; 32];
        conn.export_keying_material(&mut token, &self.cfg.uuid, self.cfg.password.as_bytes())
            .map_err(|_| anyhow::anyhow!("导出 TLS 密钥材料失败"))?;
        let mut auth = Vec::with_capacity(2 + 16 + 32);
        auth.extend_from_slice(&[VERSION, CMD_AUTHENTICATE]);
        auth.extend_from_slice(&self.cfg.uuid);
        auth.extend_from_slice(&token);
        let mut uni = conn.open_uni().await.context("打开认证流")?;
        uni.write_all(&auth).await.context("发送认证")?;
        let _ = uni.finish();

        let udp = Demux::start(conn.clone());
        // Keeps UDP associations alive on the server while any exist.
        let heartbeat = {
            let conn = conn.clone();
            let demux = Arc::downgrade(&udp);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(HEARTBEAT).await;
                    let Some(d) = demux.upgrade() else { break };
                    if d.active() && conn.send_datagram(Bytes::from_static(&[VERSION, CMD_HEARTBEAT])).is_err() {
                        break;
                    }
                }
            })
        };
        tracing::info!("tuic: connected to {}", self.cfg.server);
        let reader = udp.task.lock().unwrap_or_else(|e| e.into_inner()).take();
        Ok(Session { conn, udp, _tasks: reader.into_iter().chain([heartbeat]).collect() })
    }
}

/// A UDP association through a TUIC server. Addresses are `host:port`.
pub struct TuicUdp {
    conn: quinn::Connection,
    demux: Arc<Demux>,
    assoc: u16,
    rx: mpsc::Receiver<(String, Vec<u8>)>,
    max: usize,
    next_packet: AtomicU16,
}

impl TuicUdp {
    pub fn send_to(&self, payload: &[u8], addr: &str) -> Result<()> {
        let packet = self.next_packet.fetch_add(1, Ordering::Relaxed);
        let mut addr_bytes = Vec::new();
        put_addr(&mut addr_bytes, addr)?;
        // Header without the address: VER TYPE ASSOC PKT TOTAL ID SIZE.
        let fixed = 2 + 2 + 2 + 1 + 1 + 2;
        let first_room = self.max.checked_sub(fixed + addr_bytes.len()).filter(|r| *r > 0).context("地址过长")?;
        let rest_room = self.max - fixed - 1; // later fragments carry "no address"
        let mut pieces: Vec<&[u8]> = Vec::new();
        let (first, mut rest) = payload.split_at(payload.len().min(first_room));
        pieces.push(first);
        while !rest.is_empty() {
            let (p, r) = rest.split_at(rest.len().min(rest_room));
            pieces.push(p);
            rest = r;
        }
        if pieces.len() > 255 {
            bail!("UDP 包过大");
        }
        for (i, piece) in pieces.iter().enumerate() {
            let mut msg = Vec::with_capacity(fixed + addr_bytes.len() + piece.len());
            msg.extend_from_slice(&[VERSION, CMD_PACKET]);
            msg.extend_from_slice(&self.assoc.to_be_bytes());
            msg.extend_from_slice(&packet.to_be_bytes());
            msg.push(pieces.len() as u8);
            msg.push(i as u8);
            msg.extend_from_slice(&(piece.len() as u16).to_be_bytes());
            if i == 0 {
                msg.extend_from_slice(&addr_bytes);
            } else {
                msg.push(0xff);
            }
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

impl Drop for TuicUdp {
    fn drop(&mut self) {
        self.demux.unregister(self.assoc);
        // Tell the server to drop the association (best effort).
        let conn = self.conn.clone();
        let assoc = self.assoc;
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                if let Ok(mut uni) = conn.open_uni().await {
                    let mut msg = vec![VERSION, CMD_DISSOCIATE];
                    msg.extend_from_slice(&assoc.to_be_bytes());
                    let _ = uni.write_all(&msg).await;
                    let _ = uni.finish();
                }
            });
        }
    }
}

struct Partial {
    parts: Vec<Option<Vec<u8>>>,
    addr: Option<String>,
    since: Instant,
}

/// Routes incoming `Packet` datagrams to their association and reassembles fragments.
struct Demux {
    sessions: StdMutex<HashMap<u16, mpsc::Sender<(String, Vec<u8>)>>>,
    next: AtomicU16,
    task: StdMutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Demux {
    fn start(conn: quinn::Connection) -> Arc<Demux> {
        let mut seed = [0u8; 2];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
        let demux = Arc::new(Demux { sessions: StdMutex::new(HashMap::new()), next: AtomicU16::new(u16::from_be_bytes(seed)), task: StdMutex::new(None) });
        let weak: Weak<Demux> = Arc::downgrade(&demux);
        let task = tokio::spawn(async move {
            let mut partials: HashMap<(u16, u16), Partial> = HashMap::new();
            while let Ok(d) = conn.read_datagram().await {
                let Some(demux) = weak.upgrade() else { break };
                let Some(p) = parse_packet(&d) else { continue };
                let whole = if p.total <= 1 {
                    p.addr.map(|a| (a, p.payload.to_vec()))
                } else {
                    partials.retain(|_, x| x.since.elapsed() < Duration::from_secs(5));
                    let e = partials.entry((p.assoc, p.packet)).or_insert_with(|| Partial {
                        parts: vec![None; p.total as usize],
                        addr: None,
                        since: Instant::now(),
                    });
                    if p.addr.is_some() {
                        e.addr = p.addr.clone();
                    }
                    if let Some(slot) = e.parts.get_mut(p.id as usize) {
                        *slot = Some(p.payload.to_vec());
                    }
                    if e.parts.iter().all(Option::is_some) && e.addr.is_some() {
                        let x = partials.remove(&(p.assoc, p.packet)).expect("present");
                        Some((x.addr.unwrap_or_default(), x.parts.into_iter().flatten().flatten().collect()))
                    } else {
                        None
                    }
                };
                if let Some(packet) = whole {
                    let tx = demux.sessions.lock().unwrap_or_else(|e| e.into_inner()).get(&p.assoc).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.try_send(packet);
                    }
                }
            }
        });
        *demux.task.lock().unwrap_or_else(|e| e.into_inner()) = Some(task);
        demux
    }

    fn register(&self) -> (u16, mpsc::Receiver<(String, Vec<u8>)>) {
        let (tx, rx) = mpsc::channel(256);
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let id = loop {
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            if !sessions.contains_key(&id) {
                break id;
            }
        };
        sessions.insert(id, tx);
        (id, rx)
    }

    fn unregister(&self, id: u16) {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    }

    fn active(&self) -> bool {
        !self.sessions.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
    }
}

struct Packet<'a> {
    assoc: u16,
    packet: u16,
    total: u8,
    id: u8,
    addr: Option<String>,
    payload: &'a [u8],
}

fn parse_packet(b: &[u8]) -> Option<Packet<'_>> {
    if *b.first()? != VERSION || *b.get(1)? != CMD_PACKET {
        return None; // heartbeats and anything else
    }
    let assoc = u16::from_be_bytes(b.get(2..4)?.try_into().ok()?);
    let packet = u16::from_be_bytes(b.get(4..6)?.try_into().ok()?);
    let total = *b.get(6)?;
    let id = *b.get(7)?;
    let size = u16::from_be_bytes(b.get(8..10)?.try_into().ok()?) as usize;
    let (addr, used) = parse_addr(b.get(10..)?)?;
    let start = 10 + used;
    let payload = b.get(start..start.checked_add(size)?)?;
    Some(Packet { assoc, packet, total, id, addr, payload })
}

/// `host:port` (IPv6 in brackets) as a TUIC address.
fn put_addr(out: &mut Vec<u8>, target: &str) -> Result<()> {
    let (host, port) = target.rsplit_once(':').with_context(|| format!("地址“{target}”缺少端口"))?;
    let port: u16 = port.parse().with_context(|| format!("地址“{target}”的端口无效"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            out.push(0x02);
            out.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            if host.is_empty() || host.len() > 255 {
                bail!("域名“{host}”无效");
            }
            out.push(0x00);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

/// (address as `host:port`, or None for type 0xff; bytes used).
fn parse_addr(b: &[u8]) -> Option<(Option<String>, usize)> {
    let port_at = |at: usize| -> Option<u16> { Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?)) };
    match *b.first()? {
        0xff => Some((None, 1)),
        0x00 => {
            let len = *b.get(1)? as usize;
            let host = std::str::from_utf8(b.get(2..2 + len)?).ok()?;
            Some((Some(format!("{host}:{}", port_at(2 + len)?)), 2 + len + 2))
        }
        0x01 => {
            let ip: [u8; 4] = b.get(1..5)?.try_into().ok()?;
            Some((Some(SocketAddr::from((ip, port_at(5)?)).to_string()), 7))
        }
        0x02 => {
            let ip: [u8; 16] = b.get(1..17)?.try_into().ok()?;
            Some((Some(SocketAddr::from((ip, port_at(17)?)).to_string()), 19))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_round_trip() {
        for t in ["example.com:443", "1.2.3.4:53", "[2001:db8::1]:8443"] {
            let mut b = Vec::new();
            put_addr(&mut b, t).unwrap();
            let (back, used) = parse_addr(&b).unwrap();
            assert_eq!(used, b.len());
            assert_eq!(back.unwrap(), t);
        }
        assert_eq!(parse_addr(&[0xff]).unwrap(), (None, 1));
    }

    #[test]
    fn packet_parses() {
        let mut m = vec![VERSION, CMD_PACKET, 0, 7, 0, 9, 1, 0, 0, 3];
        put_addr(&mut m, "8.8.8.8:53").unwrap();
        m.extend_from_slice(b"abc");
        let p = parse_packet(&m).unwrap();
        assert_eq!((p.assoc, p.packet, p.total, p.id), (7, 9, 1, 0));
        assert_eq!(p.addr.as_deref(), Some("8.8.8.8:53"));
        assert_eq!(p.payload, b"abc");
    }

    #[test]
    fn uuid_parses() {
        let u = parse_uuid("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        assert_eq!(u[0], 0x00);
        assert_eq!(u[15], 0xff);
        assert!(parse_uuid("not-a-uuid").is_err());
    }
}
