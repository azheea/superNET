//! Wire format shared by devices and the coordinator.
//!
//! Every datagram superNET adds on top of WireGuard starts with `S N <type>`.
//! WireGuard's own messages start with a type byte 1–4 followed by three
//! zero bytes, so the two never collide on the shared UDP socket.
//!
//! - `CTRL`  device ↔ coordinator, sealed: `[S N 1][sender public 32][nonce 24][ciphertext]`
//! - `DISCO` device ↔ device path probes, sealed the same way with a per-pair key
//! - `RELAY` `[S N 2][destination IPv4 4][source IPv4 4][payload]`, the payload
//!   being a WireGuard datagram that the relay cannot read.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAGIC: [u8; 2] = *b"SN";
pub const T_CTRL: u8 = 1;
pub const T_RELAY: u8 = 2;
pub const T_DISCO: u8 = 3;
const SEALED_HEADER: usize = 3 + 32 + 24;
pub const RELAY_HEADER: usize = 3 + 4 + 4;

/// The coordinator's UDP port, chosen by the user.
pub const DEFAULT_PORT: u16 = 19190;

pub fn is_ours(datagram: &[u8]) -> bool {
    datagram.len() >= 3 && datagram[..2] == MAGIC
}

pub fn b64(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

pub fn unb64(s: &str) -> Result<[u8; 32]> {
    let v = base64::engine::general_purpose::STANDARD.decode(s.trim()).context("公钥不是 base64")?;
    v.try_into().map_err(|_| anyhow::anyhow!("公钥长度不是 32 字节"))
}

pub fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(*secret)).as_bytes()
}

pub fn generate_secret() -> [u8; 32] {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn derive(secret: &[u8; 32], peer: &[u8; 32], label: &[u8]) -> Result<[u8; 32]> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*peer));
    if !shared.was_contributory() {
        bail!("对方公钥无效");
    }
    let mut h = Blake2s256::new();
    h.update(b"supernet-mesh-v1");
    h.update(label);
    h.update(shared.as_bytes());
    Ok(h.finalize().into())
}

fn label(kind: u8) -> &'static [u8] {
    if kind == T_CTRL {
        b"ctrl"
    } else {
        b"disco"
    }
}

/// Seal `plain` from `secret` to `peer` as a CTRL or DISCO datagram.
pub fn seal(kind: u8, secret: &[u8; 32], peer: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>> {
    let key = derive(secret, peer, label(kind))?;
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(&key.into())
        .encrypt(XNonce::from_slice(&nonce), plain)
        .map_err(|_| anyhow::anyhow!("加密失败"))?;
    let mut out = Vec::with_capacity(SEALED_HEADER + ct.len());
    out.extend_from_slice(&MAGIC);
    out.push(kind);
    out.extend_from_slice(&public_of(secret));
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// The sender's public key of a sealed datagram, before opening it.
pub fn sealed_sender(datagram: &[u8]) -> Option<[u8; 32]> {
    datagram.get(3..35)?.try_into().ok()
}

/// Open a sealed datagram addressed to `secret`; returns (sender, plaintext).
pub fn open(datagram: &[u8], secret: &[u8; 32]) -> Result<([u8; 32], Vec<u8>)> {
    if datagram.len() < SEALED_HEADER + 16 || !is_ours(datagram) {
        bail!("报文太短");
    }
    let kind = datagram[2];
    let sender: [u8; 32] = datagram[3..35].try_into().expect("32 bytes");
    let key = derive(secret, &sender, label(kind))?;
    let plain = XChaCha20Poly1305::new(&key.into())
        .decrypt(XNonce::from_slice(&datagram[35..59]), &datagram[59..])
        .map_err(|_| anyhow::anyhow!("解密失败"))?;
    Ok((sender, plain))
}

pub fn relay_frame(dst: Ipv4Addr, src: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RELAY_HEADER + payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(T_RELAY);
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(payload);
    out
}

/// (destination, source, payload) of a RELAY datagram.
pub fn parse_relay(datagram: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, &[u8])> {
    if datagram.len() < RELAY_HEADER || datagram[2] != T_RELAY {
        return None;
    }
    let ip = |o: usize| Ipv4Addr::new(datagram[o], datagram[o + 1], datagram[o + 2], datagram[o + 3]);
    Some((ip(3), ip(7), &datagram[RELAY_HEADER..]))
}

// ------------------------------------------------------------------ messages

/// How two devices currently reach each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    /// Direct, over a private (LAN) address.
    Lan,
    /// Direct over IPv6.
    Ipv6,
    /// Direct over public IPv4 (possibly hole-punched).
    Direct,
    /// Through another device.
    Peer,
    /// Through the coordinator.
    Server,
    /// Not reachable right now.
    Down,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LinkReport {
    pub peer: Ipv4Addr,
    pub kind: PathKind,
    pub rtt_ms: Option<u32>,
    /// The relaying device, for `PathKind::Peer`.
    pub via: Option<Ipv4Addr>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// A link as seen by the coordinator: `from` reported it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LinkView {
    pub from: Ipv4Addr,
    #[serde(flatten)]
    pub link: LinkReport,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemberView {
    pub ip: Ipv4Addr,
    pub name: String,
    /// WireGuard public key, base64.
    pub pubkey: String,
    /// Where the device may be reached: its own addresses and the one the coordinator sees.
    pub endpoints: Vec<SocketAddr>,
    pub online: bool,
    /// Willing to relay for others.
    pub relay: bool,
    /// The server itself (kernel WireGuard): reached directly, never probed.
    pub server: bool,
    /// Seconds since the coordinator last heard from it.
    pub last_seen_s: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ToCoord {
    Join { invite: String, name: String, relay: bool },
    Hello { name: String, endpoints: Vec<SocketAddr>, relay: bool, links: Vec<LinkReport> },
    /// Please tell `peer` to probe me now (hole punching).
    PunchReq { peer: Ipv4Addr },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum FromCoord {
    State {
        network: String,
        prefix: u8,
        me: MemberView,
        /// This device's address as the coordinator sees it.
        observed: SocketAddr,
        members: Vec<MemberView>,
        links: Vec<LinkView>,
    },
    /// `peer` is probing you: probe these addresses back now.
    Punch { peer: Ipv4Addr, endpoints: Vec<SocketAddr> },
    Error { code: String, message: String },
}

/// The signed envelope of every CTRL message.
#[derive(Serialize, Deserialize)]
pub struct Envelope<T> {
    /// Sender's clock, unix ms; must increase per sender (replay protection).
    pub ts: u64,
    pub msg: T,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Disco {
    Ping { txid: u64 },
    Pong { txid: u64, observed: SocketAddr },
}

// ------------------------------------------------------------------ invite links

/// `supernet-net://host:port?k=INVITE&pub=COORD_KEY&n=NAME`
#[derive(Clone, Debug, PartialEq)]
pub struct Invite {
    pub coord: String,
    pub coord_pub: [u8; 32],
    pub key: String,
    pub network: String,
}

impl Invite {
    pub fn to_link(&self) -> String {
        let pubkey = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.coord_pub);
        format!("supernet-net://{}?k={}&pub={}&n={}", self.coord, self.key, pubkey, pct(&self.network))
    }

    pub fn parse(link: &str) -> Result<Invite> {
        let rest = link.trim().strip_prefix("supernet-net://").context("组网链接应以 supernet-net:// 开头")?;
        let (coord, query) = rest.split_once('?').context("组网链接缺少参数")?;
        let (mut key, mut pubkey, mut network) = (None, None, String::from("superNET"));
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            match k {
                "k" => key = Some(v.to_string()),
                "pub" => pubkey = Some(v.to_string()),
                "n" => network = unpct(v),
                _ => {}
            }
        }
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(pubkey.context("组网链接缺少 pub")?)
            .context("组网链接里的 pub 无效")?;
        let coord_pub: [u8; 32] = raw.try_into().map_err(|_| anyhow::anyhow!("组网链接里的 pub 长度不对"))?;
        let coord = coord.trim_end_matches('/').to_string();
        if !coord.contains(':') {
            bail!("组网链接缺少端口");
        }
        Ok(Invite { coord, coord_pub, key: key.context("组网链接缺少 k")?, network })
    }
}

fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

fn unpct(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Private, link-local or CGNAT IPv4: a "LAN" path when used directly.
pub fn is_lan(addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(v4) => {
            let ip = v4.ip();
            ip.is_private() || ip.is_link_local() || ip.is_loopback()
        }
        SocketAddr::V6(v6) => (v6.ip().segments()[0] & 0xffc0) == 0xfe80,
    }
}

pub fn direct_kind(addr: &SocketAddr) -> PathKind {
    if is_lan(addr) {
        PathKind::Lan
    } else if addr.is_ipv6() {
        PathKind::Ipv6
    } else {
        PathKind::Direct
    }
}
