//! A device in the mesh.
//!
//! One UDP socket carries everything: WireGuard to every peer, path probes,
//! messages to the coordinator and relayed frames. Hole punching depends on
//! probes and data leaving from the same port.
//!
//! Per peer the best working path is used:
//! LAN > IPv6 > public IPv4 > through another device > through the coordinator.
//! Packets in and out are raw IP packets of the mesh subnet: the caller
//! (TUN) writes what comes out to the OS and feeds in what the OS sends.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use boringtun::noise::{handshake::parse_handshake_anon, Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::debug;

use crate::proto::{self, Disco, Envelope, FromCoord, Invite, LinkReport, LinkView, MemberView, PathKind, ToCoord};

const HELLO_EVERY: Duration = Duration::from_secs(15);
const PROBE_UNCONFIRMED: Duration = Duration::from_secs(5);
const PROBE_CONFIRMED: Duration = Duration::from_secs(20);
/// A direct path is trusted this long after its last pong or packet.
const DIRECT_VALID: Duration = Duration::from_secs(45);
const PEER_RELAY_VALID: Duration = Duration::from_secs(45);
const PUNCH_REQ_EVERY: Duration = Duration::from_secs(10);
const TICK: Duration = Duration::from_millis(250);
const LINK_REPORT_MIN: Duration = Duration::from_secs(2);
/// Probes follow their NAT primers after this long.
const PRIME_DELAY: Duration = Duration::from_millis(500);

/// TTLs of the NAT primers: enough to pass our own NATs (home router,
/// carrier-grade NAT) but not to reach the peer's, which is many hops away
/// across the internet. `SUPERNET_PUNCH_TTL=2,3` overrides (short test paths).
fn punch_ttls() -> &'static [u32] {
    static TTLS: std::sync::OnceLock<Vec<u32>> = std::sync::OnceLock::new();
    TTLS.get_or_init(|| {
        std::env::var("SUPERNET_PUNCH_TTL")
            .ok()
            .map(|v| v.split(',').filter_map(|t| t.trim().parse().ok()).collect::<Vec<u32>>())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec![2, 3, 4, 5])
    })
}
const KEEPALIVE: u16 = 25;

#[derive(Clone)]
pub struct MeshConfig {
    pub invite: Invite,
    /// The device's WireGuard private key (its identity in the mesh).
    pub private_key: [u8; 32],
    pub name: String,
    pub relay: bool,
    /// Local UDP address; `0.0.0.0:0` normally.
    pub bind: SocketAddr,
    /// Local IPv6 UDP address for direct paths over IPv6; `[::]:0` normally,
    /// `None` to stay on IPv4.
    pub bind6: Option<SocketAddr>,
    /// Tests: probe only IPv6 candidates.
    pub only_ipv6_direct: bool,
    /// Tests: never use direct paths (simulates two devices that cannot punch).
    pub disable_direct: bool,
    /// Tests: refuse direct paths to these peers only.
    pub block_direct_to: Vec<Ipv4Addr>,
}

impl MeshConfig {
    pub fn new(invite: Invite, private_key: [u8; 32], name: impl Into<String>) -> Self {
        MeshConfig {
            invite,
            private_key,
            name: name.into(),
            relay: true,
            bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            bind6: Some(SocketAddr::from(([0u16; 8], 0))),
            only_ipv6_direct: false,
            disable_direct: false,
            block_direct_to: Vec::new(),
        }
    }
}

/// Raw IP packets between the mesh and the OS.
pub struct MeshPorts {
    /// Packets from the OS, destined to mesh addresses.
    pub to_mesh: mpsc::Sender<Vec<u8>>,
    /// Packets from peers, to write to the OS.
    pub from_mesh: mpsc::Receiver<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerStatus {
    pub ip: Ipv4Addr,
    pub name: String,
    pub online: bool,
    pub server: bool,
    pub relay: bool,
    pub kind: PathKind,
    pub rtt_ms: Option<u32>,
    pub via: Option<Ipv4Addr>,
    /// The direct address in use, if any.
    pub endpoint: Option<SocketAddr>,
    pub candidates: Vec<SocketAddr>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub handshake_s: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MeshStatus {
    pub network: String,
    pub coordinator: String,
    pub me: Option<MemberView>,
    pub observed: Option<SocketAddr>,
    pub prefix: u8,
    pub peers: Vec<PeerStatus>,
    /// Every link reported by every online device (for the topology view).
    pub links: Vec<LinkView>,
    pub members: Vec<MemberView>,
    /// Bytes this device relayed for others.
    pub relayed_bytes: u64,
    /// Datagrams the OS refused to send (counted, not retried), and the last reason.
    pub send_errors: u64,
    pub last_send_error: Option<String>,
    pub last_error: Option<String>,
    pub coord_seen_s: Option<u64>,
}

struct Direct {
    addr: SocketAddr,
    rtt: Duration,
    seen: Instant,
}

struct Peer {
    view: MemberView,
    key: [u8; 32],
    tunn: Tunn,
    direct: Option<Direct>,
    /// Through another device: (relay ip, combined rtt, last confirmation).
    via_peer: Option<(Ipv4Addr, Duration, Instant)>,
    pings: HashMap<u64, (SocketAddr, Instant)>,
    last_probe: Option<Instant>,
    last_punch_req: Option<Instant>,
    /// Addresses learned from probes the peer sent us (peer-reflexive).
    learned: Vec<SocketAddr>,
    tx: u64,
    rx: u64,
}

impl Peer {
    fn direct_ok(&self) -> Option<&Direct> {
        self.direct.as_ref().filter(|d| d.seen.elapsed() < DIRECT_VALID)
    }

    fn candidates(&self) -> Vec<SocketAddr> {
        let mut v: Vec<SocketAddr> = self.view.endpoints.clone();
        for a in &self.learned {
            if !v.contains(a) {
                v.push(*a);
            }
        }
        v
    }
}

#[derive(Clone, Copy)]
enum Route {
    Direct(SocketAddr),
    ViaPeer(Ipv4Addr),
    Server,
}

struct State {
    me: Option<MemberView>,
    observed: Option<SocketAddr>,
    network: String,
    prefix: u8,
    members: Vec<MemberView>,
    links: Vec<LinkView>,
    peers: HashMap<Ipv4Addr, Peer>,
    by_index: HashMap<u32, Ipv4Addr>,
    by_key: HashMap<[u8; 32], Ipv4Addr>,
    next_index: u32,
    last_hello: Option<Instant>,
    /// (peer, kind, via) of every link at the last hello; a change is reported early.
    reported_shape: Vec<(Ipv4Addr, PathKind, Option<Ipv4Addr>)>,
    coord_seen: Option<Instant>,
    /// Where the coordinator's (authenticated) messages actually come from.
    coord_from: Option<SocketAddr>,
    last_ts: u64,
    last_error: Option<String>,
    relayed: u64,
    out: Vec<(Vec<u8>, SocketAddr)>,
    /// Low-TTL "primers" sent before punching through NATs (see `probe`).
    primers: Vec<(Vec<u8>, SocketAddr)>,
    /// Probes held back until their primers have opened our own NAT.
    deferred: Vec<(Instant, Vec<u8>, SocketAddr)>,
    deliver: Vec<Vec<u8>>,
}

struct Inner {
    cfg: MeshConfig,
    secret: [u8; 32],
    public: [u8; 32],
    coord: SocketAddr,
    sock: UdpSocket,
    /// IPv6 direct paths (absent when the system has no IPv6).
    sock6: Option<UdpSocket>,
    st: Mutex<State>,
    /// Serialises sends, so a temporarily lowered TTL never touches other packets.
    send_lock: Mutex<()>,
    send_errors: std::sync::atomic::AtomicU64,
    last_send_error: Mutex<Option<String>>,
    joined: watch::Sender<Option<Ipv4Addr>>,
    inbound: mpsc::Sender<Vec<u8>>,
}

pub struct Mesh {
    inner: Arc<Inner>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Mesh {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Mesh {
    pub async fn start(cfg: MeshConfig) -> Result<(Mesh, MeshPorts)> {
        let coord = tokio::net::lookup_host(&cfg.invite.coord)
            .await
            .with_context(|| format!("解析协调服务地址 {}", cfg.invite.coord))?
            .find(|a| a.is_ipv4())
            .context("协调服务没有 IPv4 地址")?;
        let std_sock = supernet_netstack::sysnet::udp_bind(cfg.bind)?;
        {
            let s = socket2::SockRef::from(&std_sock);
            let _ = s.set_recv_buffer_size(4 << 20);
            let _ = s.set_send_buffer_size(4 << 20);
        }
        let sock = UdpSocket::from_std(std_sock)?;
        let sock6 = match cfg.bind6.map(supernet_netstack::sysnet::udp_bind) {
            Some(Ok(s6)) => {
                let r = socket2::SockRef::from(&s6);
                let _ = r.set_recv_buffer_size(4 << 20);
                let _ = r.set_send_buffer_size(4 << 20);
                UdpSocket::from_std(s6).ok()
            }
            Some(Err(e)) => {
                debug!("no IPv6 socket: {e}");
                None
            }
            None => None,
        };
        let (to_mesh, mut outbound) = mpsc::channel::<Vec<u8>>(1024);
        let (inbound, from_mesh) = mpsc::channel::<Vec<u8>>(1024);
        let (joined, _) = watch::channel(None);
        let inner = Arc::new(Inner {
            secret: cfg.private_key,
            public: proto::public_of(&cfg.private_key),
            coord,
            sock,
            sock6,
            send_lock: Mutex::new(()),
            send_errors: std::sync::atomic::AtomicU64::new(0),
            last_send_error: Mutex::new(None),
            st: Mutex::new(State {
                me: None,
                observed: None,
                network: cfg.invite.network.clone(),
                prefix: 24,
                members: Vec::new(),
                links: Vec::new(),
                peers: HashMap::new(),
                by_index: HashMap::new(),
                by_key: HashMap::new(),
                next_index: 1,
                last_hello: None,
                reported_shape: Vec::new(),
                coord_seen: None,
                coord_from: None,
                last_ts: 0,
                last_error: None,
                relayed: 0,
                out: Vec::new(),
                primers: Vec::new(),
                deferred: Vec::new(),
                deliver: Vec::new(),
            }),
            cfg,
            joined,
            inbound,
        });

        let recv = {
            let inner = inner.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65_536];
                loop {
                    match inner.sock.recv_from(&mut buf).await {
                        Ok((n, from)) => inner.on_datagram(&buf[..n], from),
                        Err(e) => {
                            // Windows reports ICMP port-unreachable as a recv error.
                            debug!("mesh recv: {e}");
                        }
                    }
                }
            })
        };
        let send = {
            let inner = inner.clone();
            tokio::spawn(async move {
                while let Some(packet) = outbound.recv().await {
                    inner.on_outbound(&packet);
                }
            })
        };
        let tick = {
            let inner = inner.clone();
            tokio::spawn(async move {
                let mut t = tokio::time::interval(TICK);
                loop {
                    t.tick().await;
                    inner.on_tick();
                }
            })
        };
        inner.with(|inner, st| inner.hello(st));
        let mut tasks = vec![recv, send, tick];
        if inner.sock6.is_some() {
            let inner = inner.clone();
            tasks.push(tokio::spawn(async move {
                let sock6 = inner.sock6.as_ref().expect("checked");
                let mut buf = vec![0u8; 65_536];
                loop {
                    match sock6.recv_from(&mut buf).await {
                        Ok((n, from)) => inner.on_datagram(&buf[..n], from),
                        Err(e) => debug!("mesh recv6: {e}"),
                    }
                }
            }));
        }
        Ok((Mesh { inner, tasks }, MeshPorts { to_mesh, from_mesh }))
    }

    /// The local UDP port (tests).
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.sock.local_addr().unwrap_or(self.inner.cfg.bind)
    }

    /// Wait until the coordinator has accepted this device; returns its address.
    pub async fn wait_joined(&self, timeout: Duration) -> Result<Ipv4Addr> {
        let mut rx = self.inner.joined.subscribe();
        let wait = async {
            loop {
                if let Some(ip) = *rx.borrow() {
                    return Ok(ip);
                }
                if rx.changed().await.is_err() {
                    anyhow::bail!("组网已停止");
                }
            }
        };
        match tokio::time::timeout(timeout, wait).await {
            Ok(r) => r,
            Err(_) => {
                let err = self.inner.st.lock().unwrap_or_else(|e| e.into_inner()).last_error.clone();
                anyhow::bail!("{} 秒内没能加入网络{}", timeout.as_secs(), err.map(|e| format!("：{e}")).unwrap_or_default())
            }
        }
    }

    pub fn status(&self) -> MeshStatus {
        let st = self.inner.st.lock().unwrap_or_else(|e| e.into_inner());
        let mut peers: Vec<PeerStatus> = st
            .peers
            .values()
            .map(|p| {
                let (kind, rtt, via) = self.inner.link_of(p);
                PeerStatus {
                    ip: p.view.ip,
                    name: p.view.name.clone(),
                    online: p.view.online,
                    server: p.view.server,
                    relay: p.view.relay,
                    kind,
                    rtt_ms: rtt.map(|d| d.as_millis() as u32),
                    via,
                    endpoint: p.direct_ok().map(|d| d.addr).or(if p.view.server { p.view.endpoints.first().copied() } else { None }),
                    candidates: p.candidates(),
                    tx_bytes: p.tx,
                    rx_bytes: p.rx,
                    handshake_s: p.tunn.time_since_last_handshake().map(|d| d.as_secs()),
                }
            })
            .collect();
        peers.sort_by_key(|p| p.ip);
        MeshStatus {
            network: st.network.clone(),
            coordinator: self.inner.cfg.invite.coord.clone(),
            me: st.me.clone(),
            observed: st.observed,
            prefix: st.prefix,
            peers,
            links: st.links.clone(),
            members: st.members.clone(),
            relayed_bytes: st.relayed,
            send_errors: self.inner.send_errors.load(std::sync::atomic::Ordering::Relaxed),
            last_send_error: self.inner.last_send_error.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            last_error: st.last_error.clone(),
            coord_seen_s: st.coord_seen.map(|t| t.elapsed().as_secs()),
        }
    }
}

impl Inner {
    /// Run `f` under the state lock, then send and deliver what it queued.
    fn with<R>(&self, f: impl FnOnce(&Inner, &mut State) -> R) -> R {
        let (r, out, primers, deliver) = {
            let mut st = self.st.lock().unwrap_or_else(|e| e.into_inner());
            let r = f(self, &mut st);
            // Held-back probes whose time has come.
            let now = Instant::now();
            let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut st.deferred).into_iter().partition(|(t, _, _)| *t <= now);
            st.deferred = later;
            st.out.extend(due.into_iter().map(|(_, d, a)| (d, a)));
            (r, std::mem::take(&mut st.out), std::mem::take(&mut st.primers), std::mem::take(&mut st.deliver))
        };
        let _send = self.send_lock.lock().unwrap_or_else(|e| e.into_inner());
        if !primers.is_empty() {
            let sock = socket2::SockRef::from(&self.sock);
            let normal = sock.ttl_v4().unwrap_or(64);
            for ttl in punch_ttls() {
                if sock.set_ttl_v4(*ttl).is_err() {
                    break;
                }
                for (d, to) in &primers {
                    let _ = self.sock.try_send_to(d, *to);
                }
            }
            let _ = sock.set_ttl_v4(normal);
        }
        for (d, to) in out {
            let r = match (&self.sock6, to.is_ipv6()) {
                (Some(s6), true) => s6.try_send_to(&d, to),
                (None, true) => continue,
                _ => self.sock.try_send_to(&d, to),
            };
            if let Err(e) = r {
                self.send_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                *self.last_send_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(format!("发往 {to}：{e}"));
            }
        }
        for p in deliver {
            let _ = self.inbound.try_send(p);
        }
        r
    }

    fn my_ip(st: &State) -> Option<Ipv4Addr> {
        st.me.as_ref().map(|m| m.ip)
    }

    fn ctrl(&self, st: &mut State, msg: ToCoord) {
        // Strictly increasing timestamps even within one millisecond.
        let ts = proto::now_ms().max(st.last_ts + 1);
        st.last_ts = ts;
        let Ok(plain) = serde_json::to_vec(&Envelope { ts, msg }) else { return };
        if let Ok(d) = proto::seal(proto::T_CTRL, &self.secret, &self.cfg.invite.coord_pub, &plain) {
            st.out.push((d, self.coord));
        }
    }

    fn local_endpoints(&self) -> Vec<SocketAddr> {
        let mut out = Vec::new();
        if let Ok(local) = self.sock.local_addr() {
            if !local.ip().is_unspecified() {
                out.push(local);
            } else if let Some(ip) = route_source(SocketAddr::from(([0, 0, 0, 0], 0)), "8.8.8.8:53") {
                // The address the OS would use for the internet: the LAN address. The
                // probe is pinned like our real socket, so with TUN mode on it is the
                // physical adapter's address, not the TUN's.
                out.push(SocketAddr::new(ip, local.port()));
            }
        }
        if let Some(local6) = self.sock6.as_ref().and_then(|s| s.local_addr().ok()) {
            if !local6.ip().is_unspecified() {
                out.push(local6);
            } else if let Some(ip) = route_source(SocketAddr::from(([0u16; 8], 0)), "[2400:3200::1]:53") {
                if is_global_v6(&ip) {
                    out.push(SocketAddr::new(ip, local6.port()));
                }
            }
        }
        out.retain(|a| !is_virtual(a));
        out
    }

    fn hello(&self, st: &mut State) {
        st.last_hello = Some(Instant::now());
        if st.me.is_none() {
            let msg = ToCoord::Join { invite: self.cfg.invite.key.clone(), name: self.cfg.name.clone(), relay: self.cfg.relay };
            self.ctrl(st, msg);
            return;
        }
        let links: Vec<LinkReport> = st
            .peers
            .values()
            .filter(|p| p.view.online)
            .map(|p| {
                let (kind, rtt, via) = self.link_of(p);
                LinkReport { peer: p.view.ip, kind, rtt_ms: rtt.map(|d| d.as_millis() as u32), via, tx_bytes: p.tx, rx_bytes: p.rx }
            })
            .collect();
        st.reported_shape = shape(&links);
        let msg = ToCoord::Hello { name: self.cfg.name.clone(), endpoints: self.local_endpoints(), relay: self.cfg.relay, links };
        self.ctrl(st, msg);
    }

    fn current_shape(&self, st: &State) -> Vec<(Ipv4Addr, PathKind, Option<Ipv4Addr>)> {
        let links: Vec<LinkReport> = st
            .peers
            .values()
            .filter(|p| p.view.online)
            .map(|p| {
                let (kind, _, via) = self.link_of(p);
                LinkReport { peer: p.view.ip, kind, rtt_ms: None, via, tx_bytes: 0, rx_bytes: 0 }
            })
            .collect();
        shape(&links)
    }

    fn link_of(&self, p: &Peer) -> (PathKind, Option<Duration>, Option<Ipv4Addr>) {
        if !p.view.online {
            return (PathKind::Down, None, None);
        }
        if p.view.server {
            let up = p.tunn.time_since_last_handshake().is_some_and(|d| d < Duration::from_secs(180));
            return (if up { PathKind::Direct } else { PathKind::Down }, None, None);
        }
        if let Some(d) = p.direct_ok() {
            return (proto::direct_kind(&d.addr), Some(d.rtt), None);
        }
        if let Some((via, rtt, _)) = p.via_peer.filter(|(_, _, t)| t.elapsed() < PEER_RELAY_VALID) {
            return (PathKind::Peer, Some(rtt), Some(via));
        }
        (PathKind::Server, None, None)
    }

    fn route(&self, p: &Peer) -> Route {
        if p.view.server {
            return p.view.endpoints.first().map_or(Route::Server, |a| Route::Direct(*a));
        }
        if let Some(d) = p.direct_ok() {
            return Route::Direct(d.addr);
        }
        if let Some((via, _, _)) = p.via_peer.filter(|(_, _, t)| t.elapsed() < PEER_RELAY_VALID) {
            return Route::ViaPeer(via);
        }
        Route::Server
    }

    /// Queue a WireGuard datagram to a peer along `route`.
    fn send_wg(&self, st: &mut State, peer: Ipv4Addr, route: Route, datagram: &[u8]) {
        let Some(me) = Self::my_ip(st) else { return };
        match route {
            Route::Direct(addr) => st.out.push((datagram.to_vec(), addr)),
            Route::Server => st.out.push((proto::relay_frame(peer, me, datagram), self.coord)),
            Route::ViaPeer(via) => {
                let relay_addr = st.peers.get(&via).and_then(|r| r.direct_ok().map(|d| d.addr));
                match relay_addr {
                    Some(addr) => st.out.push((proto::relay_frame(peer, me, datagram), addr)),
                    None => st.out.push((proto::relay_frame(peer, me, datagram), self.coord)),
                }
            }
        }
    }

    // ------------------------------------------------------------- inbound

    fn on_datagram(&self, data: &[u8], from: SocketAddr) {
        let from = normalize(from);
        self.with(|inner, st| {
            if proto::is_ours(data) {
                match data[2] {
                    // Authenticated by the coordinator's key, not by address: a multi-homed
                    // server may answer from another of its addresses.
                    proto::T_CTRL => inner.on_ctrl(st, data, from),
                    proto::T_DISCO => inner.on_disco(st, data, from),
                    proto::T_RELAY => inner.on_relay(st, data, from),
                    _ => {}
                }
            } else {
                inner.on_wg(st, data, Some(from), None);
            }
        });
    }

    fn on_ctrl(&self, st: &mut State, data: &[u8], from: SocketAddr) {
        if proto::sealed_sender(data) != Some(self.cfg.invite.coord_pub) {
            return;
        }
        let Ok((_, plain)) = proto::open(data, &self.secret) else { return };
        let Ok(env) = serde_json::from_slice::<Envelope<FromCoord>>(&plain) else { return };
        st.coord_seen = Some(Instant::now());
        st.coord_from = Some(from);
        match env.msg {
            FromCoord::State { network, prefix, me, observed, members, links } => {
                st.last_error = None;
                let first = st.me.is_none();
                st.network = network;
                st.prefix = prefix;
                st.observed = Some(observed);
                let my_ip = me.ip;
                st.me = Some(me);
                st.links = links;
                self.apply_members(st, my_ip, members);
                if first {
                    let _ = self.joined.send(Some(my_ip));
                    // Announce our addresses right away.
                    self.hello(st);
                }
            }
            FromCoord::Punch { peer, endpoints } => {
                if let Some(p) = st.peers.get_mut(&peer) {
                    for e in endpoints {
                        if !is_virtual(&e) && !p.learned.contains(&e) && !p.view.endpoints.contains(&e) {
                            p.learned.push(e);
                        }
                    }
                    p.last_probe = None; // probe on the next tick
                }
            }
            FromCoord::Error { code, message } => {
                st.last_error = Some(message);
                if code == "not_member" {
                    st.me = None;
                    let _ = self.joined.send(None);
                }
            }
        }
    }

    fn apply_members(&self, st: &mut State, my_ip: Ipv4Addr, members: Vec<MemberView>) {
        let keep: Vec<Ipv4Addr> = members.iter().map(|m| m.ip).collect();
        let gone: Vec<Ipv4Addr> = st.peers.keys().filter(|ip| !keep.contains(ip)).copied().collect();
        for ip in gone {
            if let Some(p) = st.peers.remove(&ip) {
                st.by_key.remove(&p.key);
                st.by_index.retain(|_, v| *v != ip);
            }
        }
        for m in &members {
            if m.ip == my_ip {
                continue;
            }
            let Ok(key) = proto::unb64(&m.pubkey) else { continue };
            let mut m = m.clone();
            m.endpoints.retain(|a| !is_virtual(a));
            let m = &m;
            match st.peers.get_mut(&m.ip) {
                Some(p) if p.key == key => p.view = m.clone(),
                _ => {
                    if let Some(old) = st.peers.remove(&m.ip) {
                        st.by_key.remove(&old.key);
                    }
                    let index = st.next_index;
                    st.next_index = (st.next_index + 1) & 0x00ff_ffff;
                    let tunn = Tunn::new(
                        StaticSecret::from(self.secret),
                        PublicKey::from(key),
                        None,
                        Some(KEEPALIVE),
                        index,
                        None,
                    );
                    st.by_index.insert(index, m.ip);
                    st.by_key.insert(key, m.ip);
                    st.peers.insert(
                        m.ip,
                        Peer {
                            view: m.clone(),
                            key,
                            tunn,
                            direct: None,
                            via_peer: None,
                            pings: HashMap::new(),
                            last_probe: None,
                            last_punch_req: None,
                            learned: Vec::new(),
                            tx: 0,
                            rx: 0,
                        },
                    );
                }
            }
        }
        st.members = members;
    }

    /// A WireGuard datagram from `from` (direct) or relayed for `relayed_src`.
    fn on_wg(&self, st: &mut State, data: &[u8], from: Option<SocketAddr>, relayed_src: Option<(Ipv4Addr, SocketAddr)>) {
        let peer_ip = match relayed_src {
            Some((src, _)) => Some(src),
            None => match Tunn::parse_incoming_packet(data) {
                Ok(Packet::HandshakeInit(init)) => {
                    let secret = StaticSecret::from(self.secret);
                    let public = PublicKey::from(self.public);
                    parse_handshake_anon(&secret, &public, &init).ok().and_then(|h| st.by_key.get(&h.peer_static_public).copied())
                }
                Ok(Packet::HandshakeResponse(r)) => st.by_index.get(&(r.receiver_idx >> 8)).copied(),
                Ok(Packet::PacketCookieReply(r)) => st.by_index.get(&(r.receiver_idx >> 8)).copied(),
                Ok(Packet::PacketData(d)) => st.by_index.get(&(d.receiver_idx >> 8)).copied(),
                Err(_) => None,
            },
        };
        let Some(peer_ip) = peer_ip else { return };
        // Replies go back the way the packet came.
        let back = match (from, relayed_src) {
            (_, Some((_, relay_addr))) if relay_addr == self.coord || Some(relay_addr) == st.coord_from => Route::Server,
            (_, Some((_, relay_addr))) => {
                let via = st.peers.iter().find(|(_, p)| p.direct_ok().is_some_and(|d| d.addr == relay_addr)).map(|(ip, _)| *ip);
                via.map_or(Route::Server, Route::ViaPeer)
            }
            (Some(addr), None) => Route::Direct(addr),
            (None, None) => return,
        };
        let mut scratch = vec![0u8; (data.len() + 256).max(2048)];
        let mut replies: Vec<Vec<u8>> = Vec::new();
        let mut delivered: Vec<Vec<u8>> = Vec::new();
        {
            let Some(p) = st.peers.get_mut(&peer_ip) else { return };
            let src_ip = from.map(|a| a.ip());
            let mut first = true;
            loop {
                let input: &[u8] = if first { data } else { &[] };
                let r = p.tunn.decapsulate(if first { src_ip } else { None }, input, &mut scratch);
                first = false;
                match r {
                    TunnResult::WriteToNetwork(b) => {
                        replies.push(b.to_vec());
                        continue; // flush queued packets
                    }
                    TunnResult::WriteToTunnelV4(b, src) => {
                        if src == peer_ip {
                            p.rx += b.len() as u64;
                            delivered.push(b.to_vec());
                        }
                    }
                    TunnResult::WriteToTunnelV6(..) | TunnResult::Done => {}
                    TunnResult::Err(e) => debug!("wg from {peer_ip}: {e:?}"),
                }
                break;
            }
            // Any authenticated packet from a direct address keeps that path alive.
            if let (Route::Direct(addr), false) = (back, p.view.server) {
                if let Some(d) = p.direct.as_mut().filter(|d| d.addr == addr) {
                    d.seen = Instant::now();
                }
            }
        }
        for r in replies {
            self.send_wg(st, peer_ip, back, &r);
        }
        st.deliver.extend(delivered);
    }

    fn on_relay(&self, st: &mut State, data: &[u8], from: SocketAddr) {
        let Some((dst, src, payload)) = proto::parse_relay(data) else { return };
        let Some(me) = Self::my_ip(st) else { return };
        if dst == me {
            // From the coordinator, or from a peer we reach directly.
            let trusted = from == self.coord || Some(from) == st.coord_from || st.peers.values().any(|p| p.direct_ok().is_some_and(|d| d.addr == from));
            if !trusted || !st.peers.contains_key(&src) {
                return;
            }
            if proto::is_ours(payload) && payload[2] == proto::T_DISCO {
                self.on_disco_relayed(st, payload, src, from);
            } else {
                self.on_wg(st, payload, None, Some((src, from)));
            }
            return;
        }
        // Relaying for others: only between peers we both reach directly, sender authenticated by address.
        if !self.cfg.relay {
            return;
        }
        let sender_ok = st.peers.get(&src).and_then(|p| p.direct_ok()).is_some_and(|d| d.addr == from);
        let target = st.peers.get(&dst).and_then(|p| p.direct_ok()).map(|d| d.addr);
        if let (true, Some(to)) = (sender_ok, target) {
            st.relayed += data.len() as u64;
            st.out.push((data.to_vec(), to));
        }
    }

    // ------------------------------------------------------------- probes

    fn on_disco(&self, st: &mut State, data: &[u8], from: SocketAddr) {
        let Some(sender) = proto::sealed_sender(data) else { return };
        let Some(&peer_ip) = st.by_key.get(&sender) else { return };
        if self.direct_blocked(peer_ip) {
            return;
        }
        let Ok((_, plain)) = proto::open(data, &self.secret) else { return };
        let Ok(msg) = serde_json::from_slice::<Disco>(&plain) else { return };
        let Some(p) = st.peers.get_mut(&peer_ip) else { return };
        match msg {
            Disco::Ping { txid } => {
                if !is_virtual(&from) && !p.learned.contains(&from) && !p.view.endpoints.contains(&from) && p.learned.len() < 8 {
                    p.learned.push(from);
                }
                let pong = Disco::Pong { txid, observed: from };
                if let Ok(d) = proto::seal(proto::T_DISCO, &self.secret, &p.key, &serde_json::to_vec(&pong).unwrap_or_default()) {
                    st.out.push((d, from));
                }
                // Their probe got through to us: probe back now (completes the punch).
                if p.direct_ok().is_none() {
                    p.last_probe = None;
                }
            }
            Disco::Pong { txid, .. } => {
                if let Some((addr, sent)) = p.pings.remove(&txid) {
                    if addr == from {
                        let rtt = sent.elapsed();
                        let better = match p.direct_ok() {
                            None => true,
                            Some(cur) => cur.addr == from || rank(&from) < rank(&cur.addr) || (rank(&from) == rank(&cur.addr) && rtt < cur.rtt),
                        };
                        if better {
                            p.direct = Some(Direct { addr: from, rtt, seen: Instant::now() });
                        }
                    }
                }
            }
        }
    }

    /// A probe relayed through device `via_addr` (used to measure peer relays).
    fn on_disco_relayed(&self, st: &mut State, payload: &[u8], src: Ipv4Addr, via_addr: SocketAddr) {
        let Ok((sender, plain)) = proto::open(payload, &self.secret) else { return };
        let Some(me) = Self::my_ip(st) else { return };
        let via = st.peers.iter().find(|(_, p)| p.direct_ok().is_some_and(|d| d.addr == via_addr)).map(|(ip, _)| *ip);
        let Some(p) = st.peers.get_mut(&src) else { return };
        if p.key != sender {
            return;
        }
        match serde_json::from_slice::<Disco>(&plain) {
            Ok(Disco::Ping { txid }) => {
                let pong = Disco::Pong { txid, observed: via_addr };
                if let Ok(d) = proto::seal(proto::T_DISCO, &self.secret, &p.key, &serde_json::to_vec(&pong).unwrap_or_default()) {
                    st.out.push((proto::relay_frame(src, me, &d), via_addr));
                }
            }
            Ok(Disco::Pong { txid, .. }) => {
                if let (Some((_, sent)), Some(via)) = (p.pings.remove(&txid), via) {
                    p.via_peer = Some((via, sent.elapsed(), Instant::now()));
                }
            }
            Err(_) => {}
        }
    }

    fn direct_blocked(&self, peer: Ipv4Addr) -> bool {
        self.cfg.disable_direct || self.cfg.block_direct_to.contains(&peer)
    }

    fn probe(&self, st: &mut State, peer_ip: Ipv4Addr) {
        let Some(me) = Self::my_ip(st) else { return };
        let blocked = self.direct_blocked(peer_ip);
        // Relay candidates: online peers that allow relaying and reach us directly.
        let relays: Vec<(Ipv4Addr, SocketAddr)> = st
            .peers
            .iter()
            .filter(|(ip, r)| **ip != peer_ip && r.view.relay && !r.view.server && r.view.online)
            .filter_map(|(ip, r)| r.direct_ok().map(|d| (*ip, d.addr)))
            .collect();
        let Some(p) = st.peers.get_mut(&peer_ip) else { return };
        p.last_probe = Some(Instant::now());
        p.pings.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(10));
        let mut sends = Vec::new();
        let mut primers = Vec::new();
        let mut deferred = Vec::new();
        if !blocked {
            let v6_ok = self.sock6.is_some();
            let only6 = self.cfg.only_ipv6_direct;
            let unconfirmed = p.direct_ok().is_none();
            for addr in p.candidates().into_iter().filter(|a| if a.is_ipv6() { v6_ok } else { !only6 }) {
                let txid = OsRng.next_u64();
                if let Ok(d) = proto::seal(proto::T_DISCO, &self.secret, &p.key, &serde_json::to_vec(&Disco::Ping { txid }).unwrap_or_default()) {
                    // Punching a public IPv4 address through NATs: first open our own
                    // NAT with low-TTL primers that die before reaching the peer's NAT,
                    // then probe. Otherwise our first packet can reach the peer's NAT
                    // before the peer's own probe left it; Linux-style NATs then keep
                    // a stale entry for it and remap the peer's port, and the punch
                    // never meets (seen in the NAT lab, scripts/nat-lab.sh).
                    if unconfirmed && addr.is_ipv4() && !proto::is_lan(&addr) {
                        primers.push((d.clone(), addr));
                        p.pings.insert(txid, (addr, Instant::now() + PRIME_DELAY));
                        deferred.push((Instant::now() + PRIME_DELAY, d, addr));
                    } else {
                        p.pings.insert(txid, (addr, Instant::now()));
                        sends.push((d, addr));
                    }
                }
            }
        }
        // No direct path: measure the relays too.
        if p.direct_ok().is_none() {
            for (_, relay_addr) in &relays {
                let txid = OsRng.next_u64();
                if let Ok(d) = proto::seal(proto::T_DISCO, &self.secret, &p.key, &serde_json::to_vec(&Disco::Ping { txid }).unwrap_or_default()) {
                    p.pings.insert(txid, (*relay_addr, Instant::now()));
                    sends.push((proto::relay_frame(peer_ip, me, &d), *relay_addr));
                }
            }
        }
        let want_punch = !blocked && p.direct_ok().is_none() && p.last_punch_req.is_none_or(|t| t.elapsed() >= PUNCH_REQ_EVERY);
        if want_punch {
            p.last_punch_req = Some(Instant::now());
        }
        st.out.extend(sends);
        st.primers.extend(primers);
        st.deferred.extend(deferred);
        if want_punch {
            self.ctrl(st, ToCoord::PunchReq { peer: peer_ip });
        }
    }

    // ------------------------------------------------------------- outbound and timers

    fn on_outbound(&self, packet: &[u8]) {
        let Some(dst) = ipv4_dst(packet) else { return };
        self.with(|inner, st| {
            let mut scratch = vec![0u8; (packet.len() + 256).max(2048)];
            let (route, datagram) = {
                let Some(p) = st.peers.get_mut(&dst) else { return };
                let route = inner.route(p);
                match p.tunn.encapsulate(packet, &mut scratch) {
                    TunnResult::WriteToNetwork(b) => {
                        p.tx += packet.len() as u64;
                        (route, b.to_vec())
                    }
                    _ => return,
                }
            };
            inner.send_wg(st, dst, route, &datagram);
        });
    }

    fn on_tick(&self) {
        self.with(|inner, st| {
            let since = st.last_hello.map_or(Duration::MAX, |t| t.elapsed());
            let due = since >= if st.me.is_none() { Duration::from_secs(2) } else { HELLO_EVERY };
            // A path changed (direct found, relay lost…): tell the others soon, at most every 2 s.
            let relinked = st.me.is_some() && since >= LINK_REPORT_MIN && inner.current_shape(st) != st.reported_shape;
            if due || relinked {
                inner.hello(st);
            }
            if st.me.is_none() {
                return;
            }
            let ips: Vec<Ipv4Addr> = st.peers.keys().copied().collect();
            let mut scratch = vec![0u8; 2048];
            for ip in ips {
                let (route, datagram, probe_due) = {
                    let p = st.peers.get_mut(&ip).expect("peer");
                    let route = inner.route(p);
                    let datagram = match p.tunn.update_timers(&mut scratch) {
                        TunnResult::WriteToNetwork(b) => Some(b.to_vec()),
                        _ => None,
                    };
                    let every = if p.direct_ok().is_some() { PROBE_CONFIRMED } else { PROBE_UNCONFIRMED };
                    let probe_due = p.view.online && !p.view.server && p.last_probe.is_none_or(|t| t.elapsed() >= every);
                    (route, datagram, probe_due)
                };
                let online = st.peers.get(&ip).is_some_and(|p| p.view.online);
                if let (Some(d), true) = (datagram, online) {
                    inner.send_wg(st, ip, route, &d);
                }
                if probe_due {
                    inner.probe(st, ip);
                }
            }
        });
    }
}

/// Addresses that only exist inside superNET itself: the mesh subnet, the TUN
/// adapter's /30 and the fake-IP range. A peer can never be reached at one.
fn is_virtual(a: &SocketAddr) -> bool {
    match a.ip() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (o[0] == 10 && o[1] == 66 && o[2] == 0) || (o[0] == 172 && o[1] == 19 && o[2] == 0 && o[3] < 4) || (o[0] == 198 && (o[1] & 0xfe) == 18)
        }
        IpAddr::V6(v6) => v6.segments()[..3] == [0xfdfe, 0xdcba, 0x9876],
    }
}

/// The source address the OS picks for `dest` (no packet is sent).
fn route_source(bind: SocketAddr, dest: &str) -> Option<IpAddr> {
    let s = supernet_netstack::sysnet::udp_bind(bind).ok()?;
    s.connect(dest).ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

/// Global unicast IPv6 (2000::/3): reachable from other networks.
fn is_global_v6(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xe000) == 0x2000)
}

fn shape(links: &[LinkReport]) -> Vec<(Ipv4Addr, PathKind, Option<Ipv4Addr>)> {
    let mut v: Vec<_> = links.iter().map(|l| (l.peer, l.kind, l.via)).collect();
    v.sort_by_key(|(ip, _, _)| *ip);
    v
}

/// Lower is better.
fn rank(addr: &SocketAddr) -> u8 {
    match proto::direct_kind(addr) {
        PathKind::Lan => 0,
        PathKind::Ipv6 => 1,
        _ => 2,
    }
}

fn normalize(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => a,
        },
        a => a,
    }
}

fn ipv4_dst(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]))
}
