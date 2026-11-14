//! The coordinator: membership, address discovery and the last-resort relay.
//!
//! It runs on the user's 1 core / 1 GB server next to other services, so it
//! is one task on one UDP socket with small, bounded state: no per-packet
//! allocation beyond the datagram itself, relay traffic rate-limited.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::proto::{self, Envelope, FromCoord, Invite, LinkReport, LinkView, MemberView, ToCoord};

/// A member that is the server's own kernel WireGuard interface.
#[derive(Clone, Debug)]
pub struct ServerMember {
    pub ip: Ipv4Addr,
    pub name: String,
    pub pubkey: [u8; 32],
    pub endpoint: SocketAddr,
}

/// Keeps the server's WireGuard interface in step with the member list.
pub trait ServerHook: Send + Sync {
    fn add_peer(&self, pubkey: &[u8; 32], ip: Ipv4Addr, name: &str) -> Result<()>;
    fn remove_peer(&self, pubkey: &[u8; 32]) -> Result<()>;
    /// Addresses already taken on the interface by peers outside the mesh.
    fn used_ips(&self) -> Vec<Ipv4Addr>;
    /// Drop mesh peers that are no longer members (removed while the service
    /// was down, or by a one-off command that had no access to the interface).
    /// Peers outside the mesh are never touched.
    fn prune(&self, _members: &[[u8; 32]]) -> Result<()> {
        Ok(())
    }
}

pub struct CoordConfig {
    pub listen: SocketAddr,
    /// Where state (keys, invite, members) is kept; `None` keeps it in memory.
    pub state_file: Option<PathBuf>,
    pub network: String,
    /// The mesh subnet, e.g. 10.66.0.0/24.
    pub subnet: (Ipv4Addr, u8),
    pub server: Option<ServerMember>,
    pub hook: Option<Arc<dyn ServerHook>>,
    /// Relay limits, bytes per second.
    pub relay_per_device: u64,
    pub relay_total: u64,
}

impl CoordConfig {
    pub fn new(listen: SocketAddr) -> Self {
        CoordConfig {
            listen,
            state_file: None,
            network: "superNET".into(),
            subnet: (Ipv4Addr::new(10, 66, 0, 0), 24),
            server: None,
            hook: None,
            relay_per_device: 2 * 1024 * 1024,
            relay_total: 8 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    ip: Ipv4Addr,
    name: String,
    pubkey: String,
    relay: bool,
    joined_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    secret: String,
    invite: String,
    members: Vec<Record>,
}

struct Live {
    observed: SocketAddr,
    endpoints: Vec<SocketAddr>,
    links: Vec<LinkReport>,
    last_seen: Instant,
}

struct Member {
    rec: Record,
    key: [u8; 32],
    last_ts: u64,
    live: Option<Live>,
    bucket: Bucket,
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn new() -> Self {
        // Start full: one second of burst is allowed right away.
        Bucket { tokens: f64::MAX, at: Instant::now() }
    }
    fn take(&mut self, n: usize, rate: u64) -> bool {
        let now = Instant::now();
        let cap = rate as f64; // one second of burst
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * rate as f64).min(cap);
        self.at = now;
        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }
}

const ONLINE: Duration = Duration::from_secs(45);

pub struct Coordinator {
    cfg: CoordConfig,
    secret: [u8; 32],
    invite: String,
    members: HashMap<Ipv4Addr, Member>,
    by_key: HashMap<[u8; 32], Ipv4Addr>,
    total: Bucket,
    sock: Arc<UdpSocket>,
    pub relayed_bytes: u64,
}

impl Coordinator {
    pub async fn bind(cfg: CoordConfig) -> Result<Coordinator> {
        let persisted = match &cfg.state_file {
            Some(p) if p.exists() => {
                Some(serde_json::from_slice::<Persisted>(&std::fs::read(p).with_context(|| format!("读取 {}", p.display()))?)?)
            }
            _ => None,
        };
        let fresh = persisted.is_none();
        let (secret, invite, records) = match persisted {
            Some(p) => (proto::unb64(&p.secret)?, p.invite, p.members),
            None => (proto::generate_secret(), random_token(), Vec::new()),
        };
        let std_sock = std::net::UdpSocket::bind(cfg.listen).with_context(|| format!("监听 UDP {}", cfg.listen))?;
        std_sock.set_nonblocking(true)?;
        {
            // Relayed bursts: the OS default buffers (64 KiB on some systems) drop most of them.
            let s = socket2::SockRef::from(&std_sock);
            let _ = s.set_recv_buffer_size(4 << 20);
            let _ = s.set_send_buffer_size(4 << 20);
        }
        let sock = UdpSocket::from_std(std_sock)?;
        let mut c = Coordinator {
            cfg,
            secret,
            invite,
            members: HashMap::new(),
            by_key: HashMap::new(),
            total: Bucket::new(),
            sock: Arc::new(sock),
            relayed_bytes: 0,
        };
        for rec in records {
            let key = proto::unb64(&rec.pubkey)?;
            if let Some(hook) = &c.cfg.hook {
                if let Err(e) = hook.add_peer(&key, rec.ip, &rec.name) {
                    warn!("同步 {} 到服务器网卡失败：{e:#}", rec.ip);
                }
            }
            c.by_key.insert(key, rec.ip);
            c.members.insert(rec.ip, Member { rec, key, last_ts: 0, live: None, bucket: Bucket::new() });
        }
        if let Some(hook) = &c.cfg.hook {
            let keys: Vec<[u8; 32]> = c.by_key.keys().copied().collect();
            if let Err(e) = hook.prune(&keys) {
                warn!("清理服务器网卡上已移除的设备失败：{e:#}");
            }
        }
        // Only a new network is written here; one-off commands must not
        // overwrite the state of a running service.
        if fresh {
            c.save()?;
        }
        Ok(c)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.sock.local_addr().unwrap_or(self.cfg.listen)
    }

    pub fn public_key(&self) -> [u8; 32] {
        proto::public_of(&self.secret)
    }

    /// The invite link, given the address devices use to reach this coordinator.
    pub fn invite(&self, reachable_at: &str) -> Invite {
        Invite { coord: reachable_at.to_string(), coord_pub: self.public_key(), key: self.invite.clone(), network: self.cfg.network.clone() }
    }

    pub fn reset_invite(&mut self) -> Result<()> {
        self.invite = random_token();
        self.save()
    }

    pub fn remove(&mut self, ip: Ipv4Addr) -> Result<bool> {
        let Some(m) = self.members.remove(&ip) else { return Ok(false) };
        self.by_key.remove(&m.key);
        if let Some(hook) = &self.cfg.hook {
            hook.remove_peer(&m.key)?;
        }
        self.save()?;
        Ok(true)
    }

    fn save(&self) -> Result<()> {
        let Some(path) = &self.cfg.state_file else { return Ok(()) };
        let mut members: Vec<Record> = self.members.values().map(|m| m.rec.clone()).collect();
        members.sort_by_key(|r| r.ip);
        let p = Persisted { secret: proto::b64(&self.secret), invite: self.invite.clone(), members };
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&p)?)?;
        // It holds the coordinator's private key and the invite: owner only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Serve forever.
    pub async fn run(mut self) -> Result<()> {
        let mut buf = vec![0u8; 65_536];
        loop {
            let (n, from) = match self.sock.recv_from(&mut buf).await {
                Ok(v) => v,
                // ICMP port unreachable surfaces as an error on some systems; keep serving.
                Err(e) => {
                    warn!("recv: {e}");
                    continue;
                }
            };
            let data = &buf[..n];
            if !proto::is_ours(data) {
                continue;
            }
            match data[2] {
                proto::T_CTRL => {
                    if let Err(e) = self.handle_ctrl(data, from) {
                        tracing::debug!("ctrl from {from}: {e:#}");
                    }
                }
                proto::T_RELAY => self.handle_relay(data, from),
                _ => {}
            }
        }
    }

    fn send(&self, to: SocketAddr, peer: &[u8; 32], msg: &FromCoord) {
        let env = Envelope { ts: proto::now_ms(), msg };
        let Ok(plain) = serde_json::to_vec(&env) else { return };
        if let Ok(d) = proto::seal(proto::T_CTRL, &self.secret, peer, &plain) {
            let _ = self.sock.try_send_to(&d, to);
        }
    }

    fn handle_ctrl(&mut self, data: &[u8], from: SocketAddr) -> Result<()> {
        let (sender, plain) = proto::open(data, &self.secret)?;
        let env: Envelope<ToCoord> = serde_json::from_slice(&plain)?;
        let skew = env.ts.abs_diff(proto::now_ms());
        if skew > 5 * 60 * 1000 {
            self.send(from, &sender, &err("clock", "设备时间和服务器相差超过 5 分钟，请校准系统时间"));
            bail!("clock skew {skew} ms");
        }
        match env.msg {
            ToCoord::Join { invite, name, relay } => {
                let ip = match self.by_key.get(&sender) {
                    Some(ip) => *ip,
                    None => {
                        if !constant_eq(invite.as_bytes(), self.invite.as_bytes()) {
                            self.send(from, &sender, &err("bad_invite", "邀请链接无效或已重置"));
                            bail!("bad invite from {from}");
                        }
                        let Some(ip) = self.allocate() else {
                            self.send(from, &sender, &err("full", "网段里没有空闲地址了"));
                            bail!("subnet full");
                        };
                        let name = clean_name(&name, ip);
                        if let Some(hook) = &self.cfg.hook {
                            hook.add_peer(&sender, ip, &name).context("登记到服务器网卡")?;
                        }
                        let rec = Record { ip, name, pubkey: proto::b64(&sender), relay, joined_ms: proto::now_ms() };
                        info!("新设备加入：{} {}", rec.ip, rec.name);
                        self.by_key.insert(sender, ip);
                        self.members.insert(ip, Member { rec, key: sender, last_ts: 0, live: None, bucket: Bucket::new() });
                        self.save()?;
                        ip
                    }
                };
                self.accept_ts(ip, env.ts)?;
                self.touch(ip, from, Vec::new(), Vec::new());
                self.send_state(ip);
                self.broadcast_except(ip);
            }
            ToCoord::Hello { name, endpoints, relay, links } => {
                let Some(&ip) = self.by_key.get(&sender) else {
                    self.send(from, &sender, &err("not_member", "这台设备不在网络里（可能已被移出），请重新用邀请链接加入"));
                    bail!("hello from non-member {from}");
                };
                self.accept_ts(ip, env.ts)?;
                let was_online = self.is_online(ip);
                let changed = {
                    let m = self.members.get_mut(&ip).expect("member");
                    let new_name = clean_name(&name, ip);
                    let changed = m.rec.name != new_name || m.rec.relay != relay;
                    m.rec.name = new_name;
                    m.rec.relay = relay;
                    changed
                };
                let moved = self.members[&ip].live.as_ref().map_or(true, |l| l.observed != from || l.endpoints != endpoints);
                let relinked = self.members[&ip].live.as_ref().map_or(true, |l| link_shape(&l.links) != link_shape(&links));
                self.touch(ip, from, endpoints, links);
                if changed {
                    self.save()?;
                }
                self.send_state(ip);
                if changed || moved || relinked || !was_online {
                    self.broadcast_except(ip);
                }
            }
            ToCoord::PunchReq { peer } => {
                let Some(&ip) = self.by_key.get(&sender) else { bail!("punch from non-member") };
                self.accept_ts(ip, env.ts)?;
                let endpoints = self.endpoints_of(ip);
                if let Some(target) = self.members.get(&peer) {
                    if let Some(live) = &target.live {
                        if live.last_seen.elapsed() < ONLINE {
                            self.send(live.observed, &target.key, &FromCoord::Punch { peer: ip, endpoints });
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn accept_ts(&mut self, ip: Ipv4Addr, ts: u64) -> Result<()> {
        let m = self.members.get_mut(&ip).expect("member");
        if ts <= m.last_ts {
            bail!("replayed or reordered message from {ip}");
        }
        m.last_ts = ts;
        Ok(())
    }

    fn touch(&mut self, ip: Ipv4Addr, from: SocketAddr, endpoints: Vec<SocketAddr>, links: Vec<LinkReport>) {
        let m = self.members.get_mut(&ip).expect("member");
        let endpoints = if endpoints.is_empty() { m.live.as_ref().map(|l| l.endpoints.clone()).unwrap_or_default() } else { endpoints };
        let links = if links.is_empty() { m.live.as_ref().map(|l| l.links.clone()).unwrap_or_default() } else { links };
        m.live = Some(Live { observed: from, endpoints: endpoints.into_iter().take(16).collect(), links: links.into_iter().take(256).collect(), last_seen: Instant::now() });
    }

    fn is_online(&self, ip: Ipv4Addr) -> bool {
        self.members.get(&ip).and_then(|m| m.live.as_ref()).is_some_and(|l| l.last_seen.elapsed() < ONLINE)
    }

    fn endpoints_of(&self, ip: Ipv4Addr) -> Vec<SocketAddr> {
        let Some(live) = self.members.get(&ip).and_then(|m| m.live.as_ref()) else { return Vec::new() };
        let mut v = live.endpoints.clone();
        if !v.contains(&live.observed) {
            v.push(live.observed);
        }
        v
    }

    fn view(&self, m: &Member) -> MemberView {
        MemberView {
            ip: m.rec.ip,
            name: m.rec.name.clone(),
            pubkey: m.rec.pubkey.clone(),
            endpoints: self.endpoints_of(m.rec.ip),
            online: self.is_online(m.rec.ip),
            relay: m.rec.relay,
            server: false,
            last_seen_s: m.live.as_ref().map(|l| l.last_seen.elapsed().as_secs()),
        }
    }

    fn send_state(&self, ip: Ipv4Addr) {
        let Some(m) = self.members.get(&ip) else { return };
        let Some(live) = &m.live else { return };
        let mut members: Vec<MemberView> = self.members.values().map(|m| self.view(m)).collect();
        if let Some(s) = &self.cfg.server {
            members.push(MemberView {
                ip: s.ip,
                name: s.name.clone(),
                pubkey: proto::b64(&s.pubkey),
                endpoints: vec![s.endpoint],
                online: true,
                relay: false,
                server: true,
                last_seen_s: Some(0),
            });
        }
        members.sort_by_key(|m| m.ip);
        let links: Vec<LinkView> = self
            .members
            .values()
            .filter(|m| self.is_online(m.rec.ip))
            .flat_map(|m| m.live.iter().flat_map(|l| l.links.iter().map(|link| LinkView { from: m.rec.ip, link: link.clone() })))
            .collect();
        let state = FromCoord::State {
            network: self.cfg.network.clone(),
            prefix: self.cfg.subnet.1,
            me: self.view(m),
            observed: live.observed,
            members,
            links,
        };
        self.send(live.observed, &m.key, &state);
    }

    fn broadcast_except(&self, except: Ipv4Addr) {
        for (ip, _) in self.members.iter().filter(|(ip, _)| **ip != except) {
            if self.is_online(*ip) {
                self.send_state(*ip);
            }
        }
    }

    fn allocate(&self) -> Option<Ipv4Addr> {
        let (net, prefix) = self.cfg.subnet;
        let base = u32::from(net) & (!0u32 << (32 - prefix));
        let size = 1u32 << (32 - prefix);
        let mut used: Vec<Ipv4Addr> = self.members.keys().copied().collect();
        if let Some(s) = &self.cfg.server {
            used.push(s.ip);
        }
        if let Some(hook) = &self.cfg.hook {
            used.extend(hook.used_ips());
        }
        (2..size - 1).map(|i| Ipv4Addr::from(base + i)).find(|ip| !used.contains(ip))
    }

    fn handle_relay(&mut self, data: &[u8], from: SocketAddr) {
        let Some((dst, src, _)) = proto::parse_relay(data) else { return };
        // Only a member may relay, and only as itself from where it last said hello.
        let ok_src = self.members.get(&src).and_then(|m| m.live.as_ref()).is_some_and(|l| l.observed == from);
        if !ok_src {
            return;
        }
        let Some(target) = self.members.get(&dst).and_then(|m| m.live.as_ref()).filter(|l| l.last_seen.elapsed() < ONLINE).map(|l| l.observed) else { return };
        let rate = self.cfg.relay_per_device;
        let total = self.cfg.relay_total;
        let allowed = self.members.get_mut(&src).is_some_and(|m| m.bucket.take(data.len(), rate)) && self.total.take(data.len(), total);
        if !allowed {
            return; // over the limit: drop, WireGuard and TCP recover
        }
        if self.sock.try_send_to(data, target).is_ok() {
            self.relayed_bytes += data.len() as u64;
        }
    }
}

/// What the topology view cares about: who reaches whom and how (not byte counts).
fn link_shape(links: &[LinkReport]) -> Vec<(Ipv4Addr, proto::PathKind, Option<Ipv4Addr>)> {
    let mut v: Vec<_> = links.iter().map(|l| (l.peer, l.kind, l.via)).collect();
    v.sort_by_key(|(ip, _, _)| *ip);
    v
}

fn err(code: &str, message: &str) -> FromCoord {
    FromCoord::Error { code: code.into(), message: message.into() }
}

fn clean_name(name: &str, ip: Ipv4Addr) -> String {
    let n: String = name.chars().filter(|c| !c.is_control()).take(40).collect();
    let n = n.trim().to_string();
    if n.is_empty() {
        format!("设备 {ip}")
    } else {
        n
    }
}

fn random_token() -> String {
    use base64::Engine as _;
    let mut b = [0u8; 18];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
