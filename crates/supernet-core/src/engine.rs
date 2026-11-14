//! The engine: owns the current profile, routes connections and runs the
//! local proxy listener.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::config::{Mode, NodeKind, Profile, DIRECT, REJECT};
use crate::dns::{DirectResolver, Upstream};
use crate::geoip::GeoIp;
use crate::outbound::{connect_direct, BoxStream, Node};
use crate::rules::{Query, RuleEngine, Step};
use crate::stats::{ConnGuard, ConnInfo, Counted, LogBuffer, LogLine, Tracker};
use crate::target::{Host, Target};

/// An immutable view of the configuration; replaced as a whole on changes.
struct Snapshot {
    profile: Profile,
    rules: Arc<RuleEngine>,
    nodes: HashMap<String, Arc<Node>>,
    resolver: Arc<DirectResolver>,
}

pub(crate) struct Inner {
    snapshot: RwLock<Arc<Snapshot>>,
    pub(crate) tracker: Arc<Tracker>,
    pub(crate) logs: LogBuffer,
    running: tokio::sync::Mutex<Option<Running>>,
    tun: tokio::sync::Mutex<Option<crate::tun::TunRuntime>>,
    base_dir: Option<PathBuf>,
}

struct Running {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

/// How one target would be routed.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RouteInfo {
    pub target: String,
    pub rule: String,
    pub policy: String,
    /// Policy plus the node a group resolved to, e.g. `代理 → 东京`.
    pub chain: String,
    /// `DIRECT`, `REJECT` or a node name.
    pub outbound: String,
    /// Addresses looked up while evaluating IP rules, if any.
    pub resolved: Vec<IpAddr>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub running: bool,
    pub listen: Option<SocketAddr>,
    pub mode: Mode,
    pub connections: usize,
    pub total_upload: u64,
    pub total_download: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeStatus {
    pub name: String,
    /// `wireguard` or `hysteria2`.
    pub kind: &'static str,
    pub endpoint: String,
    /// The tunnel has been created (first use or a latency test).
    pub active: bool,
    pub since_handshake_secs: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

pub(crate) enum OpenError {
    Rejected,
    Failed(anyhow::Error),
}

pub(crate) enum Out {
    Direct,
    Reject,
    Node(Arc<Node>),
}

impl Engine {
    /// Build an engine for `profile`. `base_dir` resolves relative rule-set paths.
    pub fn new(profile: Profile, base_dir: Option<PathBuf>) -> Result<(Engine, Vec<String>)> {
        let (snapshot, warnings) = build_snapshot(profile, None, base_dir.as_deref())?;
        let inner = Arc::new(Inner {
            snapshot: RwLock::new(Arc::new(snapshot)),
            tracker: Arc::new(Tracker::default()),
            logs: LogBuffer::default(),
            running: tokio::sync::Mutex::new(None),
            tun: tokio::sync::Mutex::new(None),
            base_dir,
        });
        for w in &warnings {
            inner.logs.push("warn", w.clone());
        }
        Ok((Engine { inner }, warnings))
    }

    pub fn profile(&self) -> Profile {
        self.inner.snapshot().profile.clone()
    }

    /// Replace the profile. Nodes whose settings did not change keep their tunnels.
    pub async fn apply(&self, profile: Profile) -> Result<Vec<String>> {
        let old = self.inner.snapshot();
        let (snapshot, warnings) = build_snapshot(profile, Some(&old), self.inner.base_dir.as_deref())?;
        let relisten = snapshot.profile.listen != old.profile.listen || snapshot.profile.allow_lan != old.profile.allow_lan;
        *self.inner.snapshot.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(snapshot);
        for w in &warnings {
            self.inner.logs.push("warn", w.clone());
        }
        self.inner.logs.push("info", "配置已更新".into());
        if relisten && self.inner.running.lock().await.is_some() {
            self.stop().await;
            self.start().await?;
        }
        Ok(warnings)
    }

    pub fn set_mode(&self, mode: Mode) {
        self.update_profile(|p| p.mode = mode);
        self.inner.logs.push("info", format!("模式切换为 {mode:?}"));
    }

    /// Choose the node a `select` group uses.
    pub fn select(&self, group: &str, node: &str) -> Result<()> {
        let snap = self.inner.snapshot();
        let g = snap.profile.group(group).with_context(|| format!("没有策略组“{group}”"))?;
        if !g.nodes.iter().any(|n| n == node) {
            bail!("“{node}”不在策略组“{group}”里");
        }
        self.update_profile(|p| {
            p.selected.insert(group.to_string(), node.to_string());
        });
        self.inner.logs.push("info", format!("策略组“{group}”切换到“{node}”"));
        Ok(())
    }

    /// Changes that do not affect rules or nodes.
    fn update_profile(&self, f: impl FnOnce(&mut Profile)) {
        let mut guard = self.inner.snapshot.write().unwrap_or_else(|e| e.into_inner());
        let mut profile = guard.profile.clone();
        f(&mut profile);
        *guard = Arc::new(Snapshot {
            profile,
            rules: guard.rules.clone(),
            nodes: guard.nodes.clone(),
            resolver: guard.resolver.clone(),
        });
    }

    /// Start TUN mode. The returned ports carry raw IP packets to and from the
    /// TUN device, which the platform layer creates and wires up. Set
    /// `sysnet::set_bypass_interface` first so superNET's own sockets avoid
    /// the TUN.
    pub async fn start_tun(&self, mtu: usize) -> Result<supernet_netstack::PacketPorts> {
        let mut tun = self.inner.tun.lock().await;
        if tun.is_some() {
            anyhow::bail!("TUN 模式已经在运行");
        }
        // Rebuild nodes so their sockets are created with the bypass pinning.
        self.reset_nodes();
        let (stack, ports, udp) = supernet_netstack::NetStack::new(mtu);
        *tun = Some(crate::tun::start(self.inner.clone(), stack, udp));
        self.inner.logs.push("info", "TUN 模式已启动".into());
        Ok(ports)
    }

    pub async fn stop_tun(&self) {
        if self.inner.tun.lock().await.take().is_some() {
            self.reset_nodes();
            self.inner.logs.push("info", "TUN 模式已停止".into());
        }
    }

    pub async fn tun_active(&self) -> bool {
        self.inner.tun.lock().await.is_some()
    }

    /// Fresh node objects (tunnels and QUIC clients reconnect on next use).
    fn reset_nodes(&self) {
        let mut guard = self.inner.snapshot.write().unwrap_or_else(|e| e.into_inner());
        let nodes = guard.profile.nodes.iter().map(|cfg| (cfg.name.clone(), Arc::new(Node::new(cfg)))).collect();
        *guard = Arc::new(Snapshot {
            profile: guard.profile.clone(),
            rules: guard.rules.clone(),
            nodes,
            resolver: guard.resolver.clone(),
        });
    }

    /// Start the local HTTP + SOCKS5 proxy. Returns the bound address.
    pub async fn start(&self) -> Result<SocketAddr> {
        let mut running = self.inner.running.lock().await;
        if let Some(r) = running.as_ref() {
            return Ok(r.addr);
        }
        let profile = self.inner.snapshot().profile.clone();
        let bind = if profile.allow_lan { SocketAddr::new([0, 0, 0, 0].into(), profile.listen.port()) } else { profile.listen };
        let listener = TcpListener::bind(bind).await.with_context(|| format!("监听 {bind}（端口可能被占用）"))?;
        let addr = listener.local_addr()?;
        let inner = self.inner.clone();
        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((sock, peer)) => {
                        tokio::spawn(crate::inbound::handle(inner.clone(), sock, peer));
                    }
                    Err(e) => {
                        tracing::warn!("accept: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
        *running = Some(Running { addr, task });
        self.inner.logs.push("info", format!("代理已启动：{addr}（HTTP 和 SOCKS5）"));
        Ok(addr)
    }

    /// Stop listening and close every open connection.
    pub async fn stop(&self) {
        if let Some(r) = self.inner.running.lock().await.take() {
            r.task.abort();
            self.inner.tracker.close_all();
            self.inner.logs.push("info", "代理已停止".into());
        }
    }

    pub async fn status(&self) -> Status {
        let running = self.inner.running.lock().await;
        let snap = self.inner.snapshot();
        Status {
            running: running.is_some(),
            listen: running.as_ref().map(|r| r.addr),
            mode: snap.profile.mode,
            connections: self.inner.tracker.count(),
            total_upload: self.inner.tracker.total_up.load(std::sync::atomic::Ordering::Relaxed),
            total_download: self.inner.tracker.total_down.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    pub fn nodes(&self) -> Vec<NodeStatus> {
        let snap = self.inner.snapshot();
        snap.profile
            .nodes
            .iter()
            .map(|cfg| {
                let (kind, endpoint) = match &cfg.kind {
                    NodeKind::Wireguard(wg) => ("wireguard", wg.endpoint.clone()),
                    NodeKind::Hysteria2(hy) => ("hysteria2", hy.server.clone()),
                };
                let node = snap.nodes.get(&cfg.name);
                let stats = node.and_then(|n| n.stats());
                NodeStatus {
                    name: cfg.name.clone(),
                    kind,
                    endpoint,
                    active: node.is_some_and(|n| n.active()),
                    since_handshake_secs: stats.as_ref().and_then(|s| s.since_handshake).map(|d| d.as_secs()),
                    tx_bytes: stats.as_ref().map_or(0, |s| s.tx_bytes),
                    rx_bytes: stats.as_ref().map_or(0, |s| s.rx_bytes),
                }
            })
            .collect()
    }

    /// Measure a node's latency with the profile's test URL.
    pub async fn probe(&self, node: &str) -> Result<Duration> {
        let snap = self.inner.snapshot();
        let n = snap.nodes.get(node).with_context(|| format!("没有节点“{node}”"))?.clone();
        let result = n.probe(&snap.profile.test_url, &snap.resolver).await;
        match &result {
            Ok(d) => self.inner.logs.push("info", format!("节点“{node}”延迟 {} ms", d.as_millis())),
            Err(e) => self.inner.logs.push("warn", format!("节点“{node}”测速失败：{e:#}")),
        }
        result
    }

    /// How `target` (`host:port`, port defaults to 443) would be routed.
    pub async fn explain(&self, target: &str) -> Result<RouteInfo> {
        let target = Target::parse(target, Some(443)).with_context(|| format!("“{target}”不是有效的地址"))?;
        let snap = self.inner.snapshot();
        let (info, _) = route(&snap, &target).await;
        Ok(info)
    }

    pub fn connections(&self) -> Vec<ConnInfo> {
        self.inner.tracker.list()
    }

    pub fn close_connection(&self, id: u64) -> bool {
        self.inner.tracker.close(id)
    }

    pub fn logs(&self, after: u64) -> Vec<LogLine> {
        self.inner.logs.since(after)
    }

    /// Add a line to the in-app log (`info`, `warn` or `error`).
    pub fn log(&self, level: &'static str, message: String) {
        self.inner.logs.push(level, message);
    }
}

impl Inner {
    fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Route a target without connecting (TUN UDP sessions).
    pub(crate) async fn decide(&self, target: &Target) -> (RouteInfo, Out, Arc<DirectResolver>) {
        let snap = self.snapshot();
        let (info, out) = route(&snap, target).await;
        (info, out, snap.resolver.clone())
    }

    /// Route and connect. The guard keeps the connection in the live list.
    pub(crate) async fn open(&self, target: &Target, inbound: &'static str) -> Result<(Counted<BoxStream>, ConnGuard), OpenError> {
        self.open_with_hint(target, inbound, None).await
    }

    /// Like `open`; `ip_hint` is the address the application itself chose
    /// (TUN with a sniffed name): direct connections go there instead of
    /// resolving the name again.
    pub(crate) async fn open_with_hint(
        &self,
        target: &Target,
        inbound: &'static str,
        ip_hint: Option<IpAddr>,
    ) -> Result<(Counted<BoxStream>, ConnGuard), OpenError> {
        let snap = self.snapshot();
        let (info, out) = route(&snap, target).await;
        let connected = match out {
            Out::Reject => {
                self.logs.push("info", format!("{target} 被拒绝（{}）", info.rule));
                return Err(OpenError::Rejected);
            }
            Out::Direct => match ip_hint {
                Some(ip) => connect_direct(target, Some(&[ip]), &snap.resolver).await,
                None => connect_direct(target, Some(&info.resolved), &snap.resolver).await,
            },
            Out::Node(node) => node.connect(target, &snap.resolver).await,
        };
        match connected {
            Ok(stream) => {
                self.logs.push("info", format!("{target} → {}（{}）", info.chain, info.rule));
                let guard = self.tracker.register(inbound, target.to_string(), info.rule, info.chain);
                Ok((Counted::new(stream, &guard, &self.tracker), guard))
            }
            Err(e) => {
                self.logs.push("warn", format!("{target} → {} 失败：{e:#}", info.chain));
                Err(OpenError::Failed(e))
            }
        }
    }
}

fn build_snapshot(profile: Profile, old: Option<&Snapshot>, base_dir: Option<&std::path::Path>) -> Result<(Snapshot, Vec<String>)> {
    profile.validate()?;
    let mut warnings = Vec::new();
    let geoip = match &profile.geoip {
        Some(path) => match GeoIp::open(path) {
            Ok(g) => Some(Arc::new(g)),
            Err(e) => {
                warnings.push(format!("{e:#}"));
                None
            }
        },
        None => None,
    };
    let (rules, rule_warnings) = RuleEngine::compile(&profile, geoip, base_dir)?;
    warnings.extend(rule_warnings);

    let mut nodes = HashMap::new();
    for cfg in &profile.nodes {
        let reused = old.and_then(|o| o.nodes.get(&cfg.name)).filter(|n| n.matches(&cfg.kind)).cloned();
        nodes.insert(cfg.name.clone(), reused.unwrap_or_else(|| Arc::new(Node::new(cfg))));
    }

    let resolver = match old {
        Some(o) if o.profile.dns == profile.dns => o.resolver.clone(),
        _ => {
            let upstreams = profile.dns.direct.iter().map(|s| Upstream::parse(s)).collect::<Result<Vec<_>>>()?;
            Arc::new(DirectResolver::new(upstreams))
        }
    };
    Ok((Snapshot { profile, rules: Arc::new(rules), nodes, resolver }, warnings))
}

/// The policy used in global mode: the first group, else the first node.
fn global_policy(profile: &Profile) -> String {
    profile
        .groups
        .first()
        .map(|g| g.name.clone())
        .or_else(|| profile.nodes.first().map(|n| n.name.clone()))
        .unwrap_or_else(|| DIRECT.to_string())
}

async fn route(snap: &Snapshot, target: &Target) -> (RouteInfo, Out) {
    let mut resolved = Vec::new();
    let (rule, policy) = match snap.profile.mode {
        Mode::Direct => ("模式：直连".to_string(), DIRECT.to_string()),
        Mode::Global => ("模式：全局".to_string(), global_policy(&snap.profile)),
        Mode::Rule => {
            let mut query = Query {
                domain: target.domain().map(str::to_string),
                ips: match target.host {
                    Host::Ip(ip) => Some(vec![ip]),
                    Host::Domain(_) => None,
                },
                port: target.port,
            };
            let mut start = 0;
            loop {
                match snap.rules.evaluate(&query, start) {
                    Step::Matched(m) => break (m.rule, m.policy),
                    Step::NeedsIp { resume_at } => {
                        let domain = query.domain.clone().unwrap_or_default();
                        let ips = match snap.resolver.resolve(&domain).await {
                            Ok(ips) => ips,
                            Err(e) => {
                                tracing::debug!("rule resolution for {domain}: {e:#}");
                                Vec::new()
                            }
                        };
                        resolved = ips.clone();
                        query.ips = Some(ips);
                        start = resume_at;
                    }
                }
            }
        }
    };

    let (chain, outbound, out) = resolve_policy(snap, &policy);
    (RouteInfo { target: target.to_string(), rule, policy, chain, outbound, resolved }, out)
}

fn resolve_policy(snap: &Snapshot, policy: &str) -> (String, String, Out) {
    let leaf = |name: &str| -> (String, Out) {
        match name {
            DIRECT => (DIRECT.to_string(), Out::Direct),
            REJECT => (REJECT.to_string(), Out::Reject),
            node => match snap.nodes.get(node) {
                Some(n) => (node.to_string(), Out::Node(n.clone())),
                // Validation prevents this; fail closed rather than leak.
                None => (REJECT.to_string(), Out::Reject),
            },
        }
    };
    match snap.profile.group(policy) {
        Some(group) => {
            let member = snap
                .profile
                .selected
                .get(policy)
                .filter(|m| group.nodes.contains(m))
                .cloned()
                .unwrap_or_else(|| group.nodes[0].clone());
            let (name, out) = leaf(&member);
            (format!("{policy} → {name}"), name, out)
        }
        None => {
            let (name, out) = leaf(policy);
            (name.clone(), name, out)
        }
    }
}
