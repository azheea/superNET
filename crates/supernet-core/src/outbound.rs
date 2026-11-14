//! Where connections go: straight out of this machine, or through a node.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::OnceCell;

use crate::config::{decode_key, Hysteria2Node, NodeConfig, NodeKind, WireGuardNode};
use crate::dns::{self, Cache, DirectResolver};
use crate::target::{Host, Target};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyStream for T {}
pub type BoxStream = Box<dyn ProxyStream>;

/// Connect directly. `resolved` carries addresses already looked up for rules.
pub async fn connect_direct(target: &Target, resolved: Option<&[IpAddr]>, resolver: &DirectResolver) -> Result<BoxStream> {
    let ips: Vec<IpAddr> = match (&target.host, resolved) {
        (Host::Ip(ip), _) => vec![*ip],
        (Host::Domain(_), Some(ips)) if !ips.is_empty() => ips.to_vec(),
        (Host::Domain(d), _) => resolver.resolve(d).await?,
    };
    if ips.is_empty() {
        bail!("{} 没有地址", target.host);
    }
    let mut last = None;
    for ip in ips.iter().take(4) {
        let addr = SocketAddr::new(*ip, target.port);
        match tokio::time::timeout(CONNECT_TIMEOUT, supernet_netstack::sysnet::tcp_connect(addr)).await {
            Ok(Ok(stream)) => {
                return Ok(Box::new(stream));
            }
            Ok(Err(e)) => last = Some(anyhow::Error::from(e).context(format!("连接 {addr}"))),
            Err(_) => last = Some(anyhow::anyhow!("连接 {addr} 超时")),
        }
    }
    Err(last.unwrap())
}

/// Any node a policy can point at. Every kind is an encrypted transport.
pub enum Node {
    Wireguard(WgNode),
    Hysteria2(Hy2Node),
}

impl Node {
    pub fn new(cfg: &NodeConfig) -> Self {
        match &cfg.kind {
            NodeKind::Wireguard(wg) => Node::Wireguard(WgNode::new(cfg.name.clone(), wg.clone())),
            NodeKind::Hysteria2(hy) => Node::Hysteria2(Hy2Node { name: cfg.name.clone(), config: hy.clone(), client: OnceCell::new() }),
        }
    }

    /// Whether this node was built from `kind` (so it is kept on reload).
    pub fn matches(&self, kind: &NodeKind) -> bool {
        match (self, kind) {
            (Node::Wireguard(n), NodeKind::Wireguard(c)) => &n.config == c,
            (Node::Hysteria2(n), NodeKind::Hysteria2(c)) => &n.config == c,
            _ => false,
        }
    }

    pub async fn connect(&self, target: &Target, resolver: &DirectResolver) -> Result<BoxStream> {
        match self {
            Node::Wireguard(n) => n.connect(target, resolver).await,
            Node::Hysteria2(n) => n.connect(target, resolver).await,
        }
    }

    /// Time until the first response line of an HTTP GET to `test_url`
    /// through this node (includes connecting when nothing is open yet).
    pub async fn probe(&self, test_url: &str, resolver: &DirectResolver) -> Result<Duration> {
        let (target, path) = parse_http_url(test_url)?;
        let started = Instant::now();
        let mut stream = self.connect(&target, resolver).await?;
        let request = format!("GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: superNET\r\nConnection: close\r\n\r\n", target.host);
        stream.write_all(request.as_bytes()).await?;
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(CONNECT_TIMEOUT, stream.read(&mut buf)).await.context("测速超时")??;
        if !buf[..n].starts_with(b"HTTP/") {
            bail!("测速地址返回的不是 HTTP 响应");
        }
        Ok(started.elapsed())
    }

    /// A UDP flow to `target` through this node.
    pub async fn udp(&self, target: &Target, resolver: &DirectResolver) -> Result<UdpOut> {
        match self {
            Node::Wireguard(n) => {
                let tunnel = n.tunnel(resolver).await?;
                let ip = match &target.host {
                    Host::Ip(ip) => *ip,
                    Host::Domain(d) => *n.resolve(d, resolver).await?.first().with_context(|| format!("{d} 没有地址"))?,
                };
                Ok(UdpOut::Wireguard { socket: tunnel.bind_udp(None)?, remote: SocketAddr::new(ip, target.port) })
            }
            Node::Hysteria2(n) => {
                let client = n.client(resolver).await?;
                let session = client.udp_session().await.with_context(|| format!("节点“{}”的 UDP", n.name))?;
                Ok(UdpOut::Hysteria2 { session, remote: target.to_string() })
            }
        }
    }

    /// WireGuard tunnel counters, once the tunnel exists.
    pub fn stats(&self) -> Option<supernet_wg::TunnelStats> {
        match self {
            Node::Wireguard(n) => n.stats(),
            Node::Hysteria2(_) => None,
        }
    }

    /// Whether the node has been used (tunnel or QUIC client exists).
    pub fn active(&self) -> bool {
        match self {
            Node::Wireguard(n) => n.stats().is_some(),
            Node::Hysteria2(n) => n.client.get().is_some(),
        }
    }
}

/// One UDP flow leaving superNET: directly, or through a node.
pub enum UdpOut {
    Direct(tokio::net::UdpSocket),
    Wireguard { socket: supernet_wg::UdpSocket, remote: SocketAddr },
    Hysteria2 { session: supernet_hy2::Hy2Udp, remote: String },
}

impl UdpOut {
    /// A direct UDP socket (pinned to the physical interface in TUN mode),
    /// connected to the target's real address.
    pub async fn direct(target: &Target, resolved: &[IpAddr], resolver: &DirectResolver) -> Result<UdpOut> {
        let ip = match &target.host {
            Host::Ip(ip) => *ip,
            Host::Domain(_) if !resolved.is_empty() => resolved[0],
            Host::Domain(d) => *resolver.resolve(d).await?.first().with_context(|| format!("{d} 没有地址"))?,
        };
        let bind: SocketAddr = if ip.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
        let socket = tokio::net::UdpSocket::from_std(supernet_netstack::sysnet::udp_bind(bind)?)?;
        socket.connect(SocketAddr::new(ip, target.port)).await?;
        Ok(UdpOut::Direct(socket))
    }

    pub async fn send(&self, payload: &[u8]) -> Result<()> {
        match self {
            UdpOut::Direct(s) => {
                s.send(payload).await?;
            }
            UdpOut::Wireguard { socket, remote } => socket.send_to(payload, *remote).await?,
            UdpOut::Hysteria2 { session, remote } => session.send_to(payload, remote)?,
        }
        Ok(())
    }

    /// Next reply payload.
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            UdpOut::Direct(s) => Ok(s.recv(buf).await?),
            UdpOut::Wireguard { socket, .. } => Ok(socket.recv_from(buf).await?.0),
            UdpOut::Hysteria2 { session, .. } => {
                let (data, _from) = session.recv_from().await.context("UDP 会话已关闭")?;
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok(n)
            }
        }
    }
}

/// A Hysteria2 node: one QUIC connection, a stream per TCP connection.
/// Domains are sent as names, so the server resolves them.
pub struct Hy2Node {
    pub name: String,
    pub config: Hysteria2Node,
    client: OnceCell<Arc<supernet_hy2::Hy2Client>>,
}

impl Hy2Node {
    async fn client(&self, resolver: &DirectResolver) -> Result<Arc<supernet_hy2::Hy2Client>> {
        self.client
            .get_or_try_init(|| async {
                let cfg = &self.config;
                let server = resolve_endpoint(&cfg.server, resolver).await?;
                let cert = match (&cfg.pin_sha256, cfg.insecure) {
                    (Some(pin), _) => supernet_hy2::CertCheck::PinSha256(supernet_hy2::parse_hex_sha256(pin)?),
                    (None, true) => {
                        tracing::warn!("node {}: certificate is not verified (insecure)", self.name);
                        supernet_hy2::CertCheck::Insecure
                    }
                    (None, false) => supernet_hy2::CertCheck::WebPki,
                };
                let client = supernet_hy2::Hy2Client::new(supernet_hy2::Hy2Config {
                    server,
                    server_name: cfg.sni.clone().unwrap_or_else(|| cfg.host().to_string()),
                    password: cfg.password.clone(),
                    cert,
                    down_mbps: cfg.down_mbps,
                })?;
                Ok::<_, anyhow::Error>(Arc::new(client))
            })
            .await
            .cloned()
    }

    pub async fn connect(&self, target: &Target, resolver: &DirectResolver) -> Result<BoxStream> {
        let client = self.client(resolver).await?;
        let stream = client
            .connect_tcp(&target.to_string())
            .await
            .with_context(|| format!("经节点“{}”连接 {target}", self.name))?;
        Ok(Box::new(stream))
    }
}

/// A WireGuard node. The tunnel is created on first use and kept for the
/// lifetime of the node; boringtun re-handshakes by itself when needed.
pub struct WgNode {
    pub name: String,
    pub config: WireGuardNode,
    tunnel: OnceCell<Arc<supernet_wg::WgTunnel>>,
    dns_cache: Cache,
}

impl WgNode {
    pub fn new(name: String, config: WireGuardNode) -> Self {
        Self { name, config, tunnel: OnceCell::new(), dns_cache: Cache::default() }
    }

    pub async fn tunnel(&self, resolver: &DirectResolver) -> Result<Arc<supernet_wg::WgTunnel>> {
        self.tunnel
            .get_or_try_init(|| async {
                let cfg = &self.config;
                let endpoint = resolve_endpoint(&cfg.endpoint, resolver).await?;
                let tunnel = supernet_wg::WgTunnel::new(supernet_wg::TunnelConfig {
                    private_key: decode_key(&cfg.private_key)?,
                    peer_public_key: decode_key(&cfg.public_key)?,
                    preshared_key: cfg.preshared_key.as_deref().map(decode_key).transpose()?,
                    endpoint: Some(endpoint),
                    bind: None,
                    addresses: cfg.address.iter().map(|n| (n.addr(), n.prefix_len())).collect(),
                    mtu: cfg.mtu as usize,
                    persistent_keepalive: cfg.keepalive,
                })
                .await
                .context("创建 WireGuard 隧道")?;
                tracing::info!("node {}: tunnel to {endpoint} ready", self.name);
                Ok::<_, anyhow::Error>(Arc::new(tunnel))
            })
            .await
            .cloned()
    }

    /// Whether the tunnel exists, and its counters.
    pub fn stats(&self) -> Option<supernet_wg::TunnelStats> {
        self.tunnel.get().map(|t| t.stats())
    }

    /// Resolve through the node's DNS servers so the lookup never leaves
    /// this machine in clear text. Without configured servers, fall back to
    /// the direct resolver.
    pub async fn resolve(&self, domain: &str, resolver: &DirectResolver) -> Result<Vec<IpAddr>> {
        if self.config.dns.is_empty() {
            return resolver.resolve(domain).await;
        }
        if let Some(ips) = self.dns_cache.get(domain) {
            return Ok(ips);
        }
        let tunnel = self.tunnel(resolver).await?;
        let has_v4 = tunnel.addresses().iter().any(|a| a.is_ipv4());
        let has_v6 = tunnel.addresses().iter().any(|a| a.is_ipv6());
        let sock = tunnel.bind_udp(None)?;
        let servers: Vec<SocketAddr> = self
            .config
            .dns
            .iter()
            .filter(|ip| (ip.is_ipv4() && has_v4) || (ip.is_ipv6() && has_v6))
            .map(|ip| SocketAddr::new(*ip, 53))
            .collect();
        let (mut ips, ttl) = dns::lookup_via(&sock, &servers, domain, has_v4, has_v6)
            .await
            .with_context(|| format!("经节点“{}”解析 {domain}", self.name))?;
        ips.retain(|ip| (ip.is_ipv4() && has_v4) || (ip.is_ipv6() && has_v6));
        ips.sort_by_key(|ip| ip.is_ipv6());
        self.dns_cache.put(domain, ips.clone(), ttl);
        Ok(ips)
    }

    pub async fn connect(&self, target: &Target, resolver: &DirectResolver) -> Result<BoxStream> {
        let tunnel = self.tunnel(resolver).await?;
        let ips = match &target.host {
            Host::Ip(ip) => vec![*ip],
            Host::Domain(d) => self.resolve(d, resolver).await?,
        };
        if ips.is_empty() {
            bail!("{} 没有地址", target.host);
        }
        let mut last = None;
        for ip in ips.iter().take(3) {
            let addr = SocketAddr::new(*ip, target.port);
            match tunnel.connect_tcp(addr).await {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(e) => last = Some(anyhow::Error::from(e)),
            }
        }
        Err(last.unwrap().context(format!("经节点“{}”连接 {target}", self.name)))
    }
}

/// Trust on first use: replace "accept any certificate" on a Hysteria2 node
/// with a pin of the certificate the server presents now. Returns the pin.
pub async fn pin_hysteria2_cert(node: &mut NodeConfig, resolver: &DirectResolver) -> Result<Option<String>> {
    let NodeKind::Hysteria2(hy) = &mut node.kind else { return Ok(None) };
    if hy.pin_sha256.is_some() || !hy.insecure {
        return Ok(None);
    }
    let server = resolve_endpoint(&hy.server, resolver).await?;
    let sni = hy.sni.clone().unwrap_or_else(|| hy.host().to_string());
    let digest = supernet_hy2::fetch_cert_sha256(server, &sni).await.context("读取服务器证书")?;
    let pin = supernet_hy2::hex(&digest);
    hy.pin_sha256 = Some(pin.clone());
    hy.insecure = false;
    Ok(Some(pin))
}

pub(crate) async fn resolve_endpoint(endpoint: &str, resolver: &DirectResolver) -> Result<SocketAddr> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let target = Target::parse(endpoint, None).with_context(|| format!("Endpoint “{endpoint}”无效"))?;
    match target.host {
        Host::Ip(ip) => Ok(SocketAddr::new(ip, target.port)),
        Host::Domain(d) => {
            let ips = resolver.resolve(&d).await.context("解析节点地址")?;
            let ip = ips.first().with_context(|| format!("节点地址 {d} 没有解析结果"))?;
            Ok(SocketAddr::new(*ip, target.port))
        }
    }
}

/// `http://host[:port]/path` → target and path. Only plain HTTP.
pub fn parse_http_url(url: &str) -> Result<(Target, String)> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("HTTP://"))
        .with_context(|| format!("测速地址必须以 http:// 开头：{url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let target = Target::parse(authority, Some(80)).with_context(|| format!("地址“{authority}”无效"))?;
    Ok((target, path.to_string()))
}

/// Error used when a rule says REJECT.
pub fn rejected(target: &Target) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("{target} 被规则拒绝"))
}
