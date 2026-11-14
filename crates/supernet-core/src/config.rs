//! The profile: everything the user configures, stored as YAML.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

pub const DIRECT: &str = "DIRECT";
pub const REJECT: &str = "REJECT";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Follow the rules.
    #[default]
    Rule,
    /// Everything through the selected node.
    Global,
    /// Nothing through any node.
    Direct,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    pub mode: Mode,
    /// Local HTTP + SOCKS5 proxy address.
    pub listen: SocketAddr,
    /// Accept proxy clients from the LAN (binds all interfaces on the same port).
    pub allow_lan: bool,
    /// Point the OS proxy settings at `listen` while running.
    pub system_proxy: bool,
    /// Capture all traffic with a TUN device while connected (needs admin).
    pub tun: bool,
    /// Connect as soon as the app starts.
    pub auto_connect: bool,
    /// Plain-HTTP URL used to measure node latency.
    pub test_url: String,
    /// Optional MaxMind-format country database for GEOIP rules.
    pub geoip: Option<PathBuf>,
    pub dns: DnsConfig,
    pub nodes: Vec<NodeConfig>,
    pub groups: Vec<GroupConfig>,
    /// Which node each `select` group currently uses.
    pub selected: BTreeMap<String, String>,
    /// Clash-style rules, e.g. `DOMAIN-SUFFIX,github.com,代理`.
    pub rules: Vec<String>,
    pub rule_sets: BTreeMap<String, RuleSetConfig>,
    /// Membership of a superNET virtual network (works in TUN mode).
    pub mesh: Option<MeshProfile>,
}

/// This device in a virtual network.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MeshProfile {
    /// The `supernet-net://` invite link.
    pub invite: String,
    /// This device's private key (base64); its identity in the network.
    pub private_key: String,
    pub name: String,
    /// Relay traffic for devices that cannot reach each other directly.
    #[serde(default = "yes")]
    pub relay: bool,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            mode: Mode::Rule,
            listen: SocketAddr::from(([127, 0, 0, 1], 7890)),
            allow_lan: false,
            system_proxy: false,
            tun: false,
            auto_connect: false,
            test_url: "http://www.gstatic.com/generate_204".into(),
            geoip: None,
            dns: DnsConfig::default(),
            nodes: Vec::new(),
            groups: Vec::new(),
            selected: BTreeMap::new(),
            rules: vec!["MATCH,DIRECT".into()],
            rule_sets: BTreeMap::new(),
            mesh: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    /// Resolvers for direct traffic and for IP rules: `system` or a DNS server IP
    /// (optionally `ip:port`).
    pub direct: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self { direct: vec!["system".into()] }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    #[serde(flatten)]
    pub kind: NodeKind,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum NodeKind {
    Wireguard(WireGuardNode),
    /// QUIC + TLS 1.3; tolerates the lossy paths where WireGuard stalls.
    Hysteria2(Hysteria2Node),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Hysteria2Node {
    /// `host:port` of the server.
    pub server: String,
    pub password: String,
    /// TLS server name; defaults to the host of `server`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// SHA-256 of the server certificate (hex). Self-signed servers are
    /// pinned, so the connection is both encrypted and authenticated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_sha256: Option<String>,
    /// Accept any certificate (encrypted but unauthenticated). Avoid.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub insecure: bool,
    /// Our download capacity in Mbit/s; 0 lets the server use BBR.
    #[serde(default)]
    pub down_mbps: u32,
}

impl Hysteria2Node {
    pub fn validate(&self) -> Result<()> {
        let (host, port) = self.server.rsplit_once(':').context("服务器地址应为 host:端口")?;
        if host.is_empty() || port.parse::<u16>().map_or(true, |p| p == 0) {
            bail!("服务器地址“{}”无效", self.server);
        }
        if self.password.is_empty() {
            bail!("缺少密码");
        }
        if let Some(pin) = &self.pin_sha256 {
            supernet_hy2::parse_hex_sha256(pin)?;
        }
        Ok(())
    }

    /// Host part of `server`, without IPv6 brackets.
    pub fn host(&self) -> &str {
        let host = self.server.rsplit_once(':').map_or(self.server.as_str(), |(h, _)| h);
        host.trim_start_matches('[').trim_end_matches(']')
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireGuardNode {
    /// `host:port` of the server.
    pub endpoint: String,
    /// Base64 client private key.
    pub private_key: String,
    /// Base64 server public key.
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    /// Our addresses inside the tunnel.
    pub address: Vec<IpNet>,
    #[serde(default = "default_allowed_ips")]
    pub allowed_ips: Vec<IpNet>,
    /// DNS servers reached through the tunnel; used for domains sent to this node.
    #[serde(default)]
    pub dns: Vec<IpAddr>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default = "default_keepalive")]
    pub keepalive: Option<u16>,
}

pub fn default_allowed_ips() -> Vec<IpNet> {
    vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]
}

/// Conservative so that PPPoE and mobile links work without fragmentation.
pub fn default_mtu() -> u16 {
    1380
}

pub fn default_keepalive() -> Option<u16> {
    Some(25)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GroupConfig {
    pub name: String,
    #[serde(rename = "type", default)]
    pub kind: GroupKind,
    pub nodes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupKind {
    /// The user picks the node.
    #[default]
    Select,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RuleSetConfig {
    /// Local file: one entry per line, or a Clash `payload:` YAML list.
    pub path: PathBuf,
    #[serde(default)]
    pub behavior: RuleSetBehavior,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetBehavior {
    /// `example.com` (exact) or `+.example.com` (domain and subdomains).
    Domain,
    /// One CIDR per line.
    Ipcidr,
    /// Rules without a policy, e.g. `DOMAIN-SUFFIX,example.com`.
    #[default]
    Classical,
}

impl Profile {
    pub fn from_yaml(text: &str) -> Result<Profile> {
        let profile: Profile = serde_yaml_ng::from_str(text).context("配置文件格式错误")?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn to_yaml(&self) -> Result<String> {
        Ok(serde_yaml_ng::to_string(self)?)
    }

    pub fn load(path: &Path) -> Result<Profile> {
        let text = std::fs::read_to_string(path).with_context(|| format!("读取 {}", path.display()))?;
        Self::from_yaml(&text)
    }

    /// Write atomically so a crash never leaves half a profile behind.
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("yaml.tmp");
        std::fs::write(&tmp, self.to_yaml()?)?;
        std::fs::rename(&tmp, path).with_context(|| format!("写入 {}", path.display()))?;
        Ok(())
    }

    pub fn node(&self, name: &str) -> Option<&NodeConfig> {
        self.nodes.iter().find(|n| n.name == name)
    }

    pub fn group(&self, name: &str) -> Option<&GroupConfig> {
        self.groups.iter().find(|g| g.name == name)
    }

    /// Names a rule may use as its policy.
    pub fn policy_names(&self) -> HashSet<String> {
        let mut names: HashSet<String> = [DIRECT, REJECT].iter().map(|s| s.to_string()).collect();
        names.extend(self.nodes.iter().map(|n| n.name.clone()));
        names.extend(self.groups.iter().map(|g| g.name.clone()));
        names
    }

    pub fn validate(&self) -> Result<()> {
        let mut seen = HashSet::new();
        for name in self.nodes.iter().map(|n| &n.name).chain(self.groups.iter().map(|g| &g.name)) {
            if name.trim().is_empty() || name.contains(',') {
                bail!("名称“{name}”无效：不能为空，也不能包含逗号");
            }
            if name == DIRECT || name == REJECT {
                bail!("名称“{name}”是保留字");
            }
            if !seen.insert(name.as_str()) {
                bail!("名称“{name}”重复（节点和策略组不能重名）");
            }
        }
        for node in &self.nodes {
            match &node.kind {
                NodeKind::Wireguard(wg) => wg.validate(),
                NodeKind::Hysteria2(hy) => hy.validate(),
            }
            .with_context(|| format!("节点“{}”", node.name))?;
        }
        for group in &self.groups {
            if group.nodes.is_empty() {
                bail!("策略组“{}”没有节点", group.name);
            }
            for member in &group.nodes {
                if self.node(member).is_none() && member != DIRECT {
                    bail!("策略组“{}”引用了不存在的节点“{member}”", group.name);
                }
            }
        }
        for (group, node) in &self.selected {
            if let Some(g) = self.group(group) {
                if !g.nodes.contains(node) {
                    bail!("策略组“{group}”当前选择的“{node}”不在组内");
                }
            }
        }
        Ok(())
    }
}

impl WireGuardNode {
    pub fn validate(&self) -> Result<()> {
        decode_key(&self.private_key).context("私钥")?;
        decode_key(&self.public_key).context("公钥")?;
        if let Some(psk) = &self.preshared_key {
            decode_key(psk).context("预共享密钥")?;
        }
        if self.address.is_empty() {
            bail!("缺少隧道地址（Address）");
        }
        let (host, port) = self.endpoint.rsplit_once(':').context("Endpoint 应为 host:port")?;
        if host.is_empty() || port.parse::<u16>().map_or(true, |p| p == 0) {
            bail!("Endpoint “{}” 无效", self.endpoint);
        }
        if !(576..=9000).contains(&self.mtu) {
            bail!("MTU {} 超出范围 576–9000", self.mtu);
        }
        Ok(())
    }
}

/// Decode a base64 WireGuard key.
pub fn decode_key(key: &str) -> Result<[u8; 32]> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(key.trim())
        .context("不是有效的 Base64")?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("长度应为 32 字节"))
}

pub fn encode_key(key: &[u8; 32]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
mode: rule
nodes:
  - name: 东京
    type: wireguard
    endpoint: 203.0.113.10:51820
    private_key: "aGVsbG8gd29ybGQgdGhpcyBpcyAzMiBieXRlcyEhISE="
    public_key: "aGVsbG8gd29ybGQgdGhpcyBpcyAzMiBieXRlcyEhISE="
    address: [10.66.0.2/32]
    dns: [10.66.0.1]
groups:
  - name: 代理
    nodes: [东京]
rules:
  - DOMAIN-SUFFIX,github.com,代理
  - MATCH,DIRECT
"#;

    #[test]
    fn yaml_round_trip_with_defaults() {
        let p = Profile::from_yaml(YAML).unwrap();
        assert_eq!(p.listen.to_string(), "127.0.0.1:7890");
        let NodeKind::Wireguard(wg) = &p.nodes[0].kind else { panic!("wireguard node expected") };
        assert_eq!(wg.mtu, 1380);
        assert_eq!(wg.keepalive, Some(25));
        assert_eq!(wg.allowed_ips.len(), 2);
        assert_eq!(p.groups[0].kind, GroupKind::Select);
        let again = Profile::from_yaml(&p.to_yaml().unwrap()).unwrap();
        assert_eq!(again, p);
    }

    #[test]
    fn rejects_bad_references() {
        let bad = YAML.replace("nodes: [东京]", "nodes: [大阪]");
        let err = Profile::from_yaml(&bad).unwrap_err();
        assert!(format!("{err:#}").contains("大阪"));
        let dup = YAML.replace("name: 代理", "name: 东京");
        assert!(Profile::from_yaml(&dup).is_err());
    }
}
