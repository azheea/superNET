//! Import and export of standard WireGuard `.conf` files and `supernet://` links.

use std::net::IpAddr;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use ipnet::IpNet;

use crate::config::{default_allowed_ips, default_keepalive, default_mtu, Hysteria2Node, NodeConfig, NodeKind, WireGuardNode};

const LINK_SCHEME: &str = "supernet://";

/// Parse a wg-quick style configuration with exactly one `[Peer]`.
pub fn parse(text: &str, name: &str) -> Result<NodeConfig> {
    #[derive(PartialEq)]
    enum Section {
        None,
        Interface,
        Peer,
    }
    let mut section = Section::None;
    let mut peers = 0;
    let mut private_key = None;
    let mut public_key = None;
    let mut preshared_key = None;
    let mut endpoint = None;
    let mut address: Vec<IpNet> = Vec::new();
    let mut allowed_ips: Vec<IpNet> = Vec::new();
    let mut dns: Vec<IpAddr> = Vec::new();
    let mut mtu = None;
    let mut keepalive = None;

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.split(['#', ';']).next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = match line.to_ascii_lowercase().as_str() {
                "[interface]" => Section::Interface,
                "[peer]" => {
                    peers += 1;
                    Section::Peer
                }
                other => bail!("第 {} 行：未知的段 {other}", lineno + 1),
            };
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("第 {} 行：应为 键 = 值", lineno + 1))?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        let ctx = || format!("第 {} 行（{}）", lineno + 1, key);
        match (&section, key.as_str()) {
            (Section::Interface, "privatekey") => private_key = Some(value.to_string()),
            (Section::Interface, "address") => {
                for item in list(value) {
                    address.push(parse_net(item).with_context(ctx)?);
                }
            }
            (Section::Interface, "dns") => {
                // wg-quick also allows search domains here; we only need servers.
                dns.extend(list(value).filter_map(|v| v.parse::<IpAddr>().ok()));
            }
            (Section::Interface, "mtu") => mtu = Some(value.parse::<u16>().with_context(ctx)?),
            (Section::Interface, "listenport" | "table" | "preup" | "postup" | "predown" | "postdown" | "saveconfig" | "fwmark") => {}
            (Section::Peer, "publickey") => public_key = Some(value.to_string()),
            (Section::Peer, "presharedkey") => preshared_key = Some(value.to_string()),
            (Section::Peer, "endpoint") => endpoint = Some(value.to_string()),
            (Section::Peer, "allowedips") => {
                for item in list(value) {
                    allowed_ips.push(parse_net(item).with_context(ctx)?);
                }
            }
            (Section::Peer, "persistentkeepalive") => {
                keepalive = Some(match value.to_ascii_lowercase().as_str() {
                    "off" | "0" => None,
                    v => Some(v.parse::<u16>().with_context(ctx)?),
                });
            }
            (Section::None, _) => bail!("第 {} 行：键值必须写在 [Interface] 或 [Peer] 段里", lineno + 1),
            _ => bail!("第 {} 行：不支持的键 {key}", lineno + 1),
        }
    }

    if peers != 1 {
        bail!("需要正好一个 [Peer]，实际有 {peers} 个");
    }
    let node = WireGuardNode {
        endpoint: endpoint.context("缺少 Endpoint")?,
        private_key: private_key.context("缺少 PrivateKey")?,
        public_key: public_key.context("缺少 PublicKey")?,
        preshared_key,
        address,
        allowed_ips: if allowed_ips.is_empty() { default_allowed_ips() } else { allowed_ips },
        dns,
        mtu: mtu.unwrap_or_else(default_mtu),
        keepalive: keepalive.unwrap_or_else(default_keepalive),
    };
    node.validate()?;
    Ok(NodeConfig { name: name.trim().to_string(), kind: NodeKind::Wireguard(node) })
}

/// Render a node as a wg-quick configuration.
pub fn render(node: &WireGuardNode) -> String {
    let join = |items: Vec<String>| items.join(", ");
    let mut out = String::from("[Interface]\n");
    out += &format!("PrivateKey = {}\n", node.private_key);
    out += &format!("Address = {}\n", join(node.address.iter().map(|a| a.to_string()).collect()));
    if !node.dns.is_empty() {
        out += &format!("DNS = {}\n", join(node.dns.iter().map(|a| a.to_string()).collect()));
    }
    out += &format!("MTU = {}\n\n[Peer]\n", node.mtu);
    out += &format!("PublicKey = {}\n", node.public_key);
    if let Some(psk) = &node.preshared_key {
        out += &format!("PresharedKey = {psk}\n");
    }
    out += &format!("Endpoint = {}\n", node.endpoint);
    out += &format!("AllowedIPs = {}\n", join(node.allowed_ips.iter().map(|a| a.to_string()).collect()));
    if let Some(k) = node.keepalive {
        out += &format!("PersistentKeepalive = {k}\n");
    }
    out
}

/// `supernet://<base64url(config)>#<percent-encoded name>`
pub fn to_link(node: &NodeConfig) -> String {
    match &node.kind {
        NodeKind::Wireguard(wg) => {
            let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(render(wg));
            format!("{LINK_SCHEME}{body}#{}", percent_encode(&node.name))
        }
        NodeKind::Hysteria2(hy) => {
            let mut query = Vec::new();
            if let Some(sni) = &hy.sni {
                query.push(format!("sni={}", percent_encode(sni)));
            }
            if let Some(pin) = &hy.pin_sha256 {
                query.push(format!("pinSHA256={pin}"));
            }
            if hy.insecure {
                query.push("insecure=1".into());
            }
            if hy.down_mbps > 0 {
                query.push(format!("downmbps={}", hy.down_mbps));
            }
            let query = if query.is_empty() { String::new() } else { format!("?{}", query.join("&")) };
            format!("hysteria2://{}@{}/{query}#{}", percent_encode(&hy.password), hy.server, percent_encode(&node.name))
        }
    }
}

/// Standard share link: `hysteria2://password@host:port/?sni=..&insecure=1&pinSHA256=..#name`
/// (`hy2://` too). Unsupported options such as `obfs` are refused.
pub fn parse_hysteria2_link(link: &str, name: &str) -> Result<NodeConfig> {
    let link = link.trim();
    let rest = link
        .strip_prefix("hysteria2://")
        .or_else(|| link.strip_prefix("hy2://"))
        .context("不是 hysteria2:// 链接")?;
    let (rest, link_name) = match rest.split_once('#') {
        Some((r, n)) => (r, percent_decode(n)?),
        None => (rest, String::new()),
    };
    let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    let rest = rest.trim_end_matches('/');
    let (auth, server) = rest.rsplit_once('@').context("链接缺少密码（password@host:port）")?;
    let mut node = Hysteria2Node {
        server: server.to_string(),
        password: percent_decode(auth)?,
        sni: None,
        pin_sha256: None,
        insecure: false,
        down_mbps: 0,
    };
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v)?;
        match k {
            "sni" | "peer" => node.sni = Some(v).filter(|s| !s.is_empty()),
            "insecure" | "allowInsecure" => node.insecure = v == "1" || v.eq_ignore_ascii_case("true"),
            "pinSHA256" | "pinsha256" => node.pin_sha256 = Some(v.replace(':', "").to_ascii_lowercase()),
            "downmbps" | "down" => node.down_mbps = v.trim_end_matches("mbps").trim().parse().unwrap_or(0),
            "obfs" | "obfs-password" if !v.is_empty() => bail!("暂不支持混淆（obfs）"),
            _ => {}
        }
    }
    node.validate()?;
    let name = if name.trim().is_empty() { link_name } else { name.trim().to_string() };
    Ok(NodeConfig { name, kind: NodeKind::Hysteria2(node) })
}

pub fn from_link(link: &str) -> Result<NodeConfig> {
    let rest = link.trim().strip_prefix(LINK_SCHEME).context("不是 supernet:// 链接")?;
    let (body, name) = rest.split_once('#').unwrap_or((rest, "节点"));
    let text = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body.trim_end_matches('='))
        .context("链接内容损坏")?;
    let text = String::from_utf8(text).context("链接内容损坏")?;
    parse(&text, &percent_decode(name)?)
}

/// Accept a link, a `.conf` text, or a QR payload containing either.
pub fn import(text: &str, name: &str) -> Result<NodeConfig> {
    let trimmed = text.trim();
    if trimmed.starts_with("hysteria2://") || trimmed.starts_with("hy2://") {
        return parse_hysteria2_link(trimmed, name);
    }
    if trimmed.starts_with(LINK_SCHEME) {
        let mut node = from_link(trimmed)?;
        if !name.trim().is_empty() {
            node.name = name.trim().to_string();
        }
        Ok(node)
    } else {
        parse(trimmed, name)
    }
}

fn list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

fn parse_net(value: &str) -> Result<IpNet> {
    if let Ok(net) = value.parse::<IpNet>() {
        return Ok(net);
    }
    let ip: IpAddr = value.parse().with_context(|| format!("“{value}”不是地址"))?;
    Ok(IpNet::from(ip))
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3])?;
            out.push(u8::from_str_radix(hex, 16).context("名称编码错误")?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.66.0.2/32, fd66::2
DNS = 10.66.0.1, home.lan
# comment
[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15
";

    #[test]
    fn parses_wg_quick() {
        let node = parse(CONF, "家里").unwrap();
        let NodeKind::Wireguard(wg) = &node.kind else { panic!("wireguard node expected") };
        assert_eq!(wg.address.len(), 2);
        assert_eq!(wg.address[1].to_string(), "fd66::2/128");
        assert_eq!(wg.dns, vec!["10.66.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(wg.keepalive, Some(15));
        assert_eq!(wg.mtu, 1380);
        assert_eq!(wg.endpoint, "vpn.example.com:51820");
    }

    #[test]
    fn link_round_trip() {
        let node = parse(CONF, "东京 1").unwrap();
        let link = to_link(&node);
        assert!(link.contains("#%E4%B8%9C%E4%BA%AC%201"));
        let back = from_link(&link).unwrap();
        assert_eq!(back, node);
        assert_eq!(import(&link, "").unwrap().name, "东京 1");
    }

    #[test]
    fn hysteria2_links() {
        let pin = "ab".repeat(32);
        let link = format!("hysteria2://p%40ss%3Aword@hy.example.com:19188/?sni=hy.example.com&pinSHA256={pin}#%E9%A6%99%E6%B8%AF");
        let node = import(&link, "").unwrap();
        assert_eq!(node.name, "香港");
        let NodeKind::Hysteria2(hy) = &node.kind else { panic!("hysteria2 node expected") };
        assert_eq!((hy.password.as_str(), hy.server.as_str()), ("p@ss:word", "hy.example.com:19188"));
        assert_eq!(hy.pin_sha256.as_deref(), Some(pin.as_str()));
        assert!(!hy.insecure);
        assert_eq!(import(&to_link(&node), "").unwrap(), node);
        let insecure = import("hy2://pw@1.2.3.4:443?insecure=1", "x").unwrap();
        let NodeKind::Hysteria2(hy) = &insecure.kind else { panic!() };
        assert!(hy.insecure);
        assert!(import("hysteria2://pw@1.2.3.4:443?obfs=salamander&obfs-password=x", "x").is_err());
        assert!(import("hysteria2://1.2.3.4:443", "x").is_err());
    }

    #[test]
    fn rejects_two_peers_and_bad_keys() {
        let two = format!("{CONF}[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n");
        assert!(parse(&two, "x").is_err());
        let bad = CONF.replace("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", "short");
        assert!(parse(&bad, "x").is_err());
    }
}
