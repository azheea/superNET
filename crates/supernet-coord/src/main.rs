//! supernet-coord: the virtual network's coordinator.
//!
//! ```text
//! supernet-coord run    --public HOST:PORT [--listen 0.0.0.0:19190] [--state FILE] [--wg wg0] [--network NAME]
//! supernet-coord invite --public HOST:PORT [--state FILE]          # print the invite link
//! supernet-coord reset-invite [--state FILE]                       # old links stop working (restart the service)
//! supernet-coord members [--state FILE]
//! supernet-coord remove IP [--state FILE] [--wg wg0]               # then restart the service
//! ```
//!
//! With `--wg wg0` the server's kernel WireGuard interface is a member of
//! the network (its address, e.g. 10.66.0.1): every device that joins is
//! added to it (and to /etc/wireguard/wg0.conf, so it survives reboots).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use supernet_mesh::coord::{CoordConfig, Coordinator, ServerHook, ServerMember};
use supernet_mesh::proto;

struct Args {
    cmd: String,
    public: Option<String>,
    listen: SocketAddr,
    state: PathBuf,
    wg: Option<String>,
    network: String,
    ip: Option<Ipv4Addr>,
}

fn parse() -> Result<Args> {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_else(|| "help".into());
    let mut a = Args {
        cmd,
        public: None,
        listen: SocketAddr::from(([0, 0, 0, 0], proto::DEFAULT_PORT)),
        state: PathBuf::from("/var/lib/supernet-coord/state.json"),
        wg: None,
        network: "superNET".into(),
        ip: None,
    };
    while let Some(arg) = it.next() {
        let mut val = || it.next().with_context(|| format!("{arg} 需要一个值"));
        match arg.as_str() {
            "--public" => a.public = Some(val()?),
            "--listen" => a.listen = val()?.parse().context("--listen 格式是 IP:端口")?,
            "--state" => a.state = val()?.into(),
            "--wg" => a.wg = Some(val()?),
            "--network" => a.network = val()?,
            other if a.cmd == "remove" && a.ip.is_none() => a.ip = Some(other.parse().context("要移除的设备地址")?),
            other => bail!("未知参数 {other}"),
        }
    }
    Ok(a)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).without_time().init();
    let a = parse()?;
    match a.cmd.as_str() {
        "run" => run(a).await,
        "invite" => {
            let public = a.public.clone().context("缺少 --public 服务器地址:端口")?;
            let c = Coordinator::bind(offline_cfg(&a)).await?;
            println!("{}", c.invite(&public).to_link());
            Ok(())
        }
        "reset-invite" => {
            let mut c = Coordinator::bind(offline_cfg(&a)).await?;
            c.reset_invite()?;
            println!("邀请密钥已重置；重启服务后旧链接失效。用 invite 查看新链接。");
            Ok(())
        }
        "members" => {
            let raw = std::fs::read(&a.state).with_context(|| format!("读取 {}", a.state.display()))?;
            let v: serde_like::State = serde_like::parse(&raw)?;
            for m in v.members {
                println!("{}\t{}\t{}", m.0, m.1, m.2);
            }
            Ok(())
        }
        "remove" => {
            let ip = a.ip.context("用法：supernet-coord remove 10.66.0.x")?;
            let mut cfg = offline_cfg(&a);
            if let Some(wg) = &a.wg {
                cfg.hook = Some(Arc::new(WgHook::new(wg)));
            }
            let mut c = Coordinator::bind(cfg).await?;
            if c.remove(ip)? {
                // The service also drops it from the WireGuard interface when it restarts.
                println!("已移除 {ip}；请重启服务（systemctl restart supernet-coord），它会同时把这台设备从服务器网卡上删掉");
            } else {
                println!("网络里没有 {ip}");
            }
            Ok(())
        }
        _ => {
            println!("supernet-coord run --public HOST:PORT [--listen 0.0.0.0:19190] [--state FILE] [--wg wg0] [--network NAME]");
            println!("supernet-coord invite --public HOST:PORT | reset-invite | members | remove IP");
            Ok(())
        }
    }
}

/// For one-off commands: bind an ephemeral loopback port, never the service's.
fn offline_cfg(a: &Args) -> CoordConfig {
    let mut cfg = CoordConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    cfg.state_file = Some(a.state.clone());
    cfg.network = a.network.clone();
    cfg
}

async fn run(a: Args) -> Result<()> {
    let public = a.public.clone().context("缺少 --public 服务器地址:端口（设备用它连接协调服务）")?;
    if let Some(dir) = a.state.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut cfg = CoordConfig::new(a.listen);
    cfg.state_file = Some(a.state.clone());
    cfg.network = a.network.clone();
    if let Some(wg) = &a.wg {
        let hook = WgHook::new(wg);
        let host = public.rsplit_once(':').map_or(public.as_str(), |(h, _)| h);
        let member = hook.server_member(host).context("读取服务器的 WireGuard 网卡")?;
        cfg.subnet = (member.ip, hook.prefix().unwrap_or(24));
        tracing::info!("服务器成员：{} {}（{}）", member.ip, member.endpoint, proto::b64(&member.pubkey));
        cfg.server = Some(member);
        cfg.hook = Some(Arc::new(hook));
    }
    let c = Coordinator::bind(cfg).await?;
    // The invite key is a secret: not in the journal. `supernet-coord invite` prints the link.
    tracing::info!("协调服务已启动：{}，网络 {}，公钥 {}", c.local_addr(), a.network, proto::b64(&c.public_key()));
    c.run().await
}

// ------------------------------------------------------------------ wg0

struct WgHook {
    iface: String,
    conf: PathBuf,
}

impl WgHook {
    fn new(iface: &str) -> Self {
        WgHook { iface: iface.into(), conf: PathBuf::from(format!("/etc/wireguard/{iface}.conf")) }
    }

    fn wg(&self, args: &[&str]) -> Result<String> {
        let out = std::process::Command::new("wg").args(args).output().context("运行 wg")?;
        if !out.status.success() {
            bail!("wg {}：{}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn address(&self) -> Result<(Ipv4Addr, u8)> {
        let out = std::process::Command::new("ip").args(["-4", "-o", "addr", "show", "dev", &self.iface]).output()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let cidr = text.split_whitespace().skip_while(|w| *w != "inet").nth(1).context("网卡没有 IPv4 地址")?;
        let (ip, prefix) = cidr.split_once('/').context("地址格式")?;
        Ok((ip.parse()?, prefix.parse()?))
    }

    fn prefix(&self) -> Option<u8> {
        self.address().ok().map(|(_, p)| p)
    }

    fn server_member(&self, public_host: &str) -> Result<ServerMember> {
        let pubkey = proto::unb64(&self.wg(&["show", &self.iface, "public-key"])?)?;
        let port: u16 = self.wg(&["show", &self.iface, "listen-port"])?.parse().context("监听端口")?;
        let (ip, _) = self.address()?;
        let host: Ipv4Addr = public_host.parse().context("--public 需要是 IPv4 地址，服务器成员用它作为 WireGuard 地址")?;
        Ok(ServerMember { ip, name: "服务器".into(), pubkey, endpoint: SocketAddr::from((host, port)) })
    }

    fn conf_text(&self) -> String {
        std::fs::read_to_string(&self.conf).unwrap_or_default()
    }

    fn write_conf(&self, text: &str) -> Result<()> {
        let tmp = self.conf.with_extension("conf.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.conf)?;
        Ok(())
    }
}

type Block<'a> = (Vec<&'a str>, Option<String>);

fn flush<'a>(cur: &mut Vec<&'a str>, out: &mut Vec<Block<'a>>) {
    if !cur.is_empty() {
        let key = cur.iter().find_map(|l| l.trim().strip_prefix("PublicKey").map(|r| r.trim_start_matches([' ', '=']).trim().to_string()));
        out.push((std::mem::take(cur), key));
    }
}

/// Blocks of the WireGuard config: (lines, public key if it is a [Peer]).
fn blocks(text: &str) -> Vec<Block<'_>> {
    let mut out: Vec<Block<'_>> = Vec::new();
    let mut cur: Vec<&str> = Vec::new();
    for line in text.lines() {
        // A block starts at a comment directly above a section, or at the section itself.
        let starts = line.trim_start().starts_with('[') && !cur.last().is_some_and(|l| l.trim_start().starts_with('#'));
        let comment_start = line.trim_start().starts_with("# supernet-");
        if (starts || comment_start) && !cur.is_empty() {
            flush(&mut cur, &mut out);
        }
        cur.push(line);
    }
    flush(&mut cur, &mut out);
    out
}

impl ServerHook for WgHook {
    fn add_peer(&self, pubkey: &[u8; 32], ip: Ipv4Addr, name: &str) -> Result<()> {
        let key = proto::b64(pubkey);
        self.wg(&["set", &self.iface, "peer", &key, "allowed-ips", &format!("{ip}/32")])?;
        let text = self.conf_text();
        if blocks(&text).iter().any(|(_, k)| k.as_deref() == Some(key.as_str())) {
            return Ok(());
        }
        let name: String = name.chars().filter(|c| !c.is_control()).collect();
        let mut new = text.trim_end().to_string();
        new.push_str(&format!("\n\n# supernet-mesh {name}\n[Peer]\nPublicKey = {key}\nAllowedIPs = {ip}/32\n"));
        self.write_conf(&new)
    }

    fn remove_peer(&self, pubkey: &[u8; 32]) -> Result<()> {
        let key = proto::b64(pubkey);
        let _ = self.wg(&["set", &self.iface, "peer", &key, "remove"]);
        let text = self.conf_text();
        let kept: Vec<String> =
            blocks(&text).into_iter().filter(|(_, k)| k.as_deref() != Some(key.as_str())).map(|(lines, _)| lines.join("\n")).collect();
        self.write_conf(&(kept.join("\n").trim_end().to_string() + "\n"))
    }

    fn used_ips(&self) -> Vec<Ipv4Addr> {
        let Ok(out) = self.wg(&["show", &self.iface, "allowed-ips"]) else { return Vec::new() };
        out.split_whitespace().filter_map(|w| w.strip_suffix("/32")).filter_map(|ip| ip.parse().ok()).collect()
    }

    fn prune(&self, members: &[[u8; 32]]) -> Result<()> {
        let keep: Vec<String> = members.iter().map(proto::b64).collect();
        let text = self.conf_text();
        let (stale, rest) = prune_mesh_peers(&text, &keep);
        if stale.is_empty() {
            return Ok(());
        }
        for key in &stale {
            let _ = self.wg(&["set", &self.iface, "peer", key, "remove"]);
            tracing::info!("已从 {} 移除不再是成员的设备 {key}", self.iface);
        }
        self.write_conf(&rest)
    }
}

/// Mesh peers (blocks tagged `# supernet-mesh`) whose key is not in `keep`,
/// and the config without them. Other peers stay as they are.
fn prune_mesh_peers(text: &str, keep: &[String]) -> (Vec<String>, String) {
    let mut stale = Vec::new();
    let mut kept = Vec::new();
    for (lines, key) in blocks(text) {
        let mesh = lines.iter().any(|l| l.trim_start().starts_with("# supernet-mesh"));
        match key {
            Some(k) if mesh && !keep.contains(&k) => stale.push(k),
            _ => kept.push(lines.join("\n")),
        }
    }
    (stale, kept.join("\n").trim_end().to_string() + "\n")
}

/// Reading the member list without starting a coordinator.
mod serde_like {
    use anyhow::Result;

    pub struct State {
        pub members: Vec<(String, String, String)>,
    }

    pub fn parse(raw: &[u8]) -> Result<State> {
        let v: serde_json::Value = serde_json::from_slice(raw)?;
        let members = v["members"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|m| {
                        let s = |k: &str| m[k].as_str().unwrap_or_default().to_string();
                        (s("ip"), s("name"), s("pubkey"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(State { members })
    }
}

#[cfg(test)]
mod tests {
    use super::blocks;

    #[test]
    fn peer_blocks_are_found_and_kept_apart() {
        let conf = "[Interface]\nAddress = 10.66.0.1/24\nListenPort = 51820\n\n# supernet-peer phone\n[Peer]\nPublicKey = AAA=\nAllowedIPs = 10.66.0.2/32\n\n# supernet-mesh 电脑\n[Peer]\nPublicKey = BBB=\nAllowedIPs = 10.66.0.3/32\n";
        let b = blocks(conf);
        let keys: Vec<Option<String>> = b.iter().map(|(_, k)| k.clone()).collect();
        assert_eq!(keys, vec![None, Some("AAA=".into()), Some("BBB=".into())]);
        let kept: Vec<String> = b.into_iter().filter(|(_, k)| k.as_deref() != Some("BBB=")).map(|(l, _)| l.join("\n")).collect();
        let out = kept.join("\n");
        assert!(out.contains("AAA=") && out.contains("ListenPort") && !out.contains("BBB="));
    }

    #[test]
    fn only_removed_mesh_peers_are_pruned() {
        let conf = "[Interface]\nAddress = 10.66.0.1/24\n\n# supernet-peer phone\n[Peer]\nPublicKey = AAA=\nAllowedIPs = 10.66.0.2/32\n\n# supernet-mesh 电脑\n[Peer]\nPublicKey = BBB=\nAllowedIPs = 10.66.0.3/32\n\n# supernet-mesh old\n[Peer]\nPublicKey = CCC=\nAllowedIPs = 10.66.0.5/32\n";
        // AAA= is not a mesh peer: kept although it is not a member.
        let (stale, rest) = super::prune_mesh_peers(conf, &["BBB=".to_string()]);
        assert_eq!(stale, vec!["CCC=".to_string()]);
        assert!(rest.contains("AAA=") && rest.contains("BBB=") && !rest.contains("CCC=") && !rest.contains("old"));
        let (none, same) = super::prune_mesh_peers(conf, &["BBB=".to_string(), "CCC=".to_string()]);
        assert!(none.is_empty() && same.trim_end() == conf.trim_end());
    }
}
