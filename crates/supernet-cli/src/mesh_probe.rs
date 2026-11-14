//! `supernet mesh-probe --invite LINK [--key FILE] [--name NAME] [--seconds 60] [--only-ipv6]`
//!
//! Join the virtual network without TUN (no routes or DNS change, no root
//! needed) and print, every few seconds, how this device reaches every
//! other member: LAN, IPv6, public IPv4, through a device or the server.
//! For checking P2P paths between two machines on real networks.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use supernet_mesh::{device as mesh, proto};

pub async fn run(mut args: impl Iterator<Item = String>) -> Result<()> {
    let (mut invite, mut key_file, mut name, mut seconds, mut only6) = (None, None::<PathBuf>, None, 60u64, false);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--invite" => invite = Some(args.next().context("--invite 需要邀请链接")?),
            "--key" => key_file = Some(args.next().context("--key 需要文件路径")?.into()),
            "--name" => name = Some(args.next().context("--name 需要名称")?),
            "--seconds" => seconds = args.next().context("--seconds 需要秒数")?.parse()?,
            "--only-ipv6" => only6 = true,
            other => bail!("未知参数 {other}"),
        }
    }
    let invite = proto::Invite::parse(&invite.context("缺少 --invite")?)?;
    // A stable identity across runs keeps the same address.
    let key = match &key_file {
        Some(f) => match std::fs::read_to_string(f) {
            Ok(k) => proto::unb64(&k)?,
            Err(_) => {
                let k = proto::generate_secret();
                std::fs::write(f, proto::b64(&k))?;
                k
            }
        },
        None => proto::generate_secret(),
    };
    let name = name.unwrap_or_else(|| std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "probe".into()));
    let mut cfg = mesh::MeshConfig::new(invite, key, name);
    cfg.only_ipv6_direct = only6;
    let (m, _ports) = mesh::Mesh::start(cfg).await?;
    let ip = m.wait_joined(Duration::from_secs(30)).await?;
    let st = m.status();
    println!("已加入：本机 {ip}，协调服务看到 {:?}，上报的本机地址 {:?}", st.observed, st.me.as_ref().map(|me| &me.endpoints));
    let end = Instant::now() + Duration::from_secs(seconds.clamp(5, 600));
    while Instant::now() < end {
        tokio::time::sleep(Duration::from_secs(5)).await;
        for p in m.status().peers.iter().filter(|p| p.online) {
            println!(
                "  {} {}：{:?}{} 延迟 {:?} ms，地址 {:?}，候选 {:?}",
                p.ip,
                p.name,
                p.kind,
                p.via.map(|v| format!(" 经 {v}")).unwrap_or_default(),
                p.rtt_ms,
                p.endpoint,
                p.candidates
            );
        }
    }
    let st = m.status();
    println!("发送失败 {} 次，最后一次：{:?}", st.send_errors, st.last_send_error);
    // Every device's own report (the Mac's view of its paths, for example).
    for l in &st.links {
        println!("  链路 {} → {}：{:?}{}", l.from, l.link.peer, l.link.kind, l.link.via.map(|v| format!(" 经 {v}")).unwrap_or_default());
    }
    Ok(())
}
