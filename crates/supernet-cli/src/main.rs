//! `supernet --profile profile.yaml [--stats 10]`
//!
//! Runs the engine without a window (Linux servers, soak tests) and prints
//! traffic and per-node tunnel counters every few seconds.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use supernet_control::{Controller, Options};
use supernet_core::Profile;

mod join;
mod mesh_probe;
mod tun_test;
mod web;

#[tokio::main]
async fn main() -> Result<()> {
    let mut profile_path: Option<PathBuf> = None;
    let mut every = 10u64;
    let mut force_tun = false;
    let mut mesh_only = false;
    let mut web_addr: Option<std::net::SocketAddr> = None;
    let mut web_token: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" | "-p" => profile_path = Some(args.next().context("--profile 需要文件路径")?.into()),
            // TUN mode whatever the profile says (the macOS app hands this command over for TUN).
            "--tun" => force_tun = true,
            // Only the virtual network through the device: default routes and DNS stay as they are (servers).
            "--mesh-only" => {
                force_tun = true;
                mesh_only = true;
            }
            "join" => return join::run(args),
            // The app's UI in a browser, for machines without a screen.
            "--web" => {
                let v = args.next().unwrap_or_else(|| "127.0.0.1:9090".into());
                web_addr = Some(if v.contains(':') { v.parse().context("--web 格式是 IP:端口")? } else { format!("127.0.0.1:{v}").parse().context("--web 端口")? });
            }
            "--web-token" => web_token = Some(args.next().context("--web-token 需要令牌（至少 16 个字符）")?),
            "--stats" => every = args.next().context("--stats 需要秒数")?.parse()?,
            "tun-test" => return tun_test::run(args).await,
            "mesh-probe" => return mesh_probe::run(args).await,
            "pin-cert" => {
                // supernet pin-cert host:port [sni] → SHA-256 of the server's certificate
                let server = args.next().context("用法：supernet pin-cert host:port [sni]")?;
                let host = server.rsplit_once(':').map_or(server.as_str(), |(h, _)| h).to_string();
                let sni = args.next().unwrap_or(host);
                let addr = tokio::net::lookup_host(&server).await?.next().context("无法解析服务器地址")?;
                let digest = supernet_hy2::fetch_cert_sha256(addr, &sni).await?;
                println!("{}", supernet_hy2::hex(&digest));
                return Ok(());
            }
            "-h" | "--help" => {
                println!("supernet --profile profile.yaml [--tun | --mesh-only] [--web 127.0.0.1:9090] [--stats 10]");
                println!("    --tun：不管配置里的 tun，都开 TUN（需要 root/管理员）");
                println!("    --mesh-only：只让组网走虚拟网卡，不改默认路由和 DNS（服务器用）");
                println!("    --web [IP:]端口：网页控制台（默认 127.0.0.1:9090，带令牌）；--web-token 指定令牌");
                println!("supernet join 邀请链接 [--name 设备名] [--profile 路径] [--install-service [--no-web]]   # 加入组网：生成密钥、写配置，可装成 systemd 服务（默认带网页控制台 127.0.0.1:9090）");
                println!("supernet pin-cert host:port [sni]   # 打印 Hysteria2 服务器证书的 SHA-256");
                println!("supernet mesh-probe --invite LINK [--key FILE] [--name N] [--seconds 60] [--only-ipv6]   # 不开 TUN，只看组网路径");
                println!("supernet tun-test --profile P [--seconds 45] [--log FILE] [--wintun DLL]   # 限时 TUN 自检（管理员）");
                return Ok(());
            }
            other => bail!("未知参数 {other}"),
        }
    }
    let path = profile_path.context("缺少 --profile")?;
    if mesh_only && !Profile::load(&path)?.mesh.is_some_and(|m| m.enabled) {
        bail!("--mesh-only 需要配置里有组网（先运行 supernet join 邀请链接）");
    }
    let data_dir = path.parent().map(PathBuf::from).filter(|d| !d.as_os_str().is_empty()).unwrap_or_else(|| PathBuf::from("."));
    let ctl = Controller::open(Options { data_dir: data_dir.clone(), profile_path: path, vpn: None, mesh_only, force_tun })?;
    for w in ctl.overview().await.map_err(anyhow::Error::msg)?.warnings {
        eprintln!("警告：{w}");
    }
    ctl.connect().await.map_err(anyhow::Error::msg)?;
    if let Some(addr) = ctl.engine.status().await.listen {
        println!("代理已启动：{addr}（HTTP / SOCKS5），Ctrl+C 退出");
    }
    if let Some(name) = ctl.tun_name().await {
        println!("TUN 已启动：网卡 {name}{}", if mesh_only { "（只组网）" } else { "" });
    }
    if let Some(addr) = web_addr {
        let token = web::token(&data_dir, web_token)?;
        {
            let (ctl, token) = (ctl.clone(), token.clone());
            tokio::spawn(async move {
                if let Err(e) = web::serve(addr, token, ctl).await {
                    eprintln!("网页控制台：{e:#}");
                }
            });
        }
        println!("网页控制台：http://{addr}/#token={token}");
        if addr.ip().is_loopback() {
            println!("  在自己电脑上打开：先 ssh -L {p}:127.0.0.1:{p} 用户@这台服务器，再用浏览器打开 http://127.0.0.1:{p}/#token={token}", p = addr.port());
        } else {
            println!("  注意：网页控制台是明文 HTTP，令牌和配置会在网络上明文传输。建议只监听 127.0.0.1，经 ssh -L 访问。");
        }
    }
    // The virtual network joins in the background: say when it has.
    {
        let ctl = ctl.clone();
        tokio::spawn(async move {
            for _ in 0..120 {
                if let Ok(v) = ctl.mesh_status().await {
                    if !v.enabled || !v.tun_active {
                        return;
                    }
                    if let Some(me) = v.status.and_then(|s| s.me.map(|me| (me.ip, s.prefix))) {
                        println!("已加入组网：本机 {}/{}", me.0, me.1);
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });
    }

    let mut tick = tokio::time::interval(Duration::from_secs(every.max(1)));
    let mut last_seq = 0;
    loop {
        tokio::select! {
            _ = shutdown_signal() => break,
            _ = tick.tick() => {
                give_back(&data_dir);
                for line in ctl.logs(last_seq) {
                    last_seq = line.seq;
                    if line.level != "info" {
                        println!("[{}] {}", line.level, line.message);
                    }
                }
                let s = ctl.engine.status().await;
                let mut out = format!(
                    "{} 连接 {} 上传 {} 下载 {}",
                    supernet_core::stats::now_ms() / 1000,
                    s.connections,
                    s.total_upload,
                    s.total_download
                );
                for n in ctl.engine.nodes().iter().filter(|n| n.active) {
                    out += &format!(
                        " | {} 握手 {} 隧道发 {} 隧道收 {}",
                        n.name,
                        n.since_handshake_secs.map_or("-".into(), |v| format!("{v}s 前")),
                        n.tx_bytes,
                        n.rx_bytes
                    );
                }
                println!("{out}");
            }
        }
    }
    // Routes, DNS and the system proxy go back to how they were.
    ctl.shutdown().await;
    give_back(&data_dir);
    Ok(())
}

/// Under sudo, files the engine creates in the data folder (rule-set caches,
/// a rewritten profile) would stay owned by root, and the app, running as the
/// user, could no longer write them: hand them back to the user who ran sudo.
#[cfg(unix)]
fn give_back(dir: &std::path::Path) {
    let id = |v: &str| std::env::var(v).ok().and_then(|s| s.parse::<u32>().ok());
    let (Some(uid), Some(gid)) = (id("SUDO_UID"), id("SUDO_GID")) else { return };
    // Only inside the user's own folder (a profile under /etc stays root's).
    {
        use std::os::unix::fs::MetadataExt;
        if uid == 0 || std::fs::metadata(dir).map(|m| m.uid()).ok() != Some(uid) {
            return;
        }
    }
    fn walk(dir: &std::path::Path, uid: u32, gid: u32, depth: u32) {
        use std::os::unix::fs::MetadataExt;
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let path = e.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.uid() == 0 {
                let _ = std::os::unix::fs::chown(&path, Some(uid), Some(gid));
            }
            if meta.is_dir() && depth < 4 {
                walk(&path, uid, gid, depth + 1);
            }
        }
    }
    walk(dir, uid, gid, 0);
}

#[cfg(not(unix))]
fn give_back(_dir: &std::path::Path) {}

/// Ctrl+C, or SIGTERM on Unix (`kill`, `timeout`, systemd stop): either way
/// the TUN routes, DNS and rp_filter must be put back, so exit through drop.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
