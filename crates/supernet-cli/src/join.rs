//! `supernet join LINK [--name N] [--profile P] [--install-service]`
//!
//! Joining the virtual network from a machine without a screen (a Linux
//! server): makes this device's key, writes the `mesh:` section into the
//! profile (creating a minimal profile if there is none) and, on Linux with
//! `--install-service`, installs and starts a systemd service that runs
//! `supernet --profile P --mesh-only`: only the network's addresses go through
//! the virtual device, the server's own routes and DNS stay as they are.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use supernet_core::config::MeshProfile;
use supernet_core::Profile;
use supernet_mesh::proto;

pub fn run(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut link: Option<String> = None;
    let mut name: Option<String> = None;
    let mut profile_path: Option<PathBuf> = None;
    let mut service = false;
    // The service's web console: on by default, local only (reach it through ssh -L).
    let mut web: Option<String> = Some("127.0.0.1:9090".into());
    while let Some(a) = args.next() {
        match a.as_str() {
            "--name" => name = Some(args.next().context("--name 需要设备名")?),
            "--profile" | "-p" => profile_path = Some(args.next().context("--profile 需要文件路径")?.into()),
            "--install-service" => service = true,
            "--web" => web = Some(args.next().context("--web 需要 IP:端口")?),
            "--no-web" => web = None,
            other if link.is_none() && other.starts_with("supernet-net://") => link = Some(other.to_string()),
            other => bail!(
                "未知参数 {other}（用法：supernet join 邀请链接 [--name 设备名] [--profile 路径] [--install-service [--web IP:端口 | --no-web]]）"
            ),
        }
    }
    let link = link.context("缺少邀请链接（supernet-net://…，在电脑版“组网”页或 supernet-coord invite 里）")?;
    let invite = proto::Invite::parse(&link).context("邀请链接无效")?;
    let name = name.unwrap_or_else(hostname);
    let path = profile_path.unwrap_or_else(default_profile_path);

    let mut profile = if path.exists() { Profile::load(&path)? } else { Profile::default() };
    // Same network again: keep the key, so the device keeps its address.
    let key = match &profile.mesh {
        Some(m) if same_network(&m.invite, &invite) && !m.private_key.is_empty() => m.private_key.clone(),
        _ => proto::b64(&proto::generate_secret()),
    };
    profile.mesh = Some(MeshProfile { invite: link, private_key: key, name: name.clone(), relay: true, enabled: true });
    profile.save(&path)?;
    restrict(&path);
    println!("已写入 {}：设备名 {name}，网络 {}（协调服务 {}）", path.display(), invite.network, invite.coord);

    if service {
        install_service(&path, web.as_deref())?;
    } else {
        println!("启动（需要 root）：sudo {} --profile {} --mesh-only", exe().display(), path.display());
        if cfg!(target_os = "linux") {
            println!("或者装成开机自启的服务：sudo {} join 邀请链接 --install-service", exe().display());
        }
    }
    Ok(())
}

fn same_network(old_link: &str, new: &proto::Invite) -> bool {
    proto::Invite::parse(old_link).is_ok_and(|old| old.coord == new.coord && old.coord_pub == new.coord_pub && old.network == new.network)
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()))
        .or_else(|| std::process::Command::new("hostname").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "server".into())
}

fn exe() -> PathBuf {
    std::env::current_exe().and_then(|p| p.canonicalize()).unwrap_or_else(|_| PathBuf::from("supernet"))
}

/// root: /etc/supernet/profile.yaml (what the service uses); otherwise the user's config folder.
fn default_profile_path() -> PathBuf {
    #[cfg(unix)]
    // SAFETY: plain libc call without arguments.
    if unsafe { libc::geteuid() } == 0 {
        return PathBuf::from("/etc/supernet/profile.yaml");
    }
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("supernet").join("profile.yaml")
}

/// The profile holds the device's private key: owner only.
fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(target_os = "linux")]
fn install_service(profile: &Path, web: Option<&str>) -> Result<()> {
    // SAFETY: plain libc call without arguments.
    if unsafe { libc::geteuid() } != 0 {
        bail!("安装服务需要 root：sudo {} join … --install-service", exe().display());
    }
    let web_arg = web.map(|w| format!(" --web {w}")).unwrap_or_default();
    let unit = format!(
        "[Unit]\nDescription=superNET virtual network\nAfter=network-online.target\nWants=network-online.target\n\n\
         [Service]\n# Only the network's addresses go through the device; the server's routes and DNS stay.\n\
         ExecStart={} --profile {} --mesh-only{web_arg} --stats 300\nRestart=on-failure\nRestartSec=5\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        exe().display(),
        profile.display()
    );
    std::fs::write("/etc/systemd/system/supernet.service", unit).context("写入 /etc/systemd/system/supernet.service")?;
    for args in [&["daemon-reload"][..], &["enable", "supernet"][..], &["restart", "supernet"][..]] {
        let ok = std::process::Command::new("systemctl").args(args).status().context("运行 systemctl")?.success();
        if !ok {
            bail!("systemctl {} 失败", args.join(" "));
        }
    }
    println!("已安装并启动服务 supernet（开机自启）。查看：systemctl status supernet；日志：journalctl -u supernet -f");
    if let Some(w) = web {
        let port = w.rsplit(':').next().unwrap_or("9090");
        let token = std::fs::read_to_string(profile.parent().unwrap_or(Path::new(".")).join("web-token")).ok();
        println!("网页控制台：http://{w}/（只监听本机，操作要带令牌）");
        println!("  在自己电脑上：ssh -L {port}:{w} 用户@这台服务器");
        match token {
            Some(t) => println!("  然后用浏览器打开：http://127.0.0.1:{port}/#token={}", t.trim()),
            None => println!("  然后用浏览器打开 journalctl -u supernet 里打印的链接（带 #token=…）"),
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_service(_profile: &Path, _web: Option<&str>) -> Result<()> {
    bail!("--install-service 只支持 Linux（systemd）")
}
