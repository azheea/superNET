//! `supernet server …`: turn this machine (Linux or Windows) into a proxy
//! node for superNET and other clients.
//!
//! ```text
//! supernet server add hy2|tuic [--name N] [--port P] [--host H] [--no-service]
//! supernet server list | show NAME | remove NAME | status | restart | run
//! ```
//!
//! The protocols run in the official sing-box (a pinned release whose SHA-256
//! is checked here), as its own service: systemd unit `supernet-proxy` (user
//! `supernet-proxy`, only CAP_NET_BIND_SERVICE) or the Windows scheduled task
//! "superNET proxy" (at startup, as SYSTEM). It never touches another
//! installation of sing-box, xray or s-ui on the same machine.
//!
//! TLS uses a self-signed certificate made here; share links carry its
//! SHA-256 (`pinSHA256`), so superNET checks it strictly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

const SING_BOX_VERSION: &str = "1.14.4";
/// (platform, SHA-256 of the release archive), from the GitHub release.
const SING_BOX_ARCHIVES: [(&str, &str); 6] = [
    ("linux-amd64", "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"),
    ("linux-arm64", "436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26"),
    ("linux-armv7", "fd164ed45ebc784f657a3e1d0e0ad0f68afdcff864ee57122c2cfed3ddb80a00"),
    ("windows-amd64", "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df"),
    ("windows-arm64", "8cd0a4d0cd8cd480be5731ac31f17038969a42d12add9feb6e031fd43d85bbae"),
    ("windows-386", "7994c40c5c1316777bdd29216a5dd7f134f894fad0afaa1efe7b872e60ed1dd9"),
];
/// Name in the self-signed certificate, and the SNI in links.
const CERT_NAME: &str = "supernet.local";
const SERVICE: &str = "supernet-proxy";
const WINDOWS_TASK: &str = "superNET proxy";

#[derive(Clone, Copy, PartialEq)]
enum Proto {
    Hysteria2,
    Tuic,
}

impl Proto {
    fn parse(s: &str) -> Result<Proto> {
        match s.to_ascii_lowercase().as_str() {
            "hy2" | "hysteria2" => Ok(Proto::Hysteria2),
            "tuic" => Ok(Proto::Tuic),
            other => bail!("不支持的协议 {other}（可选 hy2、tuic）"),
        }
    }
    fn id(self) -> &'static str {
        match self {
            Proto::Hysteria2 => "hysteria2",
            Proto::Tuic => "tuic",
        }
    }
}

struct Inbound {
    name: String,
    proto: Proto,
    port: u16,
    password: String,
    /// TUIC only.
    uuid: Option<String>,
}

struct State {
    host: String,
    pin: String,
    inbounds: Vec<Inbound>,
}

pub fn run(mut args: impl Iterator<Item = String>) -> Result<()> {
    let cmd = args.next().unwrap_or_default();
    let rest: Vec<String> = args.collect();
    match cmd.as_str() {
        "add" => add(&rest),
        "list" => list(),
        "show" => show(rest.first().context("用法：supernet server show 名称")?),
        "remove" => remove(rest.first().context("用法：supernet server remove 名称")?),
        "status" => status(),
        "restart" => restart(),
        "run" => run_foreground(),
        _ => {
            println!("supernet server add hy2|tuic [--name 名称] [--port 端口] [--host 公网地址或域名] [--no-service]");
            println!("supernet server list | show 名称 | remove 名称 | status | restart");
            println!("supernet server run     # 前台运行（不装服务时用）");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------- state

/// SUPERNET_SERVER_DIR, else /etc/supernet-proxy or %ProgramData%\superNET\server.
/// On Linux a top-level folder of its own: the service user must be able to
/// reach it, and /etc/supernet (the WireGuard node's) is root-only.
fn base_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("SUPERNET_SERVER_DIR") {
        return PathBuf::from(d);
    }
    if cfg!(windows) {
        let pd = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        pd.join("superNET").join("server")
    } else {
        PathBuf::from("/etc/supernet-proxy")
    }
}

fn load() -> Result<Option<State>> {
    let path = base_dir().join("state.json");
    let Ok(text) = std::fs::read_to_string(&path) else { return Ok(None) };
    let v: Value = serde_json::from_str(&text).with_context(|| format!("读取 {}", path.display()))?;
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let inbounds = v
        .get("inbounds")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|i| {
                    Some(Inbound {
                        name: s(i, "name"),
                        proto: Proto::parse(&s(i, "proto")).ok()?,
                        port: i.get("port")?.as_u64()? as u16,
                        password: s(i, "password"),
                        uuid: i.get("uuid").and_then(Value::as_str).map(str::to_string),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(State { host: s(&v, "host"), pin: s(&v, "pin"), inbounds }))
}

fn save(st: &State) -> Result<()> {
    let v = json!({
        "host": st.host,
        "pin": st.pin,
        "inbounds": st.inbounds.iter().map(|i| json!({
            "name": i.name, "proto": i.proto.id(), "port": i.port, "password": i.password, "uuid": i.uuid,
        })).collect::<Vec<_>>(),
    });
    write_private(&base_dir().join("state.json"), serde_json::to_string_pretty(&v)?.as_bytes())
}

/// Owner-only on Unix (the group is opened up for the service user later).
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data).with_context(|| format!("写入 {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ---------------------------------------------------------------- commands

fn add(args: &[String]) -> Result<()> {
    let mut it = args.iter();
    let proto = Proto::parse(it.next().context("用法：supernet server add hy2|tuic …")?)?;
    let (mut name, mut port, mut host, mut service) = (None, None, None, true);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--name" => name = Some(it.next().context("--name 需要名称")?.clone()),
            "--port" => port = Some(it.next().context("--port 需要端口")?.parse::<u16>().context("端口")?),
            "--host" => host = Some(it.next().context("--host 需要地址")?.clone()),
            "--no-service" => service = false,
            other => bail!("未知参数 {other}"),
        }
    }
    if service {
        require_admin()?;
    }
    let mut st = match load()? {
        Some(st) => st,
        None => {
            let host = match host.clone() {
                Some(h) => h,
                None => public_address().context("找不到本机的公网地址，请用 --host 指定（IP 或域名）")?,
            };
            let pin = make_certificate()?;
            State { host, pin, inbounds: Vec::new() }
        }
    };
    if let Some(h) = host {
        st.host = h;
    }
    let name = name.unwrap_or_else(|| {
        let base = match proto {
            Proto::Hysteria2 => "hy2",
            Proto::Tuic => "tuic",
        };
        (1..).map(|n| if n == 1 { base.to_string() } else { format!("{base}-{n}") }).find(|n| st.inbounds.iter().all(|i| &i.name != n)).unwrap()
    });
    if !valid_name(&name) {
        bail!("名称只能用字母、数字、- 和 _，最长 32 个字符");
    }
    if st.inbounds.iter().any(|i| i.name == name) {
        bail!("已经有名为 {name} 的协议（supernet server show {name}）");
    }
    let port = match port {
        Some(p) => {
            if st.inbounds.iter().any(|i| i.port == p) || !udp_port_free(p) {
                bail!("UDP 端口 {p} 已被占用，换一个，或者不写 --port 让程序自己挑");
            }
            p
        }
        None => pick_port(&st)?,
    };
    let inbound = Inbound {
        password: random_token(18),
        uuid: (proto == Proto::Tuic).then(random_uuid),
        name: name.clone(),
        proto,
        port,
    };
    st.inbounds.push(inbound);

    let bin = ensure_sing_box()?;
    write_config(&st, &bin)?;
    save(&st)?;
    if service {
        if let Err(e) = install_service(&bin) {
            // Leave the server as it was: without the new protocol.
            st.inbounds.pop();
            if write_config(&st, &bin).is_ok() && save(&st).is_ok() {
                if st.inbounds.is_empty() {
                    uninstall_service();
                } else {
                    let _ = restart_service();
                }
            }
            return Err(e.context(format!("没有添加 {name}，已恢复原来的配置")));
        }
        open_firewall(&name, port)?;
    }
    let i = st.inbounds.last().unwrap();
    println!("已添加 {}（{}，UDP {}）", i.name, i.proto.id(), i.port);
    if !service {
        println!("没有安装服务：用 supernet server run 在前台运行");
    }
    println!();
    print_link(&st, i);
    println!();
    println!("云服务器还要在安全组里放行 UDP {port} 入站。");
    Ok(())
}

fn list() -> Result<()> {
    let Some(st) = load()? else {
        println!("还没有添加协议：supernet server add hy2");
        return Ok(());
    };
    println!("{:<16} {:<10} {:>6}", "名称", "协议", "端口");
    for i in &st.inbounds {
        println!("{:<16} {:<10} {:>6}", i.name, i.proto.id(), i.port);
    }
    Ok(())
}

fn show(name: &str) -> Result<()> {
    let st = load()?.context("还没有添加协议")?;
    let i = st.inbounds.iter().find(|i| i.name == name).with_context(|| format!("没有名为 {name} 的协议"))?;
    print_link(&st, i);
    Ok(())
}

fn remove(name: &str) -> Result<()> {
    let mut st = load()?.context("还没有添加协议")?;
    let pos = st.inbounds.iter().position(|i| i.name == name).with_context(|| format!("没有名为 {name} 的协议"))?;
    let installed = service_installed();
    if installed {
        require_admin()?;
    }
    let removed = st.inbounds.remove(pos);
    let bin = ensure_sing_box()?;
    write_config(&st, &bin)?;
    save(&st)?;
    if installed {
        close_firewall(&removed.name, removed.port);
        if st.inbounds.is_empty() {
            uninstall_service();
            println!("已删除 {name}；没有协议了，服务也已停止并删除");
            return Ok(());
        }
        restart_service()?;
    }
    println!("已删除 {name}（UDP {} 不再监听）", removed.port);
    Ok(())
}

fn status() -> Result<()> {
    list()?;
    println!();
    if cfg!(windows) {
        let out = Command::new("schtasks").args(["/Query", "/TN", WINDOWS_TASK, "/FO", "LIST"]).output();
        match out {
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout).to_string();
                println!("{}", text.lines().filter(|l| l.contains(':')).take(6).collect::<Vec<_>>().join("\n"));
            }
            _ => println!("没有安装服务"),
        }
    } else {
        let _ = Command::new("systemctl").args(["--no-pager", "status", SERVICE]).status();
    }
    Ok(())
}

fn run_foreground() -> Result<()> {
    let bin = ensure_sing_box()?;
    let config = base_dir().join("config.json");
    if !config.exists() {
        bail!("还没有添加协议：supernet server add hy2 --no-service");
    }
    println!("前台运行 sing-box（Ctrl+C 停止）：{}", config.display());
    let status = Command::new(&bin).arg("run").arg("-c").arg(&config).status().context("启动 sing-box")?;
    if !status.success() {
        bail!("sing-box 退出：{status}");
    }
    Ok(())
}

// ---------------------------------------------------------------- links

fn host_for_link(host: &str) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn link(st: &State, i: &Inbound) -> String {
    let host = host_for_link(&st.host);
    let name = percent_encode(&i.name);
    match i.proto {
        Proto::Hysteria2 => format!(
            "hysteria2://{}@{host}:{}/?sni={CERT_NAME}&pinSHA256={}#{name}",
            percent_encode(&i.password),
            i.port,
            st.pin
        ),
        // allow_insecure for other clients, which cannot pin a certificate;
        // superNET checks pinSHA256 instead.
        Proto::Tuic => format!(
            "tuic://{}:{}@{host}:{}/?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni={CERT_NAME}&allow_insecure=1&pinSHA256={}#{name}",
            i.uuid.as_deref().unwrap_or_default(),
            percent_encode(&i.password),
            i.port,
            st.pin
        ),
    }
}

fn print_link(st: &State, i: &Inbound) {
    println!("===== {}：分享链接（在 superNET 的“节点”页粘贴）=====", i.name);
    println!("{}", link(st, i));
    println!("证书是自签名的，链接里带了证书指纹，superNET 会严格校验。其他客户端可能需要允许不安全证书。");
    println!("链接里包含密码，只发给你自己的设备。");
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ---------------------------------------------------------------- sing-box

fn platform() -> Result<String> {
    let os = if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        bail!("服务端目前支持 Linux 和 Windows")
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "armv7",
        "x86" => "386",
        other => bail!("不支持的处理器架构 {other}"),
    };
    Ok(format!("{os}-{arch}"))
}

/// The pinned sing-box in the server folder: downloaded and checked once.
/// SUPERNET_SING_BOX=path uses an existing binary instead (no network).
fn ensure_sing_box() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("SUPERNET_SING_BOX") {
        return Ok(PathBuf::from(p));
    }
    let exe = if cfg!(windows) { "sing-box.exe" } else { "sing-box" };
    // Linux: with the system's programs, so SELinux runs it as an ordinary
    // service (a program under /etc is etc_t, and its outbound connections
    // are refused). Windows, and test folders: inside the server folder.
    let bin = if cfg!(windows) || std::env::var_os("SUPERNET_SERVER_DIR").is_some() {
        base_dir().join("bin").join(exe)
    } else {
        PathBuf::from("/usr/local/bin/supernet-sing-box")
    };
    let dir = bin.parent().map(Path::to_path_buf).unwrap_or_else(base_dir);
    let marker = base_dir().join("sing-box.version");
    if bin.exists() && std::fs::read_to_string(&marker).is_ok_and(|v| v.trim() == SING_BOX_VERSION) {
        return Ok(bin);
    }
    let plat = platform()?;
    let (_, sha) = SING_BOX_ARCHIVES.iter().find(|(p, _)| *p == plat).with_context(|| format!("没有 {plat} 的 sing-box"))?;
    let ext = if cfg!(windows) { "zip" } else { "tar.gz" };
    let file = format!("sing-box-{SING_BOX_VERSION}-{plat}.{ext}");
    let url = format!("https://github.com/SagerNet/sing-box/releases/download/v{SING_BOX_VERSION}/{file}");
    let tmp = std::env::temp_dir().join(format!("supernet-sing-box-{}", std::process::id()));
    std::fs::create_dir_all(&tmp)?;
    let archive = tmp.join(&file);
    println!("下载 sing-box {SING_BOX_VERSION}（{plat}）……");
    let ok = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "--connect-timeout", "15", "-o"])
        .arg(&archive)
        .arg(&url)
        .status()
        .context("运行 curl（需要 curl；离线时可用 SUPERNET_SING_BOX=路径 指定已有的 sing-box）")?
        .success();
    if !ok {
        let _ = std::fs::remove_dir_all(&tmp);
        bail!("下载失败：{url}");
    }
    let got = sha256_hex(&std::fs::read(&archive)?);
    if got != *sha {
        let _ = std::fs::remove_dir_all(&tmp);
        bail!("sing-box 校验失败（{got}），没有安装");
    }
    let ok = Command::new("tar").arg("-xf").arg(&archive).arg("-C").arg(&tmp).status().context("运行 tar")?.success();
    if !ok {
        bail!("解压 {file} 失败");
    }
    let found = tmp.join(file.trim_end_matches(&format!(".{ext}"))).join(exe);
    std::fs::create_dir_all(&dir)?;
    std::fs::copy(&found, &bin).with_context(|| format!("复制 {}", found.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
        // The default SELinux label for the folder (bin_t), where SELinux is used.
        let _ = Command::new("restorecon").arg(&bin).output();
    }
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(&marker, SING_BOX_VERSION)?;
    let _ = std::fs::remove_dir_all(&tmp);
    println!("sing-box 已安装（SHA-256 校验通过）：{}", bin.display());
    Ok(bin)
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// The self-signed certificate (once per server); returns its SHA-256.
fn make_certificate() -> Result<String> {
    let mut params = rcgen::CertificateParams::new(vec![CERT_NAME.to_string()])?;
    params.distinguished_name.push(rcgen::DnType::CommonName, CERT_NAME);
    params.not_after = rcgen::date_time_ymd(2099, 12, 31);
    let key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    let dir = base_dir();
    write_private(&dir.join("cert.pem"), cert.pem().as_bytes())?;
    write_private(&dir.join("key.pem"), key.serialize_pem().as_bytes())?;
    Ok(sha256_hex(cert.der()))
}

fn write_config(st: &State, bin: &Path) -> Result<()> {
    let dir = base_dir();
    let tls = json!({
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": dir.join("cert.pem"),
        "key_path": dir.join("key.pem"),
    });
    let inbounds: Vec<Value> = st
        .inbounds
        .iter()
        .map(|i| match i.proto {
            Proto::Hysteria2 => json!({
                "type": "hysteria2", "tag": i.name, "listen": "::", "listen_port": i.port,
                "users": [{ "name": i.name, "password": i.password }],
                "tls": tls,
            }),
            Proto::Tuic => json!({
                "type": "tuic", "tag": i.name, "listen": "::", "listen_port": i.port,
                "users": [{ "name": i.name, "uuid": i.uuid, "password": i.password }],
                "congestion_control": "bbr",
                "tls": tls,
            }),
        })
        .collect();
    let config = json!({
        "log": { "level": "warn", "timestamp": true },
        "inbounds": inbounds,
        "outbounds": [{ "type": "direct", "tag": "direct" }],
    });
    let path = dir.join("config.json");
    let backup = std::fs::read(&path).ok();
    write_private(&path, serde_json::to_string_pretty(&config)?.as_bytes())?;
    let out = Command::new(bin).arg("check").arg("-c").arg(&path).output().context("运行 sing-box check")?;
    if !out.status.success() {
        match backup {
            Some(b) => write_private(&path, &b)?,
            None => {
                let _ = std::fs::remove_file(&path);
            }
        }
        bail!("sing-box 认为配置有误：{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    share_with_service();
    Ok(())
}

/// Linux: let the service user read the folder, certificate, key and config
/// through its group (files are rewritten owner-only). No-op elsewhere or
/// before the user exists.
fn share_with_service() {
    if !cfg!(target_os = "linux") || std::env::var_os("SUPERNET_SERVER_DIR").is_some() {
        return;
    }
    if Command::new("id").arg(SERVICE).output().map_or(true, |o| !o.status.success()) {
        return;
    }
    let dir = base_dir();
    let _ = run_cmd("chgrp", &["-R", SERVICE, &dir.display().to_string()]);
    let _ = run_cmd("chmod", &["750", &dir.display().to_string()]);
    for f in ["cert.pem", "key.pem", "config.json"] {
        let _ = run_cmd("chmod", &["640", &dir.join(f).display().to_string()]);
    }
}

// ---------------------------------------------------------------- ports, addresses

/// Free for IPv4, and for IPv6 where the machine has it (each probe socket is
/// closed before the next, so a dual-stack socket does not clash with itself).
fn udp_port_free(port: u16) -> bool {
    if UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))).is_err() {
        return false;
    }
    match UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::AddrInUse,
    }
}

fn pick_port(st: &State) -> Result<u16> {
    for _ in 0..200 {
        let mut b = [0u8; 2];
        fill_random(&mut b);
        let p = 20000 + (u16::from_be_bytes(b) % 40000);
        if st.inbounds.iter().all(|i| i.port != p) && udp_port_free(p) {
            return Ok(p);
        }
    }
    bail!("找不到空闲的 UDP 端口，请用 --port 指定")
}

/// The address clients reach: what the internet sees for this machine.
fn public_address() -> Option<String> {
    for url in ["https://api.ipify.org", "https://ipv4.icanhazip.com"] {
        let out = Command::new("curl").args(["-fsS", "--max-time", "6", url]).output().ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if out.status.success() && s.parse::<IpAddr>().is_ok() {
            return Some(s);
        }
    }
    None
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 32 && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn fill_random(buf: &mut [u8]) {
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(buf);
}

/// URL-safe random text (no characters that need escaping in links).
fn random_token(bytes: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut b = vec![0u8; bytes];
    fill_random(&mut b);
    b.iter().map(|x| ALPHABET[*x as usize % ALPHABET.len()] as char).collect()
}

fn random_uuid() -> String {
    let mut b = [0u8; 16];
    fill_random(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

// ---------------------------------------------------------------- service, firewall

fn require_admin() -> Result<()> {
    if !supernet_tun::has_privilege() {
        if cfg!(windows) {
            bail!("需要管理员权限：在“以管理员身份运行”的终端里执行（或加 --no-service 只生成配置）");
        }
        bail!("需要 root：用 sudo 运行（或加 --no-service 只生成配置）");
    }
    Ok(())
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(cmd).args(args).output().with_context(|| format!("运行 {cmd}"))?;
    if !out.status.success() {
        bail!("{cmd} {}：{}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn service_installed() -> bool {
    if cfg!(windows) {
        Command::new("schtasks").args(["/Query", "/TN", WINDOWS_TASK]).output().is_ok_and(|o| o.status.success())
    } else {
        Path::new(&format!("/etc/systemd/system/{SERVICE}.service")).exists()
    }
}

#[cfg(target_os = "linux")]
fn install_service(bin: &Path) -> Result<()> {
    let dir = base_dir();
    if Command::new("id").arg(SERVICE).output().map_or(true, |o| !o.status.success()) {
        let nologin = ["/usr/sbin/nologin", "/sbin/nologin"].into_iter().find(|p| Path::new(p).exists()).unwrap_or("/bin/false");
        run_cmd("useradd", &["--system", "--no-create-home", "--shell", nologin, SERVICE])?;
    }
    // The service user reads the folder through its group; nobody else can.
    share_with_service();
    let unit = format!(
        "[Unit]\nDescription=superNET proxy protocols (sing-box)\nAfter=network-online.target\nWants=network-online.target\n\n\
         [Service]\nExecStart={} run -c {}\nUser={SERVICE}\nGroup={SERVICE}\n\
         AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nNoNewPrivileges=yes\n\
         ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nRestart=on-failure\nRestartSec=5\nLimitNOFILE=65536\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        bin.display(),
        dir.join("config.json").display()
    );
    std::fs::write(format!("/etc/systemd/system/{SERVICE}.service"), unit)?;
    run_cmd("systemctl", &["daemon-reload"])?;
    run_cmd("systemctl", &["enable", SERVICE])?;
    restart_service()
}

#[cfg(windows)]
fn install_service(bin: &Path) -> Result<()> {
    let action = format!("\"{}\" run -c \"{}\"", bin.display(), base_dir().join("config.json").display());
    run_cmd("schtasks", &["/Create", "/F", "/TN", WINDOWS_TASK, "/SC", "ONSTART", "/RU", "SYSTEM", "/RL", "HIGHEST", "/TR", &action])?;
    restart_service()
}

#[cfg(not(any(target_os = "linux", windows)))]
fn install_service(_bin: &Path) -> Result<()> {
    bail!("服务端目前支持 Linux 和 Windows")
}

fn restart_service() -> Result<()> {
    if cfg!(windows) {
        let _ = run_cmd("schtasks", &["/End", "/TN", WINDOWS_TASK]);
        std::thread::sleep(std::time::Duration::from_millis(800));
        run_cmd("schtasks", &["/Run", "/TN", WINDOWS_TASK])
    } else {
        run_cmd("systemctl", &["restart", SERVICE])?;
        // Up only when it stays up: "activating" means it is restarting after a failure.
        let mut up = 0;
        for _ in 0..20 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let state = Command::new("systemctl").args(["is-active", SERVICE]).output();
            let state = state.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
            if state == "active" {
                up += 1;
                if up >= 4 {
                    return Ok(());
                }
            } else {
                up = 0;
            }
        }
        bail!("服务没有起来：journalctl -u supernet-proxy 查看原因")
    }
}

/// Rewrite the config from the saved state, repair permissions, restart.
fn restart() -> Result<()> {
    require_admin()?;
    let st = load()?.context("还没有添加协议")?;
    let bin = ensure_sing_box()?;
    write_config(&st, &bin)?;
    if st.inbounds.is_empty() {
        uninstall_service();
        println!("没有协议，服务已停止");
        return Ok(());
    }
    install_service(&bin)?;
    println!("服务已重启：{} 个协议", st.inbounds.len());
    Ok(())
}

fn uninstall_service() {
    if cfg!(windows) {
        let _ = run_cmd("schtasks", &["/End", "/TN", WINDOWS_TASK]);
        let _ = run_cmd("schtasks", &["/Delete", "/F", "/TN", WINDOWS_TASK]);
    } else {
        let _ = run_cmd("systemctl", &["disable", "--now", SERVICE]);
        let _ = std::fs::remove_file(format!("/etc/systemd/system/{SERVICE}.service"));
        let _ = run_cmd("systemctl", &["daemon-reload"]);
    }
}

/// Open the UDP port in the host firewall if one is active (the cloud
/// provider's security group is separate).
fn open_firewall(name: &str, port: u16) -> Result<()> {
    let p = format!("{port}/udp");
    if cfg!(windows) {
        let rule = format!("name=superNET {name}");
        run_cmd("netsh", &["advfirewall", "firewall", "add", "rule", &rule, "dir=in", "action=allow", "protocol=UDP", &format!("localport={port}")])?;
    } else if Command::new("firewall-cmd").arg("--state").output().is_ok_and(|o| o.status.success()) {
        run_cmd("firewall-cmd", &["--permanent", &format!("--add-port={p}")])?;
        run_cmd("firewall-cmd", &[&format!("--add-port={p}")])?;
    } else if Command::new("ufw").arg("status").output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("Status: active")) {
        run_cmd("ufw", &["allow", &p])?;
    }
    Ok(())
}

fn close_firewall(name: &str, port: u16) {
    let p = format!("{port}/udp");
    if cfg!(windows) {
        let _ = run_cmd("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name=superNET {name}")]);
    } else if Command::new("firewall-cmd").arg("--state").output().is_ok_and(|o| o.status.success()) {
        let _ = run_cmd("firewall-cmd", &["--permanent", &format!("--remove-port={p}")]);
        let _ = run_cmd("firewall-cmd", &[&format!("--remove-port={p}")]);
    } else if Command::new("ufw").arg("status").output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("Status: active")) {
        let _ = run_cmd("ufw", &["delete", "allow", &p]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_are_importable() {
        let st = State { host: "203.0.113.10".into(), pin: "ab".repeat(32), inbounds: Vec::new() };
        let hy = Inbound { name: "hy2".into(), proto: Proto::Hysteria2, port: 24443, password: "Pw123".into(), uuid: None };
        let hy_link = link(&st, &hy);
        let node = supernet_core::wgconf::import(&hy_link, "").unwrap();
        assert_eq!(node.name, "hy2");
        let tu = Inbound { name: "家里 tuic".into(), proto: Proto::Tuic, port: 24444, password: "x".into(), uuid: Some(random_uuid()) };
        assert!(link(&st, &tu).starts_with("tuic://"));
        assert!(link(&st, &tu).contains("#%E5%AE%B6"));
        let v6 = State { host: "2001:db8::1".into(), ..st };
        assert!(link(&v6, &hy).contains("@[2001:db8::1]:24443/"));
    }

    #[test]
    fn uuid_is_v4() {
        let u = random_uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
    }
}
