//! `supernet tun-test --profile P [--seconds 45] [--log FILE] [--wintun DLL]`
//!
//! A time-boxed TUN mode run for diagnosing the real device: it takes over
//! routing, runs a few probes through the system's ordinary sockets (so
//! they go through the TUN like any program's traffic), prints packet
//! counters, then removes everything. A watchdog thread ends the process
//! when time is up even if the runtime hangs; wintun adapters and the
//! `store=active` routes vanish with the process.

use std::fs::File;
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use supernet_core::{Engine, Profile};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Log(Mutex<Option<File>>);

impl Log {
    fn line(&self, s: impl AsRef<str>) {
        let s = s.as_ref();
        println!("{s}");
        if let Some(f) = self.0.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            let _ = writeln!(f, "{s}");
            let _ = f.flush();
        }
    }
}

pub async fn run(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut profile_path: Option<PathBuf> = None;
    let mut seconds = 45u64;
    let mut log_path: Option<PathBuf> = None;
    let mut wintun: Option<String> = None;
    let mut mesh: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" | "-p" => profile_path = Some(args.next().context("--profile 需要文件路径")?.into()),
            "--seconds" => seconds = args.next().context("--seconds 需要秒数")?.parse()?,
            "--log" => log_path = Some(args.next().context("--log 需要文件路径")?.into()),
            "--wintun" => wintun = Some(args.next().context("--wintun 需要 wintun.dll 路径")?),
            "--mesh" => mesh = Some(args.next().context("--mesh 需要 supernet-net:// 邀请链接")?),
            other => bail!("未知参数 {other}"),
        }
    }
    let seconds = seconds.clamp(10, 180);
    let log = Arc::new(Log(Mutex::new(log_path.as_ref().map(File::create).transpose().context("创建日志文件")?)));

    // Watchdog: whatever happens, the process (and with it the adapter and routes) is gone.
    {
        let log = log.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(seconds + 10));
            log.line("看门狗：超时，强制退出");
            std::process::exit(3);
        });
    }

    let result = session(&log, profile_path, seconds, wintun, mesh).await;
    if let Err(e) = &result {
        log.line(format!("失败：{e:#}"));
    }
    log.line("结束，TUN 网卡和路由已撤掉");
    result
}

async fn session(log: &Log, profile_path: Option<PathBuf>, seconds: u64, wintun: Option<String>, mesh: Option<String>) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    if !supernet_tun::has_privilege() {
        bail!("需要管理员权限");
    }
    let path = profile_path.context("缺少 --profile")?;
    let profile = Profile::load(&path)?;
    let (engine, warnings) = Engine::new(profile, path.parent().map(PathBuf::from))?;
    for w in warnings {
        log.line(format!("警告：{w}"));
    }

    // Resolve once before TUN so the process's name-service providers are loaded.
    let warm = Instant::now();
    let w = system_lookup("www.example.com:80").await;
    log.line(format!("TUN 前预热解析 www.example.com（{} ms）：{w:?}", warm.elapsed().as_millis()));
    supernet_core::tun::set_dns_trace(true);
    let physical = supernet_netstack::sysnet::default_interface_index().context("找出物理网卡")?;
    log.line(format!("物理网卡编号 {physical}"));
    supernet_netstack::sysnet::set_bypass_interface(Some(physical));
    let ports = engine.start_tun(supernet_tun::MTU as usize).await?;
    let mut device = match supernet_tun::start(ports, supernet_tun::TunOptions { wintun_dll: wintun, ..Default::default() }).await {
        Ok(d) => d,
        Err(e) => {
            engine.stop_tun().await;
            supernet_netstack::sysnet::set_bypass_interface(None);
            return Err(e);
        }
    };
    log.line(format!(
        "TUN 已启动，网卡编号 {}，DNS 防泄漏：{}，{} 秒后自动退出",
        device.if_index,
        device.dns_guard_error.as_deref().map_or("已启用".to_string(), |e| format!("未启用（{e}）")),
        seconds
    ));
    if let Some(link) = mesh {
        let key_file = path.with_file_name("mesh-test.key");
        let r = mesh_session(log, &link, &key_file, &mut device, deadline).await;
        drop(device);
        engine.stop_tun().await;
        supernet_netstack::sysnet::set_bypass_interface(None);
        return r;
    }
    if cfg!(windows) {
        log.line(shell("route", &["print", "-4"]));
        log.line(shell("netsh", &["interface", "ipv4", "show", "interface"]));
        log.line(shell("powershell", &["-NoProfile", "-Command", &format!("Get-DnsClientServerAddress -InterfaceIndex {} | Format-Table AddressFamily, ServerAddresses | Out-String -Width 120", device.if_index)]));
        log.line(shell("powershell", &["-NoProfile", "-Command", &format!("Get-NetIPAddress -InterfaceIndex {} | Format-Table IPAddress, PrefixLength | Out-String -Width 120", device.if_index)]));
    } else if cfg!(target_os = "macos") {
        log.line(shell("netstat", &["-rn", "-f", "inet"]));
        log.line(shell("ifconfig", &[&device.name]));
        log.line(shell("scutil", &["--dns"]).lines().filter(|l| l.contains("nameserver") || l.contains("resolver #") || l.contains("if_index")).take(12).collect::<Vec<_>>().join("
"));
    } else {
        log.line(shell("ip", &["-4", "route"]));
        log.line(shell("ip", &["addr", "show", "dev", &device.name]));
        log.line(shell("resolvectl", &["status", &device.name]));
    }

    let mut seq = 0u64;
    let t0 = supernet_core::stats::now_ms();
    let dump = |seq: &mut u64| {
        for l in engine.logs(*seq) {
            *seq = l.seq;
            log.line(format!("  {:>6} ms 引擎[{}] {}", l.time_ms.saturating_sub(t0) as i64, l.level, l.message));
        }
        log.line(format!("  TUN：{}", device.stats.summary()));
    };

    tokio::time::sleep(Duration::from_secs(2)).await;
    dump(&mut seq);

    let probes: Vec<(&str, std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send>>)> = vec![
        ("DNS 172.19.0.2 查询 www.baidu.com", Box::pin(dns_probe("172.19.0.2:53".parse()?, "www.baidu.com"))),
        ("DNS 223.5.5.5 查询 www.baidu.com（应被劫持）", Box::pin(dns_probe("223.5.5.5:53".parse()?, "www.baidu.com"))),
        ("其他进程绕过 TUN 直接问物理网卡的 IPv6 DNS（应被拦截）", Box::pin(bypass_dns_probe())),
        ("nslookup 自带套接字查 172.19.0.2", Box::pin(timed_shell("nslookup", vec!["www.sogou.com".into(), "172.19.0.2".into()]))),
        ("系统解析（每 2 秒换一个新域名，看多久恢复）", Box::pin(lookup_until_fast())),
        ("系统解析 api.ipify.org", Box::pin(system_lookup("api.ipify.org:80"))),
        ("HTTP 直连 www.baidu.com", Box::pin(http_probe("www.baidu.com", "/"))),
    ];
    let mut probes = probes;
    for node in engine.nodes() {
        let engine = engine.clone();
        let name = node.name.clone();
        probes.push((
            Box::leak(format!("引擎测速节点 {name}").into_boxed_str()),
            Box::pin(async move { engine.probe(&name).await.map(|d| format!("{} ms", d.as_millis())) }),
        ));
    }
    probes.push(("HTTP 经节点 api.ipify.org（应显示节点公网 IP）", Box::pin(http_probe("api.ipify.org", "/"))));
    for (name, probe) in probes {
        if Instant::now() >= deadline {
            break;
        }
        let started = Instant::now();
        log.line(format!("  {:>6} ms 开始：{name}", supernet_core::stats::now_ms().saturating_sub(t0)));
        let r = tokio::time::timeout(Duration::from_secs(40), probe).await;
        let ms = started.elapsed().as_millis();
        match r {
            Ok(Ok(s)) => log.line(format!("✔ {name}（{ms} ms）：{s}")),
            Ok(Err(e)) => log.line(format!("✘ {name}（{ms} ms）：{e:#}")),
            Err(_) => log.line(format!("✘ {name}：40 秒超时")),
        }
        dump(&mut seq);
    }

    // A short tail so packets from other programs show up in the counters.
    let tail = deadline.min(Instant::now() + Duration::from_secs(5));
    tokio::time::sleep_until(tail.into()).await;
    dump(&mut seq);

    drop(device);
    engine.stop_tun().await;
    supernet_netstack::sysnet::set_bypass_interface(None);
    Ok(())
}

/// Join the network, put its address on the adapter, ping the members through it.
async fn mesh_session(log: &Log, link: &str, key_file: &std::path::Path, device: &mut supernet_tun::TunDevice, deadline: Instant) -> Result<()> {
    use supernet_mesh::{device as mesh, proto};
    let invite = proto::Invite::parse(link)?;
    // A stable identity across runs, so the device keeps its address.
    let key = match std::fs::read_to_string(key_file) {
        Ok(k) => proto::unb64(&k)?,
        Err(_) => {
            let k = proto::generate_secret();
            std::fs::write(key_file, proto::b64(&k))?;
            k
        }
    };
    let name = std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::process::Command::new("hostname").arg("-s").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "tun-test".into());
    let (m, ports) = mesh::Mesh::start(mesh::MeshConfig::new(invite, key, name)).await?;
    let started = Instant::now();
    let ip = m.wait_joined(Duration::from_secs(20)).await?;
    let st = m.status();
    log.line(format!(
        "已加入组网：本机 {ip}/{}，{} ms；协调服务看到的本机地址 {:?}；成员 {}",
        st.prefix,
        started.elapsed().as_millis(),
        st.observed,
        st.members.iter().map(|x| format!("{} {}{}", x.ip, x.name, if x.online { "" } else { "（离线）" })).collect::<Vec<_>>().join("，")
    ));
    let mesh::MeshPorts { to_mesh, from_mesh } = ports;
    device.attach_mesh(ip, st.prefix, to_mesh, from_mesh)?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let targets: Vec<std::net::Ipv4Addr> = m.status().members.iter().filter(|x| x.ip != ip && x.online).map(|x| x.ip).collect();
    for t in targets {
        if Instant::now() >= deadline {
            break;
        }
        let t = t.to_string();
        let me = ip.to_string();
        let shown = t.clone();
        let out = tokio::task::spawn_blocking(move || {
            if cfg!(windows) {
                shell("ping", &["-n", "6", "-w", "3000", &t])
            } else {
                // The route and source the system picks, then a ping with the mesh address as source.
                let route = if cfg!(target_os = "macos") { shell("route", &["-n", "get", &t]) } else { shell("ip", &["route", "get", &t]) };
                let plain = shell("ping", &["-c", "3", &t]);
                let sourced = if cfg!(target_os = "macos") { shell("ping", &["-c", "3", "-S", &me, &t]) } else { shell("ping", &["-c", "3", "-I", &me, &t]) };
                format!("{route}\n（不指定源地址）\n{plain}\n（源地址 {me}）\n{sourced}")
            }
        })
        .await?;
        let summary: Vec<&str> = out
            .lines()
            .filter(|l| {
                let low = l.to_lowercase();
                low.contains("ttl") || l.contains('%') || l.contains("ms") || l.contains("源地址") || low.contains("interface") || low.contains(" dev ")
            })
            .collect();
        log.line(format!("ping {shown}：\n{}", summary.join("\n")));
    }
    let st = m.status();
    log.line(format!("组网发送失败 {} 次，最后一次：{:?}", st.send_errors, st.last_send_error));
    for p in m.status().peers {
        log.line(format!(
            "  对端 {} {}：路径 {:?}{}，延迟 {:?} ms，握手 {:?} 秒前，发 {} 收 {}，候选 {:?}",
            p.ip,
            p.name,
            p.kind,
            p.via.map(|v| format!(" 经 {v}")).unwrap_or_default(),
            p.rtt_ms,
            p.handshake_s,
            p.tx_bytes,
            p.rx_bytes,
            p.candidates
        ));
    }
    log.line(format!("  TUN：{}", device.stats.summary()));
    device.detach_mesh();
    Ok(())
}

fn shell(cmd: &str, args: &[&str]) -> String {
    match std::process::Command::new(cmd).args(args).output() {
        Ok(out) => {
            // Console tools print in the OEM code page; keep the ASCII parts readable.
            String::from_utf8_lossy(&out.stdout).lines().filter(|l| !l.trim().is_empty()).collect::<Vec<_>>().join("\n")
        }
        Err(e) => format!("{cmd}: {e}"),
    }
}

/// A plain A query over an ordinary (unpinned) UDP socket.
async fn dns_probe(server: SocketAddr, name: &str) -> Result<String> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    sock.send_to(&q, server).await?;
    let mut buf = [0u8; 1500];
    let (n, from) = sock.recv_from(&mut buf).await?;
    let resp = &buf[..n];
    if n < 12 || resp[0..2] != [0x12, 0x34] {
        bail!("{from} 回了无效应答（{n} 字节）");
    }
    let rcode = resp[3] & 0x0f;
    let answers = u16::from_be_bytes([resp[6], resp[7]]);
    // Skip the question, then collect A records.
    let mut i = 12;
    while i < n && resp[i] != 0 {
        i += 1 + resp[i] as usize;
    }
    i += 5;
    let mut ips = Vec::new();
    for _ in 0..answers {
        if i + 12 > n {
            break;
        }
        i += if resp[i] & 0xc0 == 0xc0 { 2 } else { skip_name(resp, i) - i };
        let rtype = u16::from_be_bytes([resp[i], resp[i + 1]]);
        let len = u16::from_be_bytes([resp[i + 8], resp[i + 9]]) as usize;
        i += 10;
        if rtype == 1 && len == 4 && i + 4 <= n {
            ips.push(Ipv4Addr::new(resp[i], resp[i + 1], resp[i + 2], resp[i + 3]).to_string());
        }
        i += len;
    }
    Ok(format!("来自 {from}，rcode {rcode}，A 记录 {}", if ips.is_empty() { "无".into() } else { ips.join(", ") }))
}

fn skip_name(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i] != 0 {
        if b[i] & 0xc0 == 0xc0 {
            return i + 2;
        }
        i += 1 + b[i] as usize;
    }
    i + 1
}

/// Start a lookup of a fresh name every 2 s (each in its own task); report
/// when each one finished, until one answers within 500 ms.
async fn lookup_until_fast() -> Result<String> {
    const NAMES: [&str; 12] = [
        "www.baidu.com", "www.qq.com", "www.163.com", "www.jd.com", "www.sina.com.cn", "www.sohu.com",
        "www.taobao.com", "www.bilibili.com", "www.zhihu.com", "www.douban.com", "www.ctrip.com", "www.360.cn",
    ];
    let start = Instant::now();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    for (i, name) in NAMES.iter().enumerate() {
        let tx = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2 * i as u64)).await;
            let began = start.elapsed().as_millis();
            let t = Instant::now();
            let r = system_lookup(&format!("{name}:80")).await;
            let _ = tx.send((*name, began, t.elapsed().as_millis(), r.map_err(|e| e.to_string())));
        });
    }
    drop(tx);
    let mut out = Vec::new();
    while let Some((name, began, took, r)) = rx.recv().await {
        out.push(format!("{name} 第{began}ms发起 用时{took}ms {}", r.unwrap_or_else(|e| e)));
        if took < 500 {
            break;
        }
    }
    Ok(out.join("；"))
}

/// From another process (powershell), query the DNS servers of the other
/// adapters that are up and not routed into the TUN (IPv6 ones).
async fn bypass_dns_probe() -> Result<String> {
    if !cfg!(windows) {
        // Other systems: the DNS hijack probe (223.5.5.5 above) covers it.
        return Ok("（只在 Windows 上检查）".into());
    }
    let script = r#"
$up = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -ne 'superNET' } | ForEach-Object { $_.ifIndex }
$lines = foreach ($a in Get-DnsClientServerAddress -AddressFamily IPv6 | Where-Object { $up -contains $_.InterfaceIndex -and $_.ServerAddresses }) {
  foreach ($s in ($a.ServerAddresses | Select-Object -Unique)) {
    $server = if ($s -like 'fe80*') { "$s%$($a.InterfaceIndex)" } else { $s }
    $t = Measure-Command { try { Resolve-DnsName www.qq.com -Server $server -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null; $script:ok = 'answered' } catch { $script:ok = 'failed: ' + $_.Exception.Message } }
    "$($a.InterfaceAlias) $server $([int]$t.TotalMilliseconds)ms $script:ok"
  }
}
if ($lines) { $lines } else { 'no IPv6 DNS servers on other adapters' }
"#;
    timed_shell("powershell", vec!["-NoProfile".into(), "-Command".into(), script.into()]).await
}

#[allow(dead_code)]
async fn nla_status(if_index: u32) -> Result<String> {
    let script = format!(
        "Get-NetConnectionProfile | Format-Table InterfaceAlias, InterfaceIndex, Name, NetworkCategory, IPv4Connectivity, IPv6Connectivity | Out-String -Width 160; Get-NetIPInterface -InterfaceIndex {if_index} | Format-Table AddressFamily, ConnectionState, InterfaceMetric | Out-String -Width 120"
    );
    timed_shell("powershell", vec!["-NoProfile".into(), "-Command".into(), script]).await
}

async fn timed_shell(cmd: &'static str, args: Vec<String>) -> Result<String> {
    let started = Instant::now();
    let out = tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        shell(cmd, &refs)
    })
    .await?;
    Ok(format!("{} ms
{out}", started.elapsed().as_millis()))
}

async fn system_lookup(host: &str) -> Result<String> {
    let addrs: Vec<String> = tokio::net::lookup_host(host).await?.map(|a| a.ip().to_string()).collect();
    Ok(addrs.join(", "))
}

/// GET over an ordinary socket: resolves through Windows (→ fake IP) and connects through the TUN.
async fn http_probe(host: &str, path: &str) -> Result<String> {
    let addr = tokio::net::lookup_host((host, 80)).await?.next().context("解析无结果")?;
    let started = Instant::now();
    let mut s = tokio::net::TcpStream::connect(addr).await.with_context(|| format!("连接 {addr}"))?;
    let connected = started.elapsed();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n").as_bytes()).await?;
    let mut body = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(6), s.read_to_end(&mut body)).await;
    let text = String::from_utf8_lossy(&body);
    let status = text.lines().next().unwrap_or("（无应答）").to_string();
    let tail = text.split("\r\n\r\n").nth(1).map(|b| b.trim().chars().take(60).collect::<String>()).unwrap_or_default();
    Ok(format!("{addr}，握手 {} ms，{status}，{} 字节{}", connected.as_millis(), body.len(), if tail.len() < 40 { format!("，正文 {tail}") } else { String::new() }))
}
