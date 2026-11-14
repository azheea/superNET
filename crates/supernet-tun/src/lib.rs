//! The TUN device and system routes for TUN mode.
//!
//! Windows: a wintun adapter `superNET` at 172.19.0.1/30 and fdfe:dcba:9876::1/126
//! with DNS 172.19.0.2 and fdfe:dcba:9876::2,
//! routes 0.0.0.0/1 and 128.0.0.0/1 (more specific than any default route)
//! plus the physical adapters' DNS servers (/32), so their answers cannot
//! race ours. Routes use `store=active`: nothing is persisted, and they
//! disappear with the adapter even if superNET crashes.

#[cfg(windows)]
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use supernet_netstack::PacketPorts;
use tokio::task::JoinHandle;

#[cfg(windows)]
mod wfp;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;

pub const TUN_NAME: &str = "superNET";
pub const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 1);
pub const TUN_DNS: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 2);
pub const MTU: u16 = 1500;
/// Unique-local IPv6 for the adapter and its DNS server.
pub const TUN_ADDR6: Ipv6Addr = Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 1);
pub const TUN_DNS6: Ipv6Addr = Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 2);

#[derive(Default)]
pub struct TunOptions {
    /// Path of wintun.dll (Windows).
    pub wintun_dll: Option<String>,
    /// Only the virtual network goes through the device: no default routes, no
    /// DNS change (servers that only want to join the network).
    pub mesh_only: bool,
}

/// Packet counters of a running TUN device.
#[derive(Default)]
pub struct TunStats {
    pub rx_packets: AtomicU64,
    /// Packets to and from the virtual network.
    pub mesh_out: AtomicU64,
    pub mesh_in: AtomicU64,
    pub tx_packets: AtomicU64,
    pub errors: AtomicU64,
    pub last_error: std::sync::Mutex<Option<String>>,
}

impl TunStats {
    fn note_error(&self, what: &str, e: &std::io::Error) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        let msg = format!("{what}: {e} ({:?})", e.kind());
        tracing::warn!("tun {msg}");
        *self.last_error.lock().unwrap_or_else(|p| p.into_inner()) = Some(msg);
    }

    pub fn summary(&self) -> String {
        let last = self.last_error.lock().unwrap_or_else(|p| p.into_inner()).clone();
        format!(
            "收 {} 包，发 {} 包，组网出 {} 入 {}，错误 {}{}",
            self.rx_packets.load(Ordering::Relaxed),
            self.tx_packets.load(Ordering::Relaxed),
            self.mesh_out.load(Ordering::Relaxed),
            self.mesh_in.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
            last.map(|l| format!("（最近：{l}）")).unwrap_or_default()
        )
    }
}

/// A running TUN device; dropping it removes routes and the adapter.
pub struct TunDevice {
    pub stats: Arc<TunStats>,
    mesh: MeshSlot,
    mesh_task: Option<JoinHandle<()>>,
    device: Arc<tun_rs::AsyncDevice>,
    /// Why DNS leak protection is off, if it is (it never blocks TUN mode).
    pub dns_guard_error: Option<String>,
    #[cfg(windows)]
    _dns_guard: Option<wfp::DnsGuard>,
    tasks: Vec<JoinHandle<()>>,
    #[cfg(windows)]
    routes: Vec<String>,
    /// Linux/macOS: routes and DNS to undo (dropped after the tasks stop).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    _takeover: Option<unix::Takeover>,
    /// The adapter's name (utunN on macOS).
    pub name: String,
    pub if_index: u32,
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        for t in self.tasks.iter().chain(self.mesh_task.iter()) {
            t.abort();
        }
        #[cfg(windows)]
        for prefix in &self.routes {
            let family = if prefix.contains(':') { "ipv6" } else { "ipv4" };
            let _ = netsh(&["interface", family, "delete", "route", prefix, &format!("interface={}", self.if_index), "store=active"]);
        }
    }
}

/// Create the device, wire it to the stack's packet ports and take over routing.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub async fn start(ports: PacketPorts, opts: TunOptions) -> Result<TunDevice> {
    let builder = tun_rs::DeviceBuilder::new().ipv4(TUN_ADDR, 30u8, None).ipv6(TUN_ADDR6, 126u8).mtu(MTU);
    // macOS names TUN devices utunN itself.
    #[cfg(not(target_os = "macos"))]
    let builder = builder.name(TUN_NAME);
    #[cfg(windows)]
    let mut builder = builder;
    #[cfg(windows)]
    {
        builder = builder.metric(1);
        if let Some(dll) = &opts.wintun_dll {
            builder = builder.wintun_file(dll.clone());
        }
    }
    let device = Arc::new(builder.build_async().context("创建 TUN 网卡失败（需要管理员权限，Windows 还需要 wintun.dll）")?);
    let if_index = device.if_index().context("读取 TUN 网卡编号")?;
    let name = device.name().unwrap_or_else(|_| TUN_NAME.to_string());
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    unix::clear_stale_dns();
    let (stats, mesh, tasks) = spawn_io(device.clone(), ports);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let takeover = if opts.mesh_only { None } else { Some(unix::take_over(&name, TUN_DNS)?) };

    #[cfg(windows)]
    let routes = if opts.mesh_only {
        Vec::new()
    } else {
        // Both families: Windows only sends AAAA queries to adapters that have
        // IPv6, so without it AAAA lookups wait on the other adapters' DNS
        // servers (seconds, when one of them is unreachable).
        device.set_dns_servers(&[IpAddr::V4(TUN_DNS)]).context("设置 TUN 网卡 DNS")?;
        // tun-rs takes one family at a time; the IPv6 server goes through netsh.
        if let Err(e) = netsh(&[
            "interface", "ipv6", "set", "dnsservers", &format!("name={if_index}"), "source=static", &format!("address={TUN_DNS6}"), "validate=no",
        ]) {
            tracing::warn!("TUN IPv6 DNS: {e:#}");
        }
        let mut routes: Vec<String> = vec!["0.0.0.0/1".into(), "128.0.0.0/1".into()];
        for dns in physical_dns_servers() {
            if let IpAddr::V4(v4) = dns {
                if v4 != TUN_DNS {
                    routes.push(format!("{v4}/32"));
                }
            }
        }
        let mut added = Vec::new();
        for prefix in routes {
            let ok = netsh(&[
                "interface", "ipv4", "add", "route", &prefix, &format!("interface={if_index}"), "nexthop=0.0.0.0", "metric=1", "store=active",
            ]);
            match ok {
                Ok(()) => added.push(prefix),
                Err(e) => tracing::warn!("route {prefix}: {e:#}"),
            }
        }
        if !added.iter().any(|r| r == "0.0.0.0/1") {
            anyhow::bail!("添加 TUN 路由失败");
        }
        added
    };

    #[cfg(windows)]
    let (dns_guard, dns_guard_error) = match if opts.mesh_only { Err(anyhow::anyhow!("只组网模式不接管 DNS")) } else { wfp::block_dns_leaks(if_index) } {
        Ok(g) => (Some(g), None),
        Err(e) => {
            tracing::warn!("DNS 防泄漏未启用：{e:#}");
            (None, Some(format!("{e:#}")))
        }
    };
    #[cfg(not(windows))]
    let dns_guard_error = Some("此平台暂不支持".to_string());

    Ok(TunDevice {
        stats,
        dns_guard_error,
        #[cfg(windows)]
        _dns_guard: dns_guard,
        tasks,
        #[cfg(windows)]
        routes,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        _takeover: takeover,
        mesh,
        mesh_task: None,
        device,
        name,
        if_index,
    })
}

/// Read packets from the device into the stack (or the mesh) and write the
/// stack's packets back.
fn spawn_io(device: Arc<tun_rs::AsyncDevice>, ports: PacketPorts) -> (Arc<TunStats>, MeshSlot, Vec<JoinHandle<()>>) {
    let PacketPorts { to_stack, mut from_stack } = ports;
    let stats = Arc::new(TunStats::default());
    let mesh: MeshSlot = Arc::new(std::sync::Mutex::new(None));
    let reader = {
        let device = device.clone();
        let stats = stats.clone();
        let mesh = mesh.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                match device.recv(&mut buf).await {
                    Ok(n) => {
                        stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                        // Virtual-network packets go to the mesh as they are, not to the proxy stack.
                        if let Some(tx) = mesh_target(&mesh, &buf[..n]) {
                            stats.mesh_out.fetch_add(1, Ordering::Relaxed);
                            let _ = tx.try_send(buf[..n].to_vec());
                            continue;
                        }
                        if to_stack.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    // A read error must not end the reader: count it and go on.
                    Err(e) => {
                        stats.note_error("recv", &e);
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }
            }
        })
    };
    let writer = {
        let device = device.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            while let Some(packet) = from_stack.recv().await {
                match device.send(&packet).await {
                    Ok(_) => {
                        stats.tx_packets.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => stats.note_error("send", &e),
                }
            }
        })
    };

    (stats, mesh, vec![reader, writer])
}

/// Android: wrap the TUN file descriptor from `VpnService.Builder.establish()`
/// (iOS: the utun descriptor of the Network Extension's packet flow).
/// Addresses, routes and DNS were set by the VpnService; superNET's own
/// sockets bypass the VPN because the app excludes itself from it.
#[cfg(unix)]
pub fn start_fd(fd: std::os::fd::RawFd, ports: PacketPorts) -> Result<TunDevice> {
    // SAFETY: the caller hands over ownership of an open TUN descriptor.
    let device = Arc::new(unsafe { tun_rs::AsyncDevice::from_fd(fd) }.context("接管 VPN 网卡")?);
    let (stats, mesh, tasks) = spawn_io(device.clone(), ports);
    Ok(TunDevice {
        stats,
        dns_guard_error: Some("由系统 VPN 处理".to_string()),
        tasks,
        mesh,
        mesh_task: None,
        device,
        name: "tun0".into(),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        _takeover: None,
        if_index: 0,
    })
}

type MeshSlot = Arc<std::sync::Mutex<Option<(u32, u32, tokio::sync::mpsc::Sender<Vec<u8>>)>>>;

/// Where an IPv4 packet from the OS goes if its destination is in the virtual network.
fn mesh_target(slot: &MeshSlot, packet: &[u8]) -> Option<tokio::sync::mpsc::Sender<Vec<u8>>> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let dst = u32::from_be_bytes([packet[16], packet[17], packet[18], packet[19]]);
    let guard = slot.lock().unwrap_or_else(|e| e.into_inner());
    let (net, mask, tx) = guard.as_ref()?;
    // The subnet's broadcast address never goes to a peer.
    (dst & mask == *net && dst | mask != u32::MAX).then(|| tx.clone())
}

impl TunDevice {
    /// Join the virtual network: give the adapter its address `ip/prefix`, send
    /// that subnet's packets to `to_mesh` and write what `from_mesh` yields.
    pub fn attach_mesh(
        &mut self,
        ip: Ipv4Addr,
        prefix: u8,
        to_mesh: tokio::sync::mpsc::Sender<Vec<u8>>,
        mut from_mesh: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) -> Result<()> {
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
        #[cfg(windows)]
        {
            let mask_ip = Ipv4Addr::from(mask);
            netsh(&[
                "interface", "ipv4", "add", "address", &format!("name={}", self.if_index), &format!("address={ip}"), &format!("mask={mask_ip}"),
                "store=active",
            ])
            .context("给 TUN 网卡添加组网地址")?;
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        unix::add_address(&self.name, ip, prefix).context("给 TUN 网卡添加组网地址")?;
        *self.mesh.lock().unwrap_or_else(|e| e.into_inner()) = Some((u32::from(ip) & mask, mask, to_mesh));
        let device = self.device.clone();
        let stats = self.stats.clone();
        if let Some(t) = self.mesh_task.take() {
            t.abort();
        }
        self.mesh_task = Some(tokio::spawn(async move {
            while let Some(packet) = from_mesh.recv().await {
                stats.mesh_in.fetch_add(1, Ordering::Relaxed);
                if let Err(e) = device.send(&packet).await {
                    stats.note_error("mesh send", &e);
                }
            }
        }));
        Ok(())
    }

    /// Leave the virtual network (the adapter keeps running for the proxy).
    pub fn detach_mesh(&mut self) {
        *self.mesh.lock().unwrap_or_else(|e| e.into_inner()) = None;
        if let Some(t) = self.mesh_task.take() {
            t.abort();
        }
    }
}

#[cfg(windows)]
fn run_hidden(cmd: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    std::process::Command::new(cmd).args(args).creation_flags(CREATE_NO_WINDOW).output()
}

#[cfg(windows)]
fn netsh(args: &[&str]) -> Result<()> {
    let out = run_hidden("netsh", args).context("运行 netsh")?;
    if out.status.success() {
        Ok(())
    } else {
        anyhow::bail!("netsh {}: {}", args.join(" "), String::from_utf8_lossy(&out.stdout).trim())
    }
}

/// DNS servers configured on the other (physical) adapters.
#[cfg(windows)]
fn physical_dns_servers() -> Vec<IpAddr> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let script = format!(
        "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {{ $_.InterfaceAlias -ne '{TUN_NAME}' }} | ForEach-Object {{ $_.ServerAddresses }}"
    );
    let Ok(out) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    else {
        return Vec::new();
    };
    let mut servers: Vec<IpAddr> = String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| l.trim().parse().ok()).collect();
    servers.sort();
    servers.dedup();
    servers
}

/// Whether this process can create a TUN device (administrator on Windows).
pub fn has_privilege() -> bool {
    #[cfg(windows)]
    {
        // SAFETY: no arguments; returns nonzero for an elevated administrator.
        unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
    }
    // Android and iOS: the system asks the user for VPN permission instead.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        true
    }
    #[cfg(unix)]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        // SAFETY: no arguments.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(any(windows, unix)))]
    {
        false
    }
}
