//! What the superNET UI controls, independent of the shell that shows it:
//! the engine, the saved profile, the system proxy, TUN mode and the virtual
//! network. The desktop/mobile app (Tauri) and the headless web console
//! (`supernet --web`) both drive a [`Controller`], so they behave the same.
//!
//! Every UI command is a method here; [`Controller::dispatch`] maps a command
//! name and its JSON arguments onto them (the web console's API).

use std::future::Future;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use supernet_core::config::{GroupConfig, GroupKind, MeshProfile, NodeKind, DIRECT};
use supernet_core::engine::{NodeStatus, RouteInfo, Status};
use supernet_core::stats::{ConnInfo, LogLine};
use supernet_core::{wgconf, Engine, Mode, Profile};
use tokio::sync::Mutex;

const DEFAULT_GROUP: &str = "代理";

pub type Res<T> = Result<T, String>;

pub fn fail(e: impl Into<anyhow::Error>) -> String {
    format!("{:#}", e.into())
}

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A system VPN service that owns the device and hands over its descriptor
/// (Android's VpnService). Without one, TUN mode creates its own device.
pub trait Vpn: Send + Sync {
    /// Ask for the user's permission.
    fn prepare(&self) -> BoxFut<'_, anyhow::Result<()>>;
    /// Start the VPN (with the virtual network's address, if any) and return its descriptor.
    fn establish(&self, mtu: u16, mesh: Option<(Ipv4Addr, u8)>) -> BoxFut<'_, anyhow::Result<i32>>;
    fn stop(&self) -> BoxFut<'_, ()>;
}

pub struct Options {
    /// Where the profile and the app's other files live.
    pub data_dir: PathBuf,
    /// The profile file (normally `data_dir/profile.yaml`).
    pub profile_path: PathBuf,
    pub vpn: Option<Arc<dyn Vpn>>,
    /// TUN mode carries only the virtual network (servers): no default routes, no DNS.
    pub mesh_only: bool,
    /// TUN mode on whatever the profile says (`supernet --tun` / `--mesh-only`).
    pub force_tun: bool,
}

pub struct Controller {
    pub engine: Engine,
    profile_path: PathBuf,
    proxy_backup: PathBuf,
    data_dir: PathBuf,
    vpn: Option<Arc<dyn Vpn>>,
    mesh_only: bool,
    force_tun: bool,
    /// The proxy address we pointed the OS at, while we have.
    system_proxy_on: Mutex<Option<String>>,
    /// Serialises profile edits so concurrent commands cannot lose changes.
    edit: Mutex<()>,
    warnings: std::sync::Mutex<Vec<String>>,
    /// The TUN device while TUN mode runs.
    tun: Arc<Mutex<Option<supernet_tun::TunDevice>>>,
    /// The virtual network while it runs (inside TUN mode).
    mesh: Mutex<Option<MeshRun>>,
}

struct MeshRun {
    mesh: Arc<supernet_mesh::device::Mesh>,
    /// The profile entry it was started from (restart when it changes).
    cfg: MeshProfile,
    attach: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for MeshRun {
    fn drop(&mut self) {
        if let Some(t) = &self.attach {
            t.abort();
        }
    }
}

fn load_profile(path: &Path, notes: &mut Vec<String>) -> Profile {
    if !path.exists() {
        return Profile::default();
    }
    match Profile::load(path) {
        Ok(p) => p,
        Err(e) => {
            let broken = path.with_extension(format!("broken-{}.yaml", supernet_core::stats::now_ms()));
            let _ = std::fs::rename(path, &broken);
            notes.push(format!("配置文件无法读取，已改名为 {} 并使用默认配置：{e:#}", broken.display()));
            Profile::default()
        }
    }
}

impl Controller {
    /// Load the profile (or start from the default one), repair a system proxy
    /// left behind by a crash, and build the engine. Nothing runs yet; call
    /// [`Controller::connect`] (the profile's `auto_connect` says whether to).
    pub fn open(opts: Options) -> anyhow::Result<Arc<Controller>> {
        std::fs::create_dir_all(&opts.data_dir)?;
        let proxy_backup = opts.data_dir.join("system-proxy-backup.json");
        let mut notes = Vec::new();
        let profile = load_profile(&opts.profile_path, &mut notes);

        // A crash may have left the OS pointing at us; put it back first.
        let server = format!("127.0.0.1:{}", profile.listen.port());
        match supernet_sysproxy::recover(&server, &proxy_backup) {
            Ok(true) => notes.push("上次没有正常退出，已恢复原来的系统代理设置".into()),
            Ok(false) => {}
            Err(e) => notes.push(format!("恢复系统代理失败：{e:#}")),
        }

        let (engine, mut warnings) = match Engine::new(profile, Some(opts.data_dir.clone())) {
            Ok(ok) => ok,
            Err(e) => {
                notes.push(format!("配置有误，已改用默认配置：{e:#}"));
                Engine::new(Profile::default(), Some(opts.data_dir.clone()))?
            }
        };
        warnings.extend(notes);
        Ok(Arc::new(Controller {
            engine,
            profile_path: opts.profile_path,
            proxy_backup,
            data_dir: opts.data_dir,
            vpn: opts.vpn,
            mesh_only: opts.mesh_only,
            force_tun: opts.force_tun,
            system_proxy_on: Mutex::new(None),
            edit: Mutex::new(()),
            warnings: std::sync::Mutex::new(warnings),
            tun: Arc::new(Mutex::new(None)),
            mesh: Mutex::new(None),
        }))
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// The device's name while TUN mode runs.
    pub async fn tun_name(&self) -> Option<String> {
        self.tun.lock().await.as_ref().map(|t| t.name.clone())
    }

    pub fn set_warnings(&self, w: Vec<String>) {
        *self.warnings.lock().unwrap_or_else(|e| e.into_inner()) = w;
    }

    /// Apply and persist a modified profile.
    async fn commit(&self, profile: Profile) -> Res<Vec<String>> {
        let warnings = self.engine.apply(profile.clone()).await.map_err(fail)?;
        profile.save(&self.profile_path).map_err(fail)?;
        self.set_warnings(warnings.clone());
        self.sync_system_proxy().await?;
        Ok(warnings)
    }

    /// Save selections and mode, which the engine changes without `apply`.
    fn persist(&self) -> Res<()> {
        self.engine.profile().save(&self.profile_path).map_err(fail)
    }

    /// Make the OS proxy match the profile and the running state.
    async fn sync_system_proxy(&self) -> Res<()> {
        let status = self.engine.status().await;
        let want = self.engine.profile().system_proxy && status.running;
        let mut on = self.system_proxy_on.lock().await;
        let server = status.listen.map(|a| format!("127.0.0.1:{}", a.port()));
        match (want, on.clone()) {
            (true, Some(cur)) if Some(&cur) == server.as_ref() => {}
            (true, prev) => {
                if let Some(prev) = prev {
                    supernet_sysproxy::disable(&prev, &self.proxy_backup).map_err(fail)?;
                }
                let server = server.expect("running implies a listen address");
                supernet_sysproxy::enable(&server, &self.proxy_backup).map_err(fail)?;
                *on = Some(server);
            }
            (false, Some(prev)) => {
                supernet_sysproxy::disable(&prev, &self.proxy_backup).map_err(fail)?;
                *on = None;
            }
            (false, None) => {}
        }
        Ok(())
    }

    /// Stop everything and give the system its proxy, routes and DNS back.
    pub async fn shutdown(&self) {
        self.stop_tun().await;
        if let Some(prev) = self.system_proxy_on.lock().await.take() {
            if let Err(e) = supernet_sysproxy::disable(&prev, &self.proxy_backup) {
                tracing::error!("restore system proxy: {e:#}");
            }
        }
        self.engine.stop().await;
    }

    /// Start the proxy, then TUN mode and/or the system proxy as configured.
    pub async fn connect(&self) -> Res<()> {
        self.engine.start().await.map_err(fail)?;
        if let Err(e) = self.sync_tun().await {
            self.shutdown().await;
            return Err(e);
        }
        if let Err(e) = self.sync_system_proxy().await {
            self.shutdown().await;
            return Err(format!("设置系统代理失败，已断开：{e}"));
        }
        Ok(())
    }

    /// Make TUN mode match the profile and the running state.
    async fn sync_tun(&self) -> Res<()> {
        let want = (self.engine.profile().tun || self.force_tun) && self.engine.status().await.running;
        let tun = self.tun.lock().await;
        match (want, tun.is_some()) {
            (true, false) if self.vpn.is_some() => {
                drop(tun);
                self.start_tun_vpn().await?;
            }
            (true, false) => {
                drop(tun);
                self.start_tun_device().await?;
            }
            (false, true) => {
                drop(tun);
                self.stop_tun().await;
            }
            _ => {}
        }
        Ok(())
    }

    fn privilege_error(&self) -> String {
        if cfg!(windows) {
            return "TUN 模式需要管理员权限：请点“以管理员身份重启”".to_string();
        }
        // The headless binary ships next to the app's own (superNET.app/Contents/MacOS,
        // /usr/bin) as supernet-cli: macOS file systems ignore case, "supernet" is superNET itself.
        let cli = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("supernet-cli")))
            .filter(|p| p.exists())
            .map_or_else(|| "supernet".to_string(), |p| p.display().to_string());
        format!(
            "TUN 模式（以及组网）需要 root 权限，应用本身只能用系统代理模式。请退出应用，在终端运行：sudo \"{cli}\" --profile \"{}\" --tun",
            self.profile_path.display()
        )
    }

    /// TUN mode with our own device (desktop, servers).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    async fn start_tun_device(&self) -> Res<()> {
        // The system owns the device there: TUN mode goes through its VPN service.
        Err("这个平台的 TUN 模式需要系统 VPN".into())
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn start_tun_device(&self) -> Res<()> {
        if !supernet_tun::has_privilege() {
            return Err(self.privilege_error());
        }
        // Pin our own sockets only when the device takes the default route; with
        // mesh_only the system's routes stay and nothing can loop back.
        let physical = if self.mesh_only {
            None
        } else {
            let p = supernet_netstack::sysnet::default_interface_index().map_err(fail)?;
            supernet_netstack::sysnet::set_bypass_interface(Some(p));
            Some(p)
        };
        let ports = match self.engine.start_tun(supernet_tun::MTU as usize).await {
            Ok(p) => p,
            Err(e) => {
                supernet_netstack::sysnet::set_bypass_interface(None);
                return Err(fail(e));
            }
        };
        let opts = supernet_tun::TunOptions { wintun_dll: wintun_path().map(|p| p.display().to_string()), mesh_only: self.mesh_only };
        match supernet_tun::start(ports, opts).await {
            Ok(device) => {
                match physical {
                    Some(p) => self.engine.log("info", format!("TUN 网卡已创建（出口网卡编号 {p}）")),
                    None => self.engine.log("info", "TUN 网卡已创建（只组网：默认路由和 DNS 不变）".into()),
                }
                if !self.mesh_only {
                    match &device.dns_guard_error {
                        None => self.engine.log("info", "DNS 防泄漏已启用：其他网卡上的 DNS 查询被拦截".into()),
                        Some(e) => self.engine.log("warn", format!("DNS 防泄漏未启用：{e}")),
                    }
                }
                *self.tun.lock().await = Some(device);
                if let Err(e) = self.sync_mesh().await {
                    self.engine.log("warn", format!("组网未启动：{e}"));
                }
                Ok(())
            }
            Err(e) => {
                self.engine.stop_tun().await;
                supernet_netstack::sysnet::set_bypass_interface(None);
                Err(fail(e))
            }
        }
    }

    /// Run the virtual network when TUN mode is on and a network is configured and enabled.
    async fn sync_mesh(&self) -> Res<()> {
        let want = self.engine.profile().mesh.filter(|m| m.enabled);
        if self.vpn.is_some() {
            // The network's address is part of the VPN configuration: restart the VPN.
            let same = matches!((&*self.mesh.lock().await, &want), (Some(run), Some(w)) if &run.cfg == w)
                || (self.mesh.lock().await.is_none() && want.is_none());
            if !same && self.tun.lock().await.is_some() {
                self.stop_tun().await;
                return self.start_tun_vpn().await;
            }
            return Ok(());
        }
        let tun_on = self.tun.lock().await.is_some();
        let mut cur = self.mesh.lock().await;
        let same = matches!((&*cur, &want), (Some(run), Some(w)) if &run.cfg == w);
        if same && tun_on {
            return Ok(());
        }
        if cur.take().is_some() {
            if let Some(t) = self.tun.lock().await.as_mut() {
                t.detach_mesh();
            }
            self.engine.log("info", "已退出组网".into());
        }
        let (Some(cfg), true) = (want, tun_on) else { return Ok(()) };
        let (mesh, ports) = start_mesh(&cfg).await?;
        let attach = {
            let mesh = mesh.clone();
            let tun = self.tun.clone();
            let engine = self.engine.clone();
            tokio::spawn(async move {
                // Keep trying: the coordinator may be unreachable for a while.
                let ip = loop {
                    match mesh.wait_joined(std::time::Duration::from_secs(30)).await {
                        Ok(ip) => break ip,
                        Err(e) => engine.log("warn", format!("组网：{e:#}")),
                    }
                };
                let prefix = mesh.status().prefix;
                let supernet_mesh::device::MeshPorts { to_mesh, from_mesh } = ports;
                match tun.lock().await.as_mut() {
                    Some(t) => match t.attach_mesh(ip, prefix, to_mesh, from_mesh) {
                        Ok(()) => engine.log("info", format!("已加入组网，本机地址 {ip}/{prefix}")),
                        Err(e) => engine.log("error", format!("组网地址设置失败：{e:#}")),
                    },
                    None => engine.log("warn", "TUN 已关闭，组网未接入".into()),
                }
            })
        };
        *cur = Some(MeshRun { mesh, cfg, attach: Some(attach) });
        Ok(())
    }

    async fn stop_tun(&self) {
        if let Some(run) = self.mesh.lock().await.take() {
            drop(run);
        }
        // Removing the device first gives the system its routes back.
        if self.tun.lock().await.take().is_some() {
            self.engine.stop_tun().await;
            supernet_netstack::sysnet::set_bypass_interface(None);
            if let Some(vpn) = &self.vpn {
                vpn.stop().await;
            }
        }
    }

    /// System VPN (Android): permission, then the virtual network (its address
    /// is part of the VPN configuration), then the VPN itself.
    async fn start_tun_vpn(&self) -> Res<()> {
        let vpn = self.vpn.clone().ok_or("没有系统 VPN")?;
        vpn.prepare().await.map_err(fail)?;
        let mut mesh_ports = None;
        if let Some(cfg) = self.engine.profile().mesh.filter(|m| m.enabled) {
            match start_mesh(&cfg).await {
                Ok((mesh, ports)) => match mesh.wait_joined(std::time::Duration::from_secs(15)).await {
                    Ok(ip) => {
                        let prefix = mesh.status().prefix;
                        mesh_ports = Some((ip, prefix, ports));
                        *self.mesh.lock().await = Some(MeshRun { mesh, cfg, attach: None });
                    }
                    Err(e) => self.engine.log("warn", format!("组网未接入：{e:#}")),
                },
                Err(e) => self.engine.log("warn", format!("组网未启动：{e}")),
            }
        }
        let ports = self.engine.start_tun(supernet_tun::MTU as usize).await.map_err(fail)?;
        let fd = match vpn.establish(supernet_tun::MTU, mesh_ports.as_ref().map(|(ip, p, _)| (*ip, *p))).await {
            Ok(fd) => fd,
            Err(e) => {
                self.engine.stop_tun().await;
                self.mesh.lock().await.take();
                return Err(fail(e));
            }
        };
        #[cfg(unix)]
        {
            let mut device = supernet_tun::start_fd(fd, ports).map_err(fail)?;
            if let Some((ip, prefix, ports)) = mesh_ports {
                let supernet_mesh::device::MeshPorts { to_mesh, from_mesh } = ports;
                device.attach_mesh(ip, prefix, to_mesh, from_mesh).map_err(fail)?;
                self.engine.log("info", format!("已加入组网，本机地址 {ip}/{prefix}"));
            }
            self.engine.log("info", "VPN 已启动".into());
            *self.tun.lock().await = Some(device);
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = (fd, ports, mesh_ports);
            Err("这个平台没有系统 VPN".into())
        }
    }
}

async fn start_mesh(cfg: &MeshProfile) -> Res<(Arc<supernet_mesh::device::Mesh>, supernet_mesh::device::MeshPorts)> {
    let invite = supernet_mesh::proto::Invite::parse(&cfg.invite).map_err(fail)?;
    let key = supernet_mesh::proto::unb64(&cfg.private_key).map_err(fail)?;
    let mut mc = supernet_mesh::device::MeshConfig::new(invite, key, cfg.name.clone());
    mc.relay = cfg.relay;
    let (mesh, ports) = supernet_mesh::device::Mesh::start(mc).await.map_err(fail)?;
    Ok((Arc::new(mesh), ports))
}

/// wintun.dll ships next to the executable.
fn wintun_path() -> Option<PathBuf> {
    let p = std::env::current_exe().ok()?.parent()?.join("wintun.dll");
    p.exists().then_some(p)
}

fn default_device_name() -> String {
    if cfg!(target_os = "android") {
        return "安卓手机".into();
    }
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "我的电脑".into())
}

// ---------------------------------------------------------------- commands

#[derive(Serialize)]
pub struct GroupView {
    pub name: String,
    pub nodes: Vec<String>,
    pub selected: String,
}

#[derive(Serialize)]
pub struct Overview {
    pub status: Status,
    pub mode: Mode,
    pub port: u16,
    pub system_proxy: bool,
    pub system_proxy_supported: bool,
    pub allow_lan: bool,
    pub tun: bool,
    pub tun_active: bool,
    pub is_admin: bool,
    pub nodes: Vec<NodeStatus>,
    pub groups: Vec<GroupView>,
    pub warnings: Vec<String>,
}

#[derive(Serialize)]
pub struct MeshView {
    pub configured: bool,
    pub enabled: bool,
    pub relay: bool,
    pub name: String,
    pub coordinator: Option<String>,
    pub network: Option<String>,
    pub tun_active: bool,
    pub running: bool,
    pub status: Option<supernet_mesh::device::MeshStatus>,
}

#[derive(Serialize)]
pub struct Exported {
    pub config: String,
    pub link: String,
}

#[derive(Serialize, Deserialize)]
pub struct Settings {
    pub port: u16,
    pub allow_lan: bool,
    pub auto_connect: bool,
    pub dns: Vec<String>,
    pub test_url: String,
    pub geoip: Option<String>,
}

impl Controller {
    pub async fn overview(&self) -> Res<Overview> {
        let p = self.engine.profile();
        let groups = p
            .groups
            .iter()
            .map(|g| GroupView {
                name: g.name.clone(),
                nodes: g.nodes.clone(),
                selected: p.selected.get(&g.name).cloned().unwrap_or_else(|| g.nodes[0].clone()),
            })
            .collect();
        Ok(Overview {
            status: self.engine.status().await,
            mode: p.mode,
            port: p.listen.port(),
            system_proxy: p.system_proxy,
            system_proxy_supported: supernet_sysproxy::supported(),
            allow_lan: p.allow_lan,
            tun: p.tun || self.force_tun,
            tun_active: self.tun.lock().await.is_some(),
            is_admin: supernet_tun::has_privilege(),
            nodes: self.engine.nodes(),
            groups,
            warnings: self.warnings.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        })
    }

    pub async fn connect_cmd(&self) -> Res<Status> {
        self.connect().await?;
        Ok(self.engine.status().await)
    }

    pub async fn disconnect(&self) -> Res<Status> {
        self.shutdown().await;
        Ok(self.engine.status().await)
    }

    pub async fn set_tun(&self, enabled: bool) -> Res<()> {
        if self.force_tun && !enabled {
            return Err("TUN 模式由启动参数（--tun / --mesh-only）固定开启".into());
        }
        let _g = self.edit.lock().await;
        let mut p = self.engine.profile();
        p.tun = enabled;
        self.commit(p).await?;
        self.sync_tun().await
    }

    pub async fn mesh_status(&self) -> Res<MeshView> {
        let p = self.engine.profile().mesh;
        let invite = p.as_ref().and_then(|m| supernet_mesh::proto::Invite::parse(&m.invite).ok());
        let tun_active = self.tun.lock().await.is_some();
        let run = self.mesh.lock().await;
        Ok(MeshView {
            configured: p.is_some(),
            enabled: p.as_ref().is_some_and(|m| m.enabled),
            relay: p.as_ref().is_none_or(|m| m.relay),
            name: p.as_ref().map_or_else(default_device_name, |m| m.name.clone()),
            coordinator: invite.as_ref().map(|i| i.coord.clone()),
            network: invite.map(|i| i.network),
            tun_active,
            running: run.is_some(),
            status: run.as_ref().map(|r| r.mesh.status()),
        })
    }

    /// Join (or switch to) a network from its invite link.
    pub async fn mesh_join(&self, link: String, name: String) -> Res<()> {
        let invite = supernet_mesh::proto::Invite::parse(&link).map_err(fail)?;
        {
            let _g = self.edit.lock().await;
            let mut p = self.engine.profile();
            // Same coordinator: keep the identity (and so the address).
            let key = match &p.mesh {
                Some(m) if supernet_mesh::proto::Invite::parse(&m.invite).is_ok_and(|old| old.coord_pub == invite.coord_pub) => {
                    m.private_key.clone()
                }
                _ => supernet_mesh::proto::b64(&supernet_mesh::proto::generate_secret()),
            };
            let name = if name.trim().is_empty() { default_device_name() } else { name.trim().to_string() };
            let relay = p.mesh.as_ref().is_none_or(|m| m.relay);
            p.mesh = Some(MeshProfile { invite: link.trim().to_string(), private_key: key, name, relay, enabled: true });
            self.commit(p).await?;
        }
        self.sync_mesh().await
    }

    pub async fn mesh_update(&self, enabled: bool, relay: bool, name: String) -> Res<()> {
        {
            let _g = self.edit.lock().await;
            let mut p = self.engine.profile();
            let Some(m) = p.mesh.as_mut() else { return Err("还没有加入组网".into()) };
            m.enabled = enabled;
            m.relay = relay;
            if !name.trim().is_empty() {
                m.name = name.trim().to_string();
            }
            self.commit(p).await?;
        }
        self.sync_mesh().await
    }

    /// Leave the network on this device (the coordinator keeps the entry until removed there).
    pub async fn mesh_leave(&self) -> Res<()> {
        {
            let _g = self.edit.lock().await;
            let mut p = self.engine.profile();
            p.mesh = None;
            self.commit(p).await?;
        }
        self.sync_mesh().await
    }

    pub async fn set_mode(&self, mode: Mode) -> Res<()> {
        let _g = self.edit.lock().await;
        self.engine.set_mode(mode);
        self.persist()
    }

    pub async fn set_system_proxy(&self, enabled: bool) -> Res<()> {
        if enabled && !supernet_sysproxy::supported() {
            return Err("这个平台暂不支持设置系统代理".into());
        }
        let _g = self.edit.lock().await;
        let mut p = self.engine.profile();
        p.system_proxy = enabled;
        self.commit(p).await.map(|_| ())
    }

    pub async fn select_node(&self, group: String, node: String) -> Res<()> {
        let _g = self.edit.lock().await;
        self.engine.select(&group, &node).map_err(fail)?;
        self.persist()
    }

    pub async fn import_node(&self, text: String, name: String) -> Res<String> {
        let _g = self.edit.lock().await;
        let mut p = self.engine.profile();
        let mut node = wgconf::import(&text, &name).map_err(fail)?;
        // "insecure" Hysteria2 links: pin the certificate seen now instead.
        let resolver = supernet_core::dns::DirectResolver::new(vec![supernet_core::dns::Upstream::System]);
        if let Some(pin) = supernet_core::outbound::pin_hysteria2_cert(&mut node, &resolver).await.map_err(fail)? {
            self.engine.log("info", format!("“{}”的证书已固定：SHA-256 {pin}", node.name));
        }
        if node.name.is_empty() {
            node.name = format!("节点 {}", p.nodes.len() + 1);
        }
        let base = node.name.clone();
        let mut n = 2;
        while p.policy_names().contains(&node.name) {
            node.name = format!("{base} {n}");
            n += 1;
        }
        let name = node.name.clone();
        p.nodes.push(node);
        match p.groups.iter_mut().find(|g| g.name == DEFAULT_GROUP) {
            Some(g) => {
                g.nodes.retain(|m| m != DIRECT);
                g.nodes.push(name.clone());
            }
            None => p.groups.insert(0, GroupConfig { name: DEFAULT_GROUP.into(), kind: GroupKind::Select, nodes: vec![name.clone()] }),
        }
        self.commit(p).await?;
        Ok(name)
    }

    pub async fn remove_node(&self, name: String) -> Res<()> {
        let _g = self.edit.lock().await;
        let mut p = self.engine.profile();
        // Rules naming the node directly make `commit` fail validation, which
        // keeps the node; the error names the rule to fix.
        p.nodes.retain(|n| n.name != name);
        for g in &mut p.groups {
            g.nodes.retain(|m| m != &name);
            if g.nodes.is_empty() {
                g.nodes.push(DIRECT.into());
            }
        }
        p.selected.retain(|_, v| v != &name);
        self.commit(p).await.map(|_| ())
    }

    pub async fn export_node(&self, name: String) -> Res<Exported> {
        let p = self.engine.profile();
        let node = p.node(&name).ok_or_else(|| format!("没有节点“{name}”"))?;
        let config = match &node.kind {
            NodeKind::Wireguard(wg) => wgconf::render(wg),
            NodeKind::Hysteria2(_) | NodeKind::Tuic(_) => wgconf::to_link(node),
        };
        Ok(Exported { config, link: wgconf::to_link(node) })
    }

    pub async fn probe_node(&self, name: String) -> Res<u64> {
        self.engine.probe(&name).await.map(|d| d.as_millis() as u64).map_err(fail)
    }

    pub async fn get_rules(&self) -> Res<String> {
        Ok(self.engine.profile().rules.join("\n"))
    }

    pub async fn save_rules(&self, text: String) -> Res<Vec<String>> {
        let _g = self.edit.lock().await;
        let mut p = self.engine.profile();
        p.rules = text.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect();
        self.commit(p).await
    }

    pub async fn explain(&self, target: String) -> Res<RouteInfo> {
        self.engine.explain(&target).await.map_err(fail)
    }

    pub fn connections(&self) -> Vec<ConnInfo> {
        self.engine.connections()
    }

    pub fn close_connection(&self, id: u64) -> bool {
        self.engine.close_connection(id)
    }

    pub fn logs(&self, after: u64) -> Vec<LogLine> {
        self.engine.logs(after)
    }

    pub async fn get_settings(&self) -> Res<Settings> {
        let p = self.engine.profile();
        Ok(Settings {
            port: p.listen.port(),
            allow_lan: p.allow_lan,
            auto_connect: p.auto_connect,
            dns: p.dns.direct.clone(),
            test_url: p.test_url.clone(),
            geoip: p.geoip.as_ref().map(|g| g.display().to_string()),
        })
    }

    pub async fn save_settings(&self, settings: Settings) -> Res<Vec<String>> {
        if settings.port == 0 {
            return Err("端口不能为 0".into());
        }
        for s in &settings.dns {
            supernet_core::dns::Upstream::parse(s).map_err(fail)?;
        }
        supernet_core::outbound::parse_http_url(&settings.test_url).map_err(fail)?;
        let _g = self.edit.lock().await;
        let mut p = self.engine.profile();
        p.listen.set_port(settings.port);
        p.allow_lan = settings.allow_lan;
        p.auto_connect = settings.auto_connect;
        p.dns.direct = settings.dns.into_iter().filter(|s| !s.trim().is_empty()).collect();
        p.test_url = settings.test_url;
        p.geoip = settings.geoip.filter(|g| !g.trim().is_empty()).map(PathBuf::from);
        self.commit(p).await
    }

    /// A UI command by name with its JSON arguments (the same names the app's
    /// frontend uses, see app/src/api.ts): the web console's API.
    pub async fn dispatch(&self, cmd: &str, args: &Value) -> Res<Value> {
        fn arg<T: DeserializeOwned>(args: &Value, key: &str) -> Res<T> {
            let v = args.get(key).cloned().unwrap_or(Value::Null);
            serde_json::from_value(v).map_err(|e| format!("参数 {key}：{e}"))
        }
        fn json<T: Serialize>(v: T) -> Res<Value> {
            serde_json::to_value(v).map_err(fail)
        }
        match cmd {
            "overview" => json(self.overview().await?),
            "connect" => json(self.connect_cmd().await?),
            "disconnect" => json(self.disconnect().await?),
            "set_tun" => json(self.set_tun(arg(args, "enabled")?).await?),
            "mesh_status" => json(self.mesh_status().await?),
            "mesh_join" => json(self.mesh_join(arg(args, "link")?, arg(args, "name")?).await?),
            "mesh_update" => json(self.mesh_update(arg(args, "enabled")?, arg(args, "relay")?, arg(args, "name")?).await?),
            "mesh_leave" => json(self.mesh_leave().await?),
            "set_mode" => json(self.set_mode(arg(args, "mode")?).await?),
            "set_system_proxy" => json(self.set_system_proxy(arg(args, "enabled")?).await?),
            "select_node" => json(self.select_node(arg(args, "group")?, arg(args, "node")?).await?),
            "import_node" => json(self.import_node(arg(args, "text")?, arg(args, "name")?).await?),
            "remove_node" => json(self.remove_node(arg(args, "name")?).await?),
            "export_node" => json(self.export_node(arg(args, "name")?).await?),
            "probe_node" => json(self.probe_node(arg(args, "name")?).await?),
            "get_rules" => json(self.get_rules().await?),
            "save_rules" => json(self.save_rules(arg(args, "text")?).await?),
            "explain" => json(self.explain(arg(args, "target")?).await?),
            "connections" => json(self.connections()),
            "close_connection" => json(self.close_connection(arg(args, "id")?)),
            "logs" => json(self.logs(arg(args, "after")?)),
            "get_settings" => json(self.get_settings().await?),
            "save_settings" => json(self.save_settings(arg(args, "settings")?).await?),
            "restart_as_admin" => Err("网页控制台不能重启程序：请在服务器上以 root 运行 supernet".into()),
            other => Err(format!("未知命令 {other}")),
        }
    }
}
