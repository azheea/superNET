//! Routes and DNS for the TUN device on Linux and macOS.
//!
//! Everything here is runtime-only and undone on drop: routes are deleted,
//! DNS settings reverted. If superNET dies, the kernel removes the device and
//! with it the routes; the DNS setting is the only thing that can linger:
//! - Linux: resolvectl's per-link setting goes away with the link.
//! - macOS: the scutil dynamic-store key is not persisted, so a reboot clears
//!   it. `supernet` also clears a stale one when it starts.

use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{bail, Context, Result};

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(cmd).args(args).output().with_context(|| format!("运行 {cmd}"))?;
    if !out.status.success() {
        bail!("{cmd} {}：{}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// What was changed, so it can be undone.
pub struct Takeover {
    name: String,
    routes: Vec<String>,
    dns: bool,
    /// Linux: (physical interface, its previous rp_filter value) to restore.
    rp_filter: Option<(String, String)>,
    /// macOS: the interface-scoped default route added for pinned sockets
    /// (interface, gateway), deleted again on drop.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    scoped_default: Option<(String, String)>,
}

/// macOS: superNET pins its own sockets to the physical interface with
/// IP_BOUND_IF. Such a socket is routed with an interface-scoped lookup, and
/// the primary interface normally has only an unscoped default route; once
/// the TUN's 0/1 and 128/1 routes exist, that lookup ends on a route of the
/// wrong interface and every send fails with "Network is unreachable" (seen on
/// a real Mac: DNS, Hysteria2 and the virtual network all failed). A default
/// route scoped to the physical interface gives those lookups a way out.
#[cfg(target_os = "macos")]
fn add_scoped_default() -> Option<(String, String)> {
    let index = supernet_netstack::sysnet::bypass_interface()?;
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: IF_NAMESIZE buffer, as if_indextoname requires.
    if unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) }.is_null() {
        return None;
    }
    let iface: String = buf.iter().take_while(|&&c| c != 0).map(|&c| c as u8 as char).collect();
    let out = Command::new("route").args(["-n", "get", "default"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let field = |key: &str| text.lines().find_map(|l| l.trim().strip_prefix(key).map(|v| v.trim().to_string()));
    let gateway = match (field("gateway:"), field("interface:")) {
        (Some(gw), Some(i)) if i == iface => gw,
        _ => {
            tracing::warn!("{iface} 上没有默认网关：superNET 自己的连接可能不通");
            return None;
        }
    };
    match run("route", &["-n", "add", "-ifscope", &iface, "default", &gateway]) {
        Ok(()) => Some((iface, gateway)),
        // Already there (the system adds one when several interfaces are up): keep it, do not delete it later.
        Err(e) if format!("{e:#}").contains("exists") => None,
        Err(e) => {
            tracing::warn!("添加 {iface} 的接口默认路由失败：{e:#}");
            None
        }
    }
}

/// Linux strict reverse-path filtering (rp_filter = 1, the RHEL default) drops
/// the replies to superNET's own pinned sockets: they arrive on the physical
/// interface, but the route back to their source now points into the TUN.
/// The effective value is max(all, interface), so loose (2) on the physical
/// interface is enough; it is put back on exit.
#[cfg(target_os = "linux")]
fn loosen_rp_filter() -> Option<(String, String)> {
    let index = supernet_netstack::sysnet::bypass_interface()?;
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: IF_NAMESIZE buffer, as if_indextoname requires.
    if unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) }.is_null() {
        return None;
    }
    let name: String = buf.iter().take_while(|&&c| c != 0).map(|&c| c as u8 as char).collect();
    let path = format!("/proc/sys/net/ipv4/conf/{name}/rp_filter");
    let all = std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter").unwrap_or_default();
    let before = std::fs::read_to_string(&path).ok()?.trim().to_string();
    if all.trim() != "1" && before != "1" {
        return None; // already loose or off
    }
    match std::fs::write(&path, "2") {
        Ok(()) => Some((name, before)),
        Err(e) => {
            tracing::warn!("无法放宽 {name} 的 rp_filter：{e}；superNET 自己的连接可能收不到回包");
            None
        }
    }
}

#[cfg(target_os = "macos")]
const DNS_KEY: &str = "State:/Network/Service/superNET/DNS";

#[cfg(target_os = "macos")]
fn scutil(script: &str) -> Result<()> {
    use std::io::Write;
    let mut child = Command::new("scutil").stdin(std::process::Stdio::piped()).spawn().context("运行 scutil")?;
    child.stdin.take().context("scutil stdin")?.write_all(script.as_bytes())?;
    if !child.wait()?.success() {
        bail!("scutil 失败");
    }
    Ok(())
}

/// Route everything through the device (two /1 routes, more specific than any
/// default route) and point the system resolver at superNET's DNS.
pub fn take_over(name: &str, dns: Ipv4Addr) -> Result<Takeover> {
    let mut t = Takeover { name: name.to_string(), routes: Vec::new(), dns: false, rp_filter: None, scoped_default: None };
    #[cfg(target_os = "linux")]
    {
        t.rp_filter = loosen_rp_filter();
    }
    #[cfg(target_os = "macos")]
    {
        t.scoped_default = add_scoped_default();
    }
    for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
        #[cfg(target_os = "linux")]
        run("ip", &["route", "add", prefix, "dev", name]).with_context(|| format!("添加路由 {prefix}"))?;
        #[cfg(target_os = "macos")]
        run("route", &["-n", "add", "-net", prefix, "-interface", name]).with_context(|| format!("添加路由 {prefix}"))?;
        t.routes.push(prefix.to_string());
    }
    #[cfg(target_os = "linux")]
    {
        // systemd-resolved: this link answers every domain ("~.") and is the default route for DNS.
        let dns_s = dns.to_string();
        let ok = run("resolvectl", &["dns", name, &dns_s]).is_ok()
            && run("resolvectl", &["domain", name, "~."]).is_ok()
            && run("resolvectl", &["default-route", name, "yes"]).is_ok();
        if ok {
            t.dns = true;
        } else {
            tracing::warn!("没有 systemd-resolved（resolvectl）：DNS 不会自动指向 superNET，域名规则只对发往 TUN 的 DNS 查询生效");
        }
    }
    #[cfg(target_os = "macos")]
    {
        let script = format!("d.init\nd.add ServerAddresses * {dns}\nd.add SupplementalMatchDomains * \"\"\nset {DNS_KEY}\nquit\n");
        match scutil(&script) {
            Ok(()) => t.dns = true,
            Err(e) => tracing::warn!("设置 DNS 失败：{e:#}"),
        }
    }
    Ok(t)
}

/// Give the device its virtual-network address.
pub fn add_address(name: &str, ip: Ipv4Addr, prefix: u8) -> Result<()> {
    #[cfg(target_os = "linux")]
    run("ip", &["addr", "add", &format!("{ip}/{prefix}"), "dev", name])?;
    #[cfg(target_os = "macos")]
    {
        // utun is point-to-point: the address is its own peer, the subnet a route.
        let ip_s = ip.to_string();
        run("ifconfig", &[name, "inet", &format!("{ip}/{prefix}"), &ip_s, "alias"])?;
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
        let net = Ipv4Addr::from(u32::from(ip) & mask);
        // -ifa: packets to the network take the mesh address as their source.
        // Without it macOS uses the device's first address (172.19.0.1), which
        // the other members (and the server's WireGuard) do not accept.
        let dest = format!("{net}/{prefix}");
        if run("route", &["-n", "add", "-net", &dest, "-interface", name, "-ifa", &ip_s]).is_err() {
            run("route", &["-n", "add", "-net", &dest, "-interface", name])?;
        }
    }
    Ok(())
}

/// Remove a DNS setting left behind by a superNET that did not exit cleanly.
pub fn clear_stale_dns() {
    #[cfg(target_os = "macos")]
    let _ = scutil(&format!("remove {DNS_KEY}\nquit\n"));
}

impl Drop for Takeover {
    fn drop(&mut self) {
        for prefix in &self.routes {
            #[cfg(target_os = "linux")]
            let _ = run("ip", &["route", "del", prefix, "dev", &self.name]);
            #[cfg(target_os = "macos")]
            let _ = run("route", &["-n", "delete", "-net", prefix, "-interface", &self.name]);
        }
        #[cfg(target_os = "macos")]
        if let Some((iface, gateway)) = &self.scoped_default {
            let _ = run("route", &["-n", "delete", "-ifscope", iface, "default", gateway]);
        }
        if let Some((iface, before)) = &self.rp_filter {
            let _ = std::fs::write(format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter"), before);
        }
        if self.dns {
            #[cfg(target_os = "linux")]
            let _ = run("resolvectl", &["revert", &self.name]);
            #[cfg(target_os = "macos")]
            clear_stale_dns();
        }
    }
}
