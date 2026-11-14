//! macOS (networksetup) and Linux desktop (GNOME gsettings) system proxy.
//!
//! The settings are mapped onto the Windows-shaped [`ProxySettings`]: the
//! PROXY flag means "HTTP and HTTPS proxy on", `server` is `host:port` and
//! `bypass` the exception list (`;`-separated, as on Windows).

use std::process::Command;

use anyhow::{bail, Context, Result};

use super::ProxySettings;

pub const DIRECT_FLAG: u32 = 1;
pub const PROXY_FLAG: u32 = 2;

fn output(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd).args(args).output().with_context(|| format!("运行 {cmd}"))?;
    if !out.status.success() {
        bail!("{cmd} {}：{}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Windows bypass syntax to a list of hosts (`<local>` and wildcards trimmed to what the OS accepts).
fn bypass_list(bypass: Option<&str>) -> Vec<String> {
    bypass
        .unwrap_or_default()
        .split(';')
        .map(str::trim)
        .filter(|h| !h.is_empty() && *h != "<local>")
        .map(|h| h.trim_end_matches(".*").to_string() + if h.ends_with(".*") { ".0.0/8" } else { "" })
        .map(|h| h.replace("127.0.0/8", "127.0.0.0/8"))
        .collect()
}

#[cfg(target_os = "macos")]
mod os {
    use super::*;

    /// Enabled network services ("Wi-Fi", "Ethernet"…); disabled ones start with `*`.
    fn services() -> Result<Vec<String>> {
        let text = output("networksetup", &["-listallnetworkservices"])?;
        Ok(text.lines().skip(1).filter(|l| !l.trim().is_empty() && !l.starts_with('*')).map(str::to_string).collect())
    }

    fn field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
        text.lines().find_map(|l| l.strip_prefix(name).map(|v| v.trim_start_matches(':').trim()))
    }

    pub fn supported() -> bool {
        services().is_ok_and(|s| !s.is_empty())
    }

    /// The first enabled service stands for the system.
    pub fn current() -> Result<ProxySettings> {
        let svc = services()?.into_iter().next().context("没有可用的网络服务")?;
        let web = output("networksetup", &["-getwebproxy", &svc])?;
        let on = field(&web, "Enabled") == Some("Yes");
        let server = match (field(&web, "Server"), field(&web, "Port")) {
            (Some(h), Some(p)) if !h.is_empty() => Some(format!("{h}:{p}")),
            _ => None,
        };
        let bypass = output("networksetup", &["-getproxybypassdomains", &svc]).ok().map(|t| {
            t.lines().filter(|l| !l.contains("There aren't any")).map(str::trim).collect::<Vec<_>>().join(";")
        });
        Ok(ProxySettings { flags: if on { DIRECT_FLAG | PROXY_FLAG } else { DIRECT_FLAG }, server, bypass, autoconfig_url: None })
    }

    pub fn apply(s: &ProxySettings) -> Result<()> {
        let on = s.flags & PROXY_FLAG != 0;
        for svc in services()? {
            if on {
                let server = s.server.as_deref().context("缺少代理地址")?;
                let (host, port) = server.rsplit_once(':').context("代理地址格式应为 主机:端口")?;
                output("networksetup", &["-setwebproxy", &svc, host, port])?;
                output("networksetup", &["-setsecurewebproxy", &svc, host, port])?;
                let mut args = vec!["-setproxybypassdomains".to_string(), svc.clone()];
                let hosts = bypass_list(s.bypass.as_deref());
                args.extend(if hosts.is_empty() { vec!["Empty".to_string()] } else { hosts });
                let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                output("networksetup", &refs)?;
            } else {
                output("networksetup", &["-setwebproxystate", &svc, "off"])?;
                output("networksetup", &["-setsecurewebproxystate", &svc, "off"])?;
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
mod os {
    use super::*;

    fn get(schema: &str, key: &str) -> Result<String> {
        Ok(output("gsettings", &["get", schema, key])?.trim().trim_matches('\'').to_string())
    }

    fn set(schema: &str, key: &str, value: &str) -> Result<()> {
        output("gsettings", &["set", schema, key, value]).map(|_| ())
    }

    /// GNOME (and desktops reading its settings); elsewhere the user sets the proxy by hand.
    pub fn supported() -> bool {
        get("org.gnome.system.proxy", "mode").is_ok()
    }

    pub fn current() -> Result<ProxySettings> {
        let mode = get("org.gnome.system.proxy", "mode").context("没有 GNOME 代理设置（gsettings），请在应用里手动填写代理地址")?;
        let host = get("org.gnome.system.proxy.http", "host")?;
        let port = get("org.gnome.system.proxy.http", "port")?;
        let ignore = get("org.gnome.system.proxy", "ignore-hosts")?;
        let bypass = ignore.trim_matches(['[', ']']).split(',').map(|h| h.trim().trim_matches('\'')).filter(|h| !h.is_empty()).collect::<Vec<_>>().join(";");
        Ok(ProxySettings {
            flags: if mode == "manual" { DIRECT_FLAG | PROXY_FLAG } else { DIRECT_FLAG },
            server: (!host.is_empty()).then(|| format!("{host}:{port}")),
            bypass: Some(bypass),
            autoconfig_url: None,
        })
    }

    pub fn apply(s: &ProxySettings) -> Result<()> {
        if s.flags & PROXY_FLAG == 0 {
            return set("org.gnome.system.proxy", "mode", "none");
        }
        let server = s.server.as_deref().context("缺少代理地址")?;
        let (host, port) = server.rsplit_once(':').context("代理地址格式应为 主机:端口")?;
        for schema in ["org.gnome.system.proxy.http", "org.gnome.system.proxy.https"] {
            set(schema, "host", host)?;
            set(schema, "port", port)?;
        }
        let hosts: Vec<String> = bypass_list(s.bypass.as_deref()).into_iter().map(|h| format!("'{h}'")).collect();
        set("org.gnome.system.proxy", "ignore-hosts", &format!("[{}]", hosts.join(", ")))?;
        set("org.gnome.system.proxy", "mode", "manual")
    }
}

pub use os::{apply, current, supported};
