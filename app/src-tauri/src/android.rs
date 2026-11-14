//! Android: the system VPN (VpnService) provides the TUN device.
//!
//! The Kotlin side (`VpnPlugin`, `SupernetVpnService` in gen/android) asks
//! for permission, builds the interface and returns its file descriptor; the
//! Rust core owns the descriptor from then on.

use std::sync::OnceLock;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tauri::plugin::{Builder, PluginHandle, TauriPlugin};
use tauri::Wry;

static HANDLE: OnceLock<PluginHandle<Wry>> = OnceLock::new();

pub fn init() -> TauriPlugin<Wry> {
    Builder::new("supernet-vpn")
        .setup(|_app, api| {
            let handle = api.register_android_plugin("app.supernet.client", "VpnPlugin")?;
            let _ = HANDLE.set(handle);
            Ok(())
        })
        .build()
}

fn handle() -> Result<&'static PluginHandle<Wry>> {
    HANDLE.get().ok_or_else(|| anyhow::anyhow!("VPN 插件没有加载"))
}

#[derive(Deserialize)]
struct Granted {
    granted: bool,
}

#[derive(Deserialize)]
struct Fd {
    fd: i32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EstablishArgs {
    mtu: u16,
    mesh_ip: Option<String>,
    mesh_prefix: u8,
}

/// Ask for VPN permission (a system dialog the first time).
pub async fn prepare() -> Result<()> {
    let r: Granted = handle()?.run_mobile_plugin_async("prepare", ()).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    if !r.granted {
        bail!("没有获得 VPN 授权");
    }
    Ok(())
}

/// Bring the VPN up; returns the TUN descriptor (now ours to close).
pub async fn establish(mtu: u16, mesh: Option<(std::net::Ipv4Addr, u8)>) -> Result<i32> {
    let args = EstablishArgs { mtu, mesh_ip: mesh.map(|(ip, _)| ip.to_string()), mesh_prefix: mesh.map_or(24, |(_, p)| p) };
    let r: Fd = handle()?.run_mobile_plugin_async("establish", args).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(r.fd)
}

pub async fn stop() {
    if let Ok(h) = handle() {
        let _ = h.run_mobile_plugin_async::<serde_json::Value>("stop", ()).await;
    }
}

/// Android's VpnService as the controller's system VPN.
pub struct AndroidVpn;

impl supernet_control::Vpn for AndroidVpn {
    fn prepare(&self) -> supernet_control::BoxFut<'_, Result<()>> {
        Box::pin(prepare())
    }
    fn establish(&self, mtu: u16, mesh: Option<(std::net::Ipv4Addr, u8)>) -> supernet_control::BoxFut<'_, Result<i32>> {
        Box::pin(establish(mtu, mesh))
    }
    fn stop(&self) -> supernet_control::BoxFut<'_, ()> {
        Box::pin(stop())
    }
}
