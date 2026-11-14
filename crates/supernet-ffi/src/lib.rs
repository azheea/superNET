//! C interface to the superNET core, for platforms whose VPN is driven from
//! native code: the iOS Network Extension (and usable from any C caller).
//!
//! The order matches Android: the virtual-network address must be part of the
//! VPN configuration, so the caller
//! 1. `supernet_prepare(profile, data_dir)` — starts the engine and joins the mesh (if configured);
//! 2. `supernet_mesh_address(h)` — "10.66.0.x/24" or "" — goes into NEPacketTunnelNetworkSettings;
//! 3. `supernet_attach_tun(h, fd)` once the tunnel is up — packets start flowing;
//! 4. `supernet_status_json(h)` any time, `supernet_stop(h)` at the end.
//!
//! Strings returned by this library are freed with `supernet_free_string`.
//! Errors are reported as negative return values or NULL; the last error of
//! a handle is available from `supernet_last_error`.

use std::ffi::{c_char, c_int, CStr, CString};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use supernet_core::{Engine, Profile};

pub struct Handle {
    rt: tokio::runtime::Runtime,
    engine: Engine,
    mesh: Option<(supernet_mesh::device::Mesh, Option<supernet_mesh::device::MeshPorts>, std::net::Ipv4Addr, u8)>,
    tun: Mutex<Option<supernet_tun::TunDevice>>,
    error: Mutex<Option<CString>>,
}

fn cstr(p: *const c_char) -> Result<String> {
    anyhow::ensure!(!p.is_null(), "空指针");
    // SAFETY: the caller passes a NUL-terminated string.
    Ok(unsafe { CStr::from_ptr(p) }.to_str().context("不是 UTF-8")?.to_string())
}

fn prepare(profile_path: &str, data_dir: &str) -> Result<Handle> {
    // Few threads: the iOS Network Extension has a tight memory limit.
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    let profile = Profile::load(std::path::Path::new(profile_path)).context("读取配置")?;
    let (engine, _warnings) = Engine::new(profile, Some(PathBuf::from(data_dir)))?;
    rt.block_on(engine.start())?;
    let mut mesh = None;
    if let Some(cfg) = engine.profile().mesh.filter(|m| m.enabled) {
        let joined = rt.block_on(async {
            use supernet_mesh::{device as m, proto};
            let invite = proto::Invite::parse(&cfg.invite)?;
            let key = proto::unb64(&cfg.private_key)?;
            let mut mc = m::MeshConfig::new(invite, key, cfg.name.clone());
            mc.relay = cfg.relay;
            let (mesh, ports) = m::Mesh::start(mc).await?;
            let ip = mesh.wait_joined(Duration::from_secs(15)).await?;
            let prefix = mesh.status().prefix;
            anyhow::Ok((mesh, Some(ports), ip, prefix))
        });
        match joined {
            Ok(m) => mesh = Some(m),
            Err(e) => engine.log("warn", format!("组网未接入：{e:#}")),
        }
    }
    Ok(Handle { rt, engine, mesh, tun: Mutex::new(None), error: Mutex::new(None) })
}

fn set_error(h: &Handle, e: anyhow::Error) {
    *h.error.lock().unwrap_or_else(|p| p.into_inner()) = CString::new(format!("{e:#}")).ok();
}

/// Start the engine and join the virtual network. Returns NULL on failure.
///
/// # Safety
/// `profile_path` and `data_dir` must be NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn supernet_prepare(profile_path: *const c_char, data_dir: *const c_char) -> *mut Handle {
    let r = (|| prepare(&cstr(profile_path)?, &cstr(data_dir)?))();
    match r {
        Ok(h) => Box::into_raw(Box::new(h)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// The virtual-network address as "a.b.c.d/prefix", or "" when not joined.
///
/// # Safety
/// `h` comes from `supernet_prepare`.
#[no_mangle]
pub unsafe extern "C" fn supernet_mesh_address(h: *const Handle) -> *mut c_char {
    let Some(h) = h.as_ref() else { return std::ptr::null_mut() };
    let s = h.mesh.as_ref().map(|(_, _, ip, p)| format!("{ip}/{p}")).unwrap_or_default();
    CString::new(s).map_or(std::ptr::null_mut(), CString::into_raw)
}

/// Hand over the tunnel's file descriptor; superNET owns it from now on.
/// Returns 0, or -1 (see `supernet_last_error`).
///
/// # Safety
/// `h` comes from `supernet_prepare`; `fd` is an open TUN/utun descriptor.
#[no_mangle]
pub unsafe extern "C" fn supernet_attach_tun(h: *mut Handle, fd: c_int) -> c_int {
    let Some(h) = h.as_mut() else { return -1 };
    #[cfg(not(unix))]
    let r: Result<()> = {
        let _ = fd;
        Err(anyhow::anyhow!("此平台不支持接管 TUN 描述符"))
    };
    #[cfg(unix)]
    let r = (|| -> Result<()> {
        let ports = h.rt.block_on(h.engine.start_tun(supernet_tun::MTU as usize))?;
        let mut dev = {
            let _guard = h.rt.enter();
            supernet_tun::start_fd(fd, ports)?
        };
        if let Some((_, ports, ip, prefix)) = h.mesh.as_mut() {
            if let Some(supernet_mesh::device::MeshPorts { to_mesh, from_mesh }) = ports.take() {
                let _guard = h.rt.enter();
                dev.attach_mesh(*ip, *prefix, to_mesh, from_mesh)?;
            }
        }
        *h.tun.lock().unwrap_or_else(|p| p.into_inner()) = Some(dev);
        Ok(())
    })();
    match r {
        Ok(()) => 0,
        Err(e) => {
            set_error(h, e);
            -1
        }
    }
}

#[derive(serde::Serialize)]
struct StatusJson {
    status: supernet_core::Status,
    mesh: Option<supernet_mesh::device::MeshStatus>,
    tun_active: bool,
}

/// Engine and mesh status as JSON (free with `supernet_free_string`).
///
/// # Safety
/// `h` comes from `supernet_prepare`.
#[no_mangle]
pub unsafe extern "C" fn supernet_status_json(h: *const Handle) -> *mut c_char {
    let Some(h) = h.as_ref() else { return std::ptr::null_mut() };
    let s = StatusJson {
        status: h.rt.block_on(h.engine.status()),
        mesh: h.mesh.as_ref().map(|(m, _, _, _)| m.status()),
        tun_active: h.tun.lock().map(|t| t.is_some()).unwrap_or(false),
    };
    serde_json::to_string(&s).ok().and_then(|j| CString::new(j).ok()).map_or(std::ptr::null_mut(), CString::into_raw)
}

/// The last error of `h` (free with `supernet_free_string`), or NULL.
///
/// # Safety
/// `h` comes from `supernet_prepare`.
#[no_mangle]
pub unsafe extern "C" fn supernet_last_error(h: *const Handle) -> *mut c_char {
    let Some(h) = h.as_ref() else { return std::ptr::null_mut() };
    h.error.lock().ok().and_then(|e| e.clone()).map_or(std::ptr::null_mut(), CString::into_raw)
}

/// Stop everything and free the handle.
///
/// # Safety
/// `h` comes from `supernet_prepare` and is not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn supernet_stop(h: *mut Handle) {
    if h.is_null() {
        return;
    }
    let h = Box::from_raw(h);
    let tun = h.tun.lock().unwrap_or_else(|p| p.into_inner()).take();
    drop(tun);
    h.rt.block_on(async {
        h.engine.stop_tun().await;
        h.engine.stop().await;
    });
    drop(h);
}

/// # Safety
/// `s` comes from this library (or is NULL).
#[no_mangle]
pub unsafe extern "C" fn supernet_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_status_and_stop_without_tun() {
        let dir = std::env::temp_dir().join(format!("supernet-ffi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let profile = dir.join("profile.yaml");
        std::fs::write(&profile, "listen: 127.0.0.1:0\nrules:\n- MATCH,DIRECT\n").unwrap();
        let p = CString::new(profile.to_str().unwrap()).unwrap();
        let d = CString::new(dir.to_str().unwrap()).unwrap();
        unsafe {
            let h = supernet_prepare(p.as_ptr(), d.as_ptr());
            assert!(!h.is_null());
            let addr = supernet_mesh_address(h);
            assert_eq!(CStr::from_ptr(addr).to_str().unwrap(), "");
            supernet_free_string(addr);
            let s = supernet_status_json(h);
            let json: serde_json::Value = serde_json::from_str(CStr::from_ptr(s).to_str().unwrap()).unwrap();
            assert_eq!(json["status"]["running"], true);
            assert_eq!(json["tun_active"], false);
            supernet_free_string(s);
            supernet_stop(h);
        }
        let bad = CString::new("/nonexistent/profile.yaml").unwrap();
        assert!(unsafe { supernet_prepare(bad.as_ptr(), d.as_ptr()) }.is_null());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
