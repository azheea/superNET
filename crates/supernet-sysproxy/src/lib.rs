//! Point the operating system's proxy settings at superNET and put them back.
//!
//! Before changing anything the previous settings are written to a backup
//! file. If superNET crashes, the next start calls [`recover`] and restores
//! them, so the machine is never left pointing at a proxy that is not running.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Addresses that should never go through the proxy.
pub const DEFAULT_BYPASS: &str =
    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";

/// The OS proxy configuration as far as superNET touches it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxySettings {
    /// Windows `PROXY_TYPE_*` flags.
    pub flags: u32,
    pub server: Option<String>,
    pub bypass: Option<String>,
    pub autoconfig_url: Option<String>,
}

/// Whether the OS proxy currently points at `server` (e.g. `127.0.0.1:7890`).
pub fn is_pointing_at(server: &str) -> Result<bool> {
    let cur = platform::current()?;
    Ok(cur.flags & platform::PROXY_FLAG != 0 && cur.server.as_deref() == Some(server))
}

/// Use `server` as the system proxy. Keeps the original settings in `backup`
/// (an existing backup is kept: it holds the settings from before superNET).
pub fn enable(server: &str, backup: &Path) -> Result<()> {
    if !backup.exists() {
        let previous = platform::current()?;
        if let Some(dir) = backup.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(backup, serde_json::to_vec_pretty(&previous)?).context("保存原系统代理设置")?;
    }
    platform::apply(&ProxySettings {
        flags: platform::DIRECT_FLAG | platform::PROXY_FLAG,
        server: Some(server.to_string()),
        bypass: Some(DEFAULT_BYPASS.to_string()),
        autoconfig_url: None,
    })
}

/// Restore the settings saved by [`enable`]. Does nothing without a backup.
/// If someone else changed the proxy meanwhile, their setting is left alone.
pub fn disable(server: &str, backup: &Path) -> Result<()> {
    let Ok(text) = std::fs::read(backup) else { return Ok(()) };
    let previous: ProxySettings = serde_json::from_slice(&text).context("原系统代理设置备份已损坏")?;
    if is_pointing_at(server)? {
        platform::apply(&previous)?;
    }
    std::fs::remove_file(backup).context("删除系统代理备份")?;
    Ok(())
}

/// Call on startup: undo a system proxy left behind by a crash.
pub fn recover(server: &str, backup: &Path) -> Result<bool> {
    if !backup.exists() {
        return Ok(false);
    }
    disable(server, backup)?;
    Ok(true)
}

pub fn current() -> Result<ProxySettings> {
    platform::current()
}

pub fn supported() -> bool {
    platform::supported()
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    use anyhow::{bail, Result};
    use windows_sys::Win32::Foundation::{GetLastError, GlobalFree};
    use windows_sys::Win32::Networking::WinInet::*;

    use super::ProxySettings;

    pub fn supported() -> bool {
        true
    }
    pub const DIRECT_FLAG: u32 = PROXY_TYPE_DIRECT;
    pub const PROXY_FLAG: u32 = PROXY_TYPE_PROXY;

    fn option(kind: u32) -> INTERNET_PER_CONN_OPTIONW {
        INTERNET_PER_CONN_OPTIONW { dwOption: kind, Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: 0 } }
    }

    unsafe fn take_string(ptr: windows_sys::core::PWSTR) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
        GlobalFree(ptr as *mut c_void);
        (!s.is_empty()).then_some(s)
    }

    fn query(flags_option: u32) -> Option<ProxySettings> {
        let mut options = [
            option(flags_option),
            option(INTERNET_PER_CONN_PROXY_SERVER),
            option(INTERNET_PER_CONN_PROXY_BYPASS),
            option(INTERNET_PER_CONN_AUTOCONFIG_URL),
        ];
        let mut list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: null_mut(),
            dwOptionCount: options.len() as u32,
            dwOptionError: 0,
            pOptions: options.as_mut_ptr(),
        };
        let mut len = list.dwSize;
        // SAFETY: `list` points at `options`, both live for the call; WinINet
        // allocates the returned strings, which `take_string` frees.
        unsafe {
            if InternetQueryOptionW(null(), INTERNET_OPTION_PER_CONNECTION_OPTION, &mut list as *mut _ as *mut c_void, &mut len) == 0 {
                return None;
            }
            Some(ProxySettings {
                flags: options[0].Value.dwValue,
                server: take_string(options[1].Value.pszValue),
                bypass: take_string(options[2].Value.pszValue),
                autoconfig_url: take_string(options[3].Value.pszValue),
            })
        }
    }

    pub fn current() -> Result<ProxySettings> {
        // FLAGS_UI reflects the settings dialog more accurately; older systems
        // only know FLAGS.
        match query(INTERNET_PER_CONN_FLAGS_UI).or_else(|| query(INTERNET_PER_CONN_FLAGS)) {
            Some(s) => Ok(s),
            None => bail!("读取系统代理设置失败（错误码 {}）", unsafe { GetLastError() }),
        }
    }

    pub fn apply(settings: &ProxySettings) -> Result<()> {
        let wide = |s: &Option<String>| s.as_ref().map(|v| v.encode_utf16().chain(Some(0)).collect::<Vec<u16>>());
        let mut server = wide(&settings.server);
        let mut bypass = wide(&settings.bypass);
        let mut pac = wide(&settings.autoconfig_url);
        let ptr = |v: &mut Option<Vec<u16>>| v.as_mut().map_or(null_mut(), |b| b.as_mut_ptr());
        let mut options = [
            INTERNET_PER_CONN_OPTIONW { dwOption: INTERNET_PER_CONN_FLAGS, Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: settings.flags } },
            INTERNET_PER_CONN_OPTIONW { dwOption: INTERNET_PER_CONN_PROXY_SERVER, Value: INTERNET_PER_CONN_OPTIONW_0 { pszValue: ptr(&mut server) } },
            INTERNET_PER_CONN_OPTIONW { dwOption: INTERNET_PER_CONN_PROXY_BYPASS, Value: INTERNET_PER_CONN_OPTIONW_0 { pszValue: ptr(&mut bypass) } },
            INTERNET_PER_CONN_OPTIONW { dwOption: INTERNET_PER_CONN_AUTOCONFIG_URL, Value: INTERNET_PER_CONN_OPTIONW_0 { pszValue: ptr(&mut pac) } },
        ];
        let list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: null_mut(),
            dwOptionCount: options.len() as u32,
            dwOptionError: 0,
            pOptions: options.as_mut_ptr(),
        };
        // SAFETY: every pointer refers to a buffer that outlives the calls.
        unsafe {
            if InternetSetOptionW(null(), INTERNET_OPTION_PER_CONNECTION_OPTION, &list as *const _ as *const c_void, list.dwSize) == 0 {
                bail!("设置系统代理失败（错误码 {}）", GetLastError());
            }
            // Tell running applications to pick up the change.
            InternetSetOptionW(null(), INTERNET_OPTION_SETTINGS_CHANGED, null(), 0);
            InternetSetOptionW(null(), INTERNET_OPTION_REFRESH, null(), 0);
        }
        Ok(())
    }
}

#[cfg(any(target_os = "macos", all(unix, not(target_os = "android"))))]
#[path = "unix.rs"]
mod platform;

#[cfg(not(any(windows, target_os = "macos", all(unix, not(target_os = "android")))))]
mod platform {
    use anyhow::{bail, Result};

    use super::ProxySettings;

    pub const DIRECT_FLAG: u32 = 1;
    pub const PROXY_FLAG: u32 = 2;

    pub fn supported() -> bool {
        false
    }

    pub fn current() -> Result<ProxySettings> {
        bail!("这个平台没有系统代理设置（Android 用 VPN 模式）")
    }

    pub fn apply(_settings: &ProxySettings) -> Result<()> {
        current().map(|_| ())
    }
}

#[cfg(all(test, windows))]
mod tests {
    // Read-only: tests must not change the machine's proxy settings.
    #[test]
    fn reads_current_settings() {
        let s = super::current().unwrap();
        // Windows always reports at least PROXY_TYPE_DIRECT.
        assert_ne!(s.flags, 0, "{s:?}");
    }

    #[test]
    fn disable_without_backup_is_a_no_op() {
        let missing = std::env::temp_dir().join("supernet-no-such-backup.json");
        let _ = std::fs::remove_file(&missing);
        super::disable("127.0.0.1:1", &missing).unwrap();
        assert!(!super::recover("127.0.0.1:1", &missing).unwrap());
    }
}
