//! DNS leak protection with the Windows Filtering Platform.
//!
//! While TUN mode runs, DNS (remote port 53, UDP and TCP) is blocked on every
//! path except:
//! - the TUN adapter, where superNET answers it;
//! - superNET's own process, whose upstream queries leave through the physical adapter;
//! - loopback.
//!
//! Without this, Windows also asks the DNS servers of the other adapters,
//! and waits for them. A VPN adapter whose server is unreachable stalled
//! every lookup for 12 seconds in testing. The blocked servers also see
//! the user's queries (a leak), and their real answers bypass domain rules.
//!
//! The filters live in a dynamic WFP session: Windows deletes them when
//! the session handle closes, which also happens when the process exits
//! or crashes. Nothing persists.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};

use anyhow::{bail, Result};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

/// RPC_C_AUTHN_WINNT
const AUTHN_WINNT: u32 = 10;

pub struct DnsGuard {
    engine: HANDLE,
}

// SAFETY: the engine handle is only used to close the session, from any thread.
unsafe impl Send for DnsGuard {}
unsafe impl Sync for DnsGuard {}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        // SAFETY: handle from FwpmEngineOpen0, closed once; dynamic filters go with it.
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

fn check(what: &str, rc: u32) -> Result<()> {
    if rc != 0 {
        bail!("{what} 失败（0x{rc:08x}）");
    }
    Ok(())
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn random_guid() -> GUID {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let mixed = nanos ^ ((std::process::id() as u128) << 64) ^ 0x5355_5045_524e_4554_0000_0000_0000_0000;
    GUID::from_u128(mixed)
}

/// Install the filters for the TUN adapter `tun_index`.
pub fn block_dns_leaks(tun_index: u32) -> Result<DnsGuard> {
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: out pointer to a local.
    check("ConvertInterfaceIndexToLuid", unsafe { ConvertInterfaceIndexToLuid(tun_index, &mut luid) })?;
    // SAFETY: Value is the whole union.
    let mut luid = unsafe { luid.Value };

    let mut name = wide("superNET");
    let mut session = FWPM_SESSION0::default();
    session.displayData.name = name.as_mut_ptr();
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    let mut engine: HANDLE = null_mut();
    // SAFETY: valid session struct and out handle.
    check("FwpmEngineOpen0", unsafe { FwpmEngineOpen0(null(), AUTHN_WINNT, null(), &session, &mut engine) })?;
    let guard = DnsGuard { engine };

    // SAFETY: open engine handle.
    check("FwpmTransactionBegin0", unsafe { FwpmTransactionBegin0(engine, 0) })?;
    let result = add_filters(engine, &mut name, &mut luid);
    // SAFETY: a transaction is open on this handle.
    match result {
        Ok(()) => check("FwpmTransactionCommit0", unsafe { FwpmTransactionCommit0(engine) })?,
        Err(e) => {
            unsafe { FwpmTransactionAbort0(engine) };
            return Err(e);
        }
    }
    Ok(guard)
}

fn add_filters(engine: HANDLE, name: &mut [u16], tun_luid: &mut u64) -> Result<()> {
    let sublayer_key = random_guid();
    let mut sublayer = FWPM_SUBLAYER0::default();
    sublayer.subLayerKey = sublayer_key;
    sublayer.displayData.name = name.as_mut_ptr();
    sublayer.weight = u16::MAX;
    // SAFETY: valid struct, default security descriptor.
    check("FwpmSubLayerAdd0", unsafe { FwpmSubLayerAdd0(engine, &sublayer, null_mut()) })?;

    // The app ID of this executable (for its own upstream DNS queries).
    let exe = std::env::current_exe()?;
    let exe_w = wide(&exe.display().to_string());
    let mut app_id: *mut FWP_BYTE_BLOB = null_mut();
    // SAFETY: NUL-terminated path, out pointer freed below.
    check("FwpmGetAppIdFromFileName0", unsafe { FwpmGetAppIdFromFileName0(exe_w.as_ptr(), &mut app_id) })?;

    let port53 = condition(FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, FWP_UINT16, |v| v.uint16 = 53);
    let on_tun = condition(FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_MATCH_EQUAL, FWP_UINT64, |v| v.uint64 = tun_luid);
    let ours = condition(FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL, FWP_BYTE_BLOB_TYPE, |v| v.byteBlob = app_id);
    let loopback =
        condition(FWPM_CONDITION_FLAGS, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT32, |v| v.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK);

    let mut result = Ok(());
    for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
        let rules: [(&[FWPM_FILTER_CONDITION0], u32, u8); 4] = [
            (&[port53, on_tun], FWP_ACTION_PERMIT, 15),
            (&[port53, ours], FWP_ACTION_PERMIT, 15),
            (&[port53, loopback], FWP_ACTION_PERMIT, 15),
            (&[port53], FWP_ACTION_BLOCK, 14),
        ];
        for (conditions, action, weight) in rules {
            if let Err(e) = add_filter(engine, name, layer, sublayer_key, conditions, action, weight) {
                result = Err(e);
                break;
            }
        }
        if result.is_err() {
            break;
        }
    }
    // SAFETY: allocated by FwpmGetAppIdFromFileName0; the filters keep their own copy.
    unsafe { FwpmFreeMemory0(&mut app_id as *mut *mut FWP_BYTE_BLOB as *mut *mut c_void) };
    result
}

fn condition(
    field: GUID,
    match_type: FWP_MATCH_TYPE,
    data_type: FWP_DATA_TYPE,
    set: impl FnOnce(&mut FWP_CONDITION_VALUE0_0),
) -> FWPM_FILTER_CONDITION0 {
    let mut c = FWPM_FILTER_CONDITION0::default();
    c.fieldKey = field;
    c.matchType = match_type;
    c.conditionValue.r#type = data_type;
    set(&mut c.conditionValue.Anonymous);
    c
}

fn add_filter(
    engine: HANDLE,
    name: &mut [u16],
    layer: GUID,
    sublayer: GUID,
    conditions: &[FWPM_FILTER_CONDITION0],
    action: FWP_ACTION_TYPE,
    weight: u8,
) -> Result<()> {
    let mut conditions = conditions.to_vec();
    let mut filter = FWPM_FILTER0::default();
    filter.displayData.name = name.as_mut_ptr();
    filter.layerKey = layer;
    filter.subLayerKey = sublayer;
    filter.weight.r#type = FWP_UINT8;
    filter.weight.Anonymous.uint8 = weight;
    filter.numFilterConditions = conditions.len() as u32;
    filter.filterCondition = conditions.as_mut_ptr();
    filter.action.r#type = action;
    let mut id = 0u64;
    // SAFETY: the filter and everything it points to outlive the call.
    check("FwpmFilterAdd0", unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), &mut id) })
}
