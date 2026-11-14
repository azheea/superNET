//! Keeping superNET's own traffic out of its TUN device.
//!
//! While TUN mode captures the default route, every socket superNET opens
//! itself (direct connections, WireGuard and QUIC transports, DNS) is pinned
//! to the physical interface, otherwise it would loop back into the TUN.

use std::io;
use std::net::SocketAddr;
use std::sync::RwLock;

/// Interface index to pin outgoing sockets to; `None` outside TUN mode.
static BYPASS: RwLock<Option<u32>> = RwLock::new(None);

pub fn set_bypass_interface(index: Option<u32>) {
    *BYPASS.write().unwrap_or_else(|e| e.into_inner()) = index;
}

pub fn bypass_interface() -> Option<u32> {
    *BYPASS.read().unwrap_or_else(|e| e.into_inner())
}

/// Open a TCP connection that leaves through the bypass interface.
pub async fn tcp_connect(addr: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    let socket = if addr.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
    if let Some(index) = bypass_interface() {
        pin(&socket, index, addr.is_ipv6())?;
    }
    let stream = socket.connect(addr).await?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Bind a UDP socket that sends through the bypass interface.
pub fn udp_bind(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    if let Some(index) = bypass_interface() {
        pin(&socket, index, addr.is_ipv6())?;
    }
    Ok(socket)
}

#[cfg(windows)]
fn pin<S: std::os::windows::io::AsRawSocket>(socket: &S, index: u32, v6: bool) -> io::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF, SOCKET};
    // IP_UNICAST_IF takes the index in network byte order; IPV6_UNICAST_IF in host order.
    let (level, name, value) =
        if v6 { (IPPROTO_IPV6, IPV6_UNICAST_IF, index) } else { (IPPROTO_IP, IP_UNICAST_IF, index.to_be()) };
    // SAFETY: valid socket handle and a 4-byte option value.
    let rc = unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            level,
            name,
            &value as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Linux: SO_BINDTODEVICE by interface name (needs root/CAP_NET_RAW, as TUN mode does).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn pin<S: std::os::fd::AsRawFd>(socket: &S, index: u32, _v6: bool) -> io::Result<()> {
    let name = interface_name(index)?;
    // SAFETY: valid fd and a buffer of `len` bytes.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr() as *const libc::c_void,
            name.len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// macOS and iOS: IP_BOUND_IF / IPV6_BOUND_IF by interface index.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn pin<S: std::os::fd::AsRawFd>(socket: &S, index: u32, v6: bool) -> io::Result<()> {
    let (level, name) = if v6 { (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF) } else { (libc::IPPROTO_IP, libc::IP_BOUND_IF) };
    let value = index as libc::c_int;
    // SAFETY: valid fd and a 4-byte option value.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(windows, target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios")))]
fn pin<S>(_socket: &S, _index: u32, _v6: bool) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "interface pinning is not supported on this platform"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn interface_name(index: u32) -> io::Result<Vec<u8>> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: the buffer has IF_NAMESIZE bytes, as if_indextoname requires.
    if unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(buf.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect())
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn interface_index(name: &str) -> io::Result<u32> {
    let c = std::ffi::CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name"))?;
    // SAFETY: NUL-terminated name.
    let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}

#[cfg(any(windows, target_os = "linux", target_os = "android", target_os = "macos"))]
fn refuse_virtual(alias: &str, kind: &str) -> io::Error {
    io::Error::other(format!(
        "默认路由在虚拟网卡“{alias}”上（{kind}），可能是 Clash/mihomo 等软件的 TUN 模式或其他 VPN。请先关闭它再开启 superNET 的 TUN 模式"
    ))
}

/// Index of the interface that currently carries the default IPv4 route.
#[cfg(windows)]
pub fn default_interface_index() -> io::Result<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterface;
    let mut index = 0u32;
    // 1.1.1.1 in network byte order, as GetBestInterface expects.
    let dest = u32::from_ne_bytes([1, 1, 1, 1]);
    // SAFETY: plain value in, pointer to a local out.
    let rc = unsafe { GetBestInterface(dest, &mut index) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    // Another VPN or TUN (Clash/mihomo, sing-box, a VPN client) holding the default
    // route: pinning our own traffic to it and stacking our routes on top makes
    // the two loop into each other until socket buffers run out.
    if let Some((kind, alias)) = virtual_interface(index) {
        return Err(refuse_virtual(&alias, kind));
    }
    Ok(index)
}

/// (kind, alias) when `index` is a virtual (tunnel) adapter.
#[cfg(windows)]
fn virtual_interface(index: u32) -> Option<(&'static str, String)> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2, IF_TYPE_PROP_VIRTUAL, IF_TYPE_TUNNEL, MIB_IF_ROW2};
    // SAFETY: MIB_IF_ROW2 is plain data; zeroed with only the index set is the documented input.
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = index;
    // SAFETY: valid pointer to a local row.
    if unsafe { GetIfEntry2(&mut row) } != 0 {
        return None;
    }
    let kind = match row.Type {
        IF_TYPE_PROP_VIRTUAL => "虚拟网卡",
        IF_TYPE_TUNNEL => "隧道",
        _ => return None,
    };
    let end = row.Alias.iter().position(|&c| c == 0).unwrap_or(row.Alias.len());
    Some((kind, String::from_utf16_lossy(&row.Alias[..end])))
}

/// Linux: the interface of the lowest-metric default route in /proc/net/route.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn default_interface_index() -> io::Result<u32> {
    let table = std::fs::read_to_string("/proc/net/route")?;
    let name = default_route_interface(&table).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "没有默认路由"))?;
    // tun/tap, WireGuard and other point-to-point devices report ARPHRD_NONE (65534).
    let kind = std::fs::read_to_string(format!("/sys/class/net/{name}/type")).unwrap_or_default();
    if kind.trim() == "65534" {
        return Err(refuse_virtual(&name, "虚拟网卡"));
    }
    interface_index(&name)
}

/// The interface of the lowest-metric default route in a /proc/net/route table.
pub fn default_route_interface(table: &str) -> Option<String> {
    table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
            (f.len() >= 8 && f[1] == "00000000" && f[7] == "00000000").then(|| (f[6].parse::<u32>().unwrap_or(u32::MAX), f[0].to_string()))
        })
        .min()
        .map(|(_, name)| name)
}

/// macOS: `route -n get` names the interface of the default route.
#[cfg(target_os = "macos")]
pub fn default_interface_index() -> io::Result<u32> {
    let out = std::process::Command::new("route").args(["-n", "get", "1.1.1.1"]).output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let name = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface:").map(|v| v.trim().to_string()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "没有默认路由"))?;
    if name.starts_with("utun") || name.starts_with("ipsec") || name.starts_with("tun") {
        return Err(refuse_virtual(&name, "虚拟网卡"));
    }
    interface_index(&name)
}

/// iOS: the Network Extension owns routing; superNET never pins there.
#[cfg(not(any(windows, target_os = "linux", target_os = "android", target_os = "macos")))]
pub fn default_interface_index() -> io::Result<u32> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "not supported on this platform"))
}
