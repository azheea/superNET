//! Userspace WireGuard tunnel.
//!
//! boringtun handles the WireGuard protocol and smoltcp is the TCP/IP stack
//! *inside* the tunnel, so a connection through a node never touches the OS
//! routing table. TCP streams opened here implement tokio's `AsyncRead` and
//! `AsyncWrite`; UDP sockets offer `send_to` / `recv_from`.
//!
//! The same type serves both ends: a client knows the peer endpoint, a server
//! (`endpoint: None`) learns it from the first authenticated datagram.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::{OsRng, RngCore};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket as OsUdpSocket;
use tokio::sync::Notify;
use tracing::{debug, trace};

const TCP_BUFFER: usize = 256 * 1024;
const UDP_BUFFER: usize = 64 * 1024;
const UDP_PACKETS: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ORPHAN_LINGER: Duration = Duration::from_secs(30);
const UDP_OS_BUFFER: usize = 4 * 1024 * 1024;
const UDP_OUT_QUEUE: usize = 8192;
const EPHEMERAL_PORTS: std::ops::RangeInclusive<u16> = 49152..=65535;

/// Settings for one WireGuard peer relationship.
#[derive(Clone, Debug)]
pub struct TunnelConfig {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// Peer UDP endpoint. `None` means wait for the peer to contact us.
    pub endpoint: Option<SocketAddr>,
    /// Local UDP address. Defaults to the wildcard address of the endpoint's family.
    pub bind: Option<SocketAddr>,
    /// Our addresses inside the tunnel, for example `10.66.0.2/32`.
    pub addresses: Vec<(IpAddr, u8)>,
    pub mtu: usize,
    pub persistent_keepalive: Option<u16>,
}

/// Counters reported by boringtun.
#[derive(Clone, Debug, Default)]
pub struct TunnelStats {
    /// Time since the last completed handshake, if there was one.
    pub since_handshake: Option<Duration>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub drops: Drops,
    /// The most recent WireGuard error, for diagnostics.
    pub last_error: Option<String>,
}

/// Packets the tunnel had to drop or could not process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Drops {
    /// Decrypted packets dropped because the stack's input queue was full.
    pub rx_queue_full: u64,
    /// Datagrams dropped because the OS socket stayed full.
    pub udp_out_full: u64,
    /// OS send errors other than "would block".
    pub send_errors: u64,
    /// Datagrams boringtun rejected (bad key, replayed or too old counter, ...).
    pub decapsulate_errors: u64,
    pub encapsulate_errors: u64,
}

/// Generate a new WireGuard private key.
pub fn generate_private_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    StaticSecret::from(key).to_bytes()
}

/// The public key belonging to `private`.
pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}

/// A running tunnel. Dropping it closes every stream opened through it.
pub struct WgTunnel {
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

struct Shared {
    state: Mutex<State>,
    udp: OsUdpSocket,
    wake: Notify,
    closed: AtomicBool,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn check_open(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            Err(io::Error::new(io::ErrorKind::NotConnected, "tunnel closed"))
        } else {
            Ok(())
        }
    }
}

struct State {
    iface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    tunn: Tunn,
    endpoint: Option<SocketAddr>,
    learn_endpoint: bool,
    epoch: Instant,
    addresses: Vec<IpAddr>,
    used_ports: HashSet<u16>,
    next_port: u16,
    socket_ports: HashMap<SocketHandle, u16>,
    orphans: Vec<(SocketHandle, Instant)>,
    listeners: HashMap<u16, ListenerState>,
    scratch: Vec<u8>,
    /// Datagrams the OS socket could not take yet (send buffer full).
    udp_out: VecDeque<(Vec<u8>, SocketAddr)>,
    drops: Drops,
    last_error: Option<String>,
}

struct ListenerState {
    backlog: usize,
    pending: Vec<SocketHandle>,
    ready: VecDeque<SocketHandle>,
    waker: Option<Waker>,
}

impl WgTunnel {
    /// Bind the UDP socket and start the tunnel. The handshake happens when the
    /// first packet is sent (client) or received (server).
    pub async fn new(cfg: TunnelConfig) -> io::Result<Self> {
        if cfg.addresses.is_empty() {
            return Err(invalid("tunnel needs at least one address"));
        }
        let bind = cfg.bind.unwrap_or_else(|| match cfg.endpoint {
            Some(SocketAddr::V6(_)) => SocketAddr::from(([0u16; 8], 0)),
            _ => SocketAddr::from(([0u8; 4], 0)),
        });
        // Pinned to the physical interface while TUN mode is on.
        let udp = OsUdpSocket::from_std(supernet_netstack::sysnet::udp_bind(bind)?)?;
        {
            // Bursts of a full TCP window arrive at once; the OS default (64 KiB on
            // Windows) would drop most of them.
            let sock = socket2::SockRef::from(&udp);
            let _ = sock.set_recv_buffer_size(UDP_OS_BUFFER);
            let _ = sock.set_send_buffer_size(UDP_OS_BUFFER);
        }

        let tunn = Tunn::new(
            StaticSecret::from(cfg.private_key),
            PublicKey::from(cfg.peer_public_key),
            cfg.preshared_key,
            cfg.persistent_keepalive,
            OsRng.next_u32() >> 8,
            None,
        );

        let mtu = cfg.mtu.clamp(576, 9000);
        let mut device = VirtualDevice { rx: VecDeque::new(), tx: VecDeque::new(), mtu };
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = OsRng.next_u64();
        let epoch = Instant::now();
        let mut iface = Interface::new(iface_cfg, &mut device, SmolInstant::ZERO);
        iface.update_ip_addrs(|addrs| {
            for (ip, prefix) in &cfg.addresses {
                if addrs.push(IpCidr::new(IpAddress::from(*ip), *prefix)).is_err() {
                    debug!("ignoring extra tunnel address {ip}/{prefix}");
                }
            }
        });
        let addresses: Vec<IpAddr> = cfg.addresses.iter().map(|(ip, _)| *ip).collect();
        // Every destination is reachable through the peer; the gateway value is
        // never used for an IP medium, it only has to exist.
        for ip in &addresses {
            match ip {
                IpAddr::V4(v4) => {
                    let _ = iface.routes_mut().add_default_ipv4_route(*v4);
                }
                IpAddr::V6(v6) => {
                    let _ = iface.routes_mut().add_default_ipv6_route(*v6);
                }
            }
        }

        let state = State {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            tunn,
            endpoint: cfg.endpoint,
            learn_endpoint: cfg.endpoint.is_none(),
            epoch,
            addresses,
            used_ports: HashSet::new(),
            next_port: *EPHEMERAL_PORTS.start(),
            socket_ports: HashMap::new(),
            orphans: Vec::new(),
            listeners: HashMap::new(),
            scratch: vec![0u8; 65_536 + 256],
            udp_out: VecDeque::new(),
            drops: Drops::default(),
            last_error: None,
        };
        let shared = Arc::new(Shared {
            state: Mutex::new(state),
            udp,
            wake: Notify::new(),
            closed: AtomicBool::new(false),
        });
        let task = tokio::spawn(drive(shared.clone()));
        Ok(Self { shared, task })
    }

    /// The local UDP address the tunnel sends from.
    pub fn local_udp_addr(&self) -> io::Result<SocketAddr> {
        self.shared.udp.local_addr()
    }

    pub fn stats(&self) -> TunnelStats {
        let st = self.shared.lock();
        let (since_handshake, tx, rx, _, _) = st.tunn.stats();
        TunnelStats { since_handshake, tx_bytes: tx as u64, rx_bytes: rx as u64, drops: st.drops, last_error: st.last_error.clone() }
    }

    /// Our addresses inside the tunnel.
    pub fn addresses(&self) -> Vec<IpAddr> {
        self.shared.lock().addresses.clone()
    }

    /// Open a TCP connection to `remote` through the tunnel.
    pub async fn connect_tcp(&self, remote: SocketAddr) -> io::Result<TcpStream> {
        self.shared.check_open()?;
        let (handle, local) = {
            let mut st = self.shared.lock();
            let local_ip = st.source_for(remote.ip())?;
            let port = st.alloc_port()?;
            let mut sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
                tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
            );
            sock.set_nagle_enabled(false);
            sock.set_timeout(Some(SmolDuration::from_secs(60)));
            sock.set_keep_alive(Some(SmolDuration::from_secs(25)));
            let handle = st.sockets.add(sock);
            st.socket_ports.insert(handle, port);
            let result = {
                let State { iface, sockets, .. } = &mut *st;
                sockets
                    .get_mut::<tcp::Socket>(handle)
                    .connect(iface.context(), remote, (local_ip, port))
            };
            if let Err(e) = result {
                st.remove_socket(handle);
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("connect {remote}: {e}")));
            }
            (handle, SocketAddr::new(local_ip, port))
        };
        self.shared.wake.notify_one();

        let stream = TcpStream { shared: self.shared.clone(), handle, local, peer: remote };
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        loop {
            // The 50 ms cap is a safety net; state changes wake us immediately.
            match tokio::time::timeout(Duration::from_millis(50), poll_fn(|cx| stream.poll_established(cx))).await {
                Ok(Ok(())) => return Ok(stream),
                Ok(Err(e)) => return Err(e),
                Err(_) if Instant::now() < deadline => continue,
                Err(_) => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, format!("connect {remote}: timed out")))
                }
            }
        }
    }

    /// Bind a UDP socket inside the tunnel. `port: None` picks an ephemeral port.
    pub fn bind_udp(&self, port: Option<u16>) -> io::Result<UdpSocket> {
        self.shared.check_open()?;
        let mut st = self.shared.lock();
        let (port, owned) = match port {
            Some(p) => (p, false),
            None => (st.alloc_port()?, true),
        };
        let mut sock = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_PACKETS], vec![0u8; UDP_BUFFER]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_PACKETS], vec![0u8; UDP_BUFFER]),
        );
        if let Err(e) = sock.bind(port) {
            if owned {
                st.used_ports.remove(&port);
            }
            return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("bind udp {port}: {e}")));
        }
        let handle = st.sockets.add(sock);
        if owned {
            st.socket_ports.insert(handle, port);
        }
        Ok(UdpSocket { shared: self.shared.clone(), handle, port })
    }

    /// Accept TCP connections on `port` of our tunnel addresses (used by servers).
    pub fn listen_tcp(&self, port: u16, backlog: usize) -> io::Result<TcpListener> {
        self.shared.check_open()?;
        let mut st = self.shared.lock();
        if st.listeners.contains_key(&port) {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("port {port} already listening")));
        }
        st.listeners.insert(
            port,
            ListenerState { backlog: backlog.max(1), pending: Vec::new(), ready: VecDeque::new(), waker: None },
        );
        st.service_listeners();
        drop(st);
        self.shared.wake.notify_one();
        Ok(TcpListener { shared: self.shared.clone(), port })
    }
}

impl Drop for WgTunnel {
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::Release);
        {
            let mut st = self.shared.lock();
            // Aborting wakes every task waiting on these sockets; they then see
            // the closed flag and fail instead of hanging.
            for (_, socket) in st.sockets.iter_mut() {
                if let smoltcp::socket::Socket::Tcp(s) = socket {
                    s.abort();
                }
            }
            for listener in st.listeners.values_mut() {
                if let Some(w) = listener.waker.take() {
                    w.wake();
                }
            }
        }
        self.task.abort();
    }
}

impl State {
    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.epoch.elapsed().as_micros() as i64)
    }

    fn source_for(&self, dst: IpAddr) -> io::Result<IpAddr> {
        self.addresses
            .iter()
            .copied()
            .find(|a| a.is_ipv4() == dst.is_ipv4())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("tunnel has no {} address for {dst}", if dst.is_ipv4() { "IPv4" } else { "IPv6" }),
                )
            })
    }

    fn alloc_port(&mut self) -> io::Result<u16> {
        let span = (*EPHEMERAL_PORTS.end() - *EPHEMERAL_PORTS.start()) as usize + 1;
        for _ in 0..span {
            let port = self.next_port;
            self.next_port = if port == *EPHEMERAL_PORTS.end() { *EPHEMERAL_PORTS.start() } else { port + 1 };
            if self.used_ports.insert(port) {
                return Ok(port);
            }
        }
        Err(io::Error::new(io::ErrorKind::AddrInUse, "no free tunnel ports"))
    }

    fn remove_socket(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
        if let Some(port) = self.socket_ports.remove(&handle) {
            self.used_ports.remove(&port);
        }
    }

    /// Run the TCP/IP stack and send whatever it produced. Returns how long the
    /// driver may sleep before the stack needs attention again.
    fn pump(&mut self, udp: &OsUdpSocket) -> Duration {
        #[cfg(test)]
        TRACE_TAG.with(|t| t.set(udp.local_addr().map_or(0, |a| a.port())));
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.flush_tx(udp);
        self.service_listeners();
        self.reap_orphans();
        let delay = self
            .iface
            .poll_delay(self.now(), &self.sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(Duration::from_secs(1));
        delay.clamp(Duration::from_millis(1), Duration::from_secs(1))
    }

    fn flush_tx(&mut self, udp: &OsUdpSocket) {
        let endpoint = self.endpoint;
        while let Some(packet) = self.device.tx.pop_front() {
            match self.tunn.encapsulate(&packet, &mut self.scratch) {
                TunnResult::WriteToNetwork(data) => send_datagram(udp, &mut self.udp_out, &mut self.drops, endpoint, data),
                TunnResult::Err(e) => {
                    self.drops.encapsulate_errors += 1;
                    self.last_error = Some(format!("encapsulate: {e:?}"));
                }
                _ => {}
            }
        }
    }

    fn on_datagram(&mut self, udp: &OsUdpSocket, data: &[u8], from: SocketAddr) {
        let mut authenticated = false;
        match self.tunn.decapsulate(Some(from.ip()), data, &mut self.scratch) {
            TunnResult::WriteToNetwork(reply) => {
                authenticated = true;
                send_datagram(udp, &mut self.udp_out, &mut self.drops, Some(from), reply);
                // Flush packets that were queued while the handshake ran.
                while let TunnResult::WriteToNetwork(queued) = self.tunn.decapsulate(None, &[], &mut self.scratch) {
                    send_datagram(udp, &mut self.udp_out, &mut self.drops, Some(from), queued);
                }
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                authenticated = true;
                if self.device.rx.len() < 4096 {
                    self.device.rx.push_back(packet.to_vec());
                } else {
                    self.drops.rx_queue_full += 1;
                }
            }
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                self.drops.decapsulate_errors += 1;
                self.last_error = Some(format!("decapsulate from {from}: {e:?}"));
            }
        }
        if authenticated && self.learn_endpoint && self.endpoint != Some(from) {
            debug!("peer endpoint is now {from}");
            self.endpoint = Some(from);
        }
    }

    fn update_timers(&mut self, udp: &OsUdpSocket) {
        match self.tunn.update_timers(&mut self.scratch) {
            TunnResult::WriteToNetwork(data) => send_datagram(udp, &mut self.udp_out, &mut self.drops, self.endpoint, data),
            // An expired session is re-established by the next outgoing packet.
            TunnResult::Err(e) => trace!("timers: {e:?}"),
            _ => {}
        }
    }

    fn service_listeners(&mut self) {
        for (&port, listener) in self.listeners.iter_mut() {
            let mut i = 0;
            while i < listener.pending.len() {
                let handle = listener.pending[i];
                let sock = self.sockets.get_mut::<tcp::Socket>(handle);
                match sock.state() {
                    tcp::State::Listen | tcp::State::SynReceived => i += 1,
                    tcp::State::Established | tcp::State::CloseWait => {
                        listener.pending.swap_remove(i);
                        listener.ready.push_back(handle);
                    }
                    _ => {
                        // A half-open attempt failed; listen again.
                        let _ = sock.listen(IpListenEndpoint { addr: None, port });
                        i += 1;
                    }
                }
            }
            while listener.pending.len() < listener.backlog {
                let mut sock = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
                    tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
                );
                sock.set_nagle_enabled(false);
                sock.set_timeout(Some(SmolDuration::from_secs(60)));
                if sock.listen(IpListenEndpoint { addr: None, port }).is_err() {
                    break;
                }
                listener.pending.push(self.sockets.add(sock));
            }
            if !listener.ready.is_empty() {
                if let Some(w) = listener.waker.take() {
                    w.wake();
                }
            }
        }
    }

    fn reap_orphans(&mut self) {
        let mut i = 0;
        while i < self.orphans.len() {
            let (handle, since) = self.orphans[i];
            let sock = self.sockets.get_mut::<tcp::Socket>(handle);
            let done = matches!(sock.state(), tcp::State::Closed | tcp::State::TimeWait);
            if done {
                self.orphans.swap_remove(i);
                self.remove_socket(handle);
                continue;
            }
            if since.elapsed() > ORPHAN_LINGER {
                sock.abort();
            }
            i += 1;
        }
    }
}

/// Test-only packet loss injected on send, in per-mille.
#[cfg(test)]
static TEST_LOSS_PER_MILLE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

#[cfg(test)]
fn test_drop_packet() -> bool {
    let loss = TEST_LOSS_PER_MILLE.load(Ordering::Relaxed);
    loss > 0 && OsRng.next_u32() % 1000 < loss
}

#[cfg(test)]
thread_local! {
    /// Which tunnel (its UDP port) the current thread is driving; tags test traces.
    static TRACE_TAG: std::cell::Cell<u16> = const { std::cell::Cell::new(0) };
}

fn send_datagram(
    udp: &OsUdpSocket,
    queue: &mut VecDeque<(Vec<u8>, SocketAddr)>,
    drops: &mut Drops,
    to: Option<SocketAddr>,
    data: &[u8],
) {
    let Some(to) = to else { return };
    #[cfg(test)]
    if test_drop_packet() {
        return;
    }
    // Never block while holding the state lock. Keep order: once something is
    // queued, everything after it queues too until the socket drains.
    if queue.is_empty() {
        match udp.try_send_to(data, to) {
            Ok(_) => return,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                trace!("send to {to}: {e}");
                drops.send_errors += 1;
                return;
            }
        }
    }
    if queue.len() < UDP_OUT_QUEUE {
        queue.push_back((data.to_vec(), to));
    } else {
        drops.udp_out_full += 1;
    }
}

impl State {
    /// Send queued datagrams; returns true if some are still waiting.
    fn flush_udp_out(&mut self, udp: &OsUdpSocket) -> bool {
        while let Some((data, to)) = self.udp_out.front() {
            match udp.try_send_to(data, *to) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return true,
                Err(e) => {
                    trace!("send to {to}: {e}");
                    self.drops.send_errors += 1;
                }
            }
            self.udp_out.pop_front();
        }
        false
    }
}

async fn drive(shared: Arc<Shared>) {
    let mut buf = vec![0u8; 65_536];
    let mut timers = tokio::time::interval(Duration::from_millis(250));
    timers.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if shared.closed.load(Ordering::Acquire) {
            break;
        }
        let (delay, backlog) = {
            let mut st = shared.lock();
            let delay = st.pump(&shared.udp);
            (delay, st.flush_udp_out(&shared.udp))
        };
        tokio::select! {
            received = shared.udp.recv_from(&mut buf) => match received {
                Ok((n, from)) => {
                    let mut st = shared.lock();
                    st.on_datagram(&shared.udp, &buf[..n], from);
                    // Drain whatever else already arrived before running the stack.
                    while let Ok((n, from)) = shared.udp.try_recv_from(&mut buf) {
                        st.on_datagram(&shared.udp, &buf[..n], from);
                    }
                }
                // Windows reports ICMP "port unreachable" as a receive error
                // (WSAECONNRESET); the socket itself is still usable.
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                Err(e) => {
                    debug!("udp receive: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
            _ = shared.wake.notified() => {}
            _ = tokio::time::sleep(delay) => {}
            _ = timers.tick() => shared.lock().update_timers(&shared.udp),
            _ = shared.udp.writable(), if backlog => {}
        }
    }
}

struct VirtualDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct VirtualRx(Vec<u8>);
struct VirtualTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for VirtualRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl TxToken for VirtualTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRx;
    type TxToken<'a> = VirtualTx<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((VirtualRx(packet), VirtualTx(&mut self.tx)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.tx.len() >= 4096 {
            None
        } else {
            Some(VirtualTx(&mut self.tx))
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// A TCP connection inside the tunnel.
pub struct TcpStream {
    shared: Arc<Shared>,
    handle: SocketHandle,
    local: SocketAddr,
    peer: SocketAddr,
}

impl TcpStream {
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    fn poll_established(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.check_open()?;
        let mut st = self.shared.lock();
        let sock = st.sockets.get_mut::<tcp::Socket>(self.handle);
        match sock.state() {
            tcp::State::Established | tcp::State::CloseWait => Poll::Ready(Ok(())),
            tcp::State::SynSent | tcp::State::SynReceived => {
                sock.register_send_waker(cx.waker());
                sock.register_recv_waker(cx.waker());
                Poll::Pending
            }
            _ => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("connect {}: refused", self.peer),
            ))),
        }
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.shared.check_open()?;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut st = this.shared.lock();
        let sock = st.sockets.get_mut::<tcp::Socket>(this.handle);
        if sock.can_recv() {
            let n = sock.recv_slice(buf.initialize_unfilled()).map_err(io::Error::other)?;
            buf.advance(n);
            drop(st);
            // Let the driver advertise the freed receive window.
            this.shared.wake.notify_one();
            return Poll::Ready(Ok(()));
        }
        if !sock.may_recv() {
            return Poll::Ready(Ok(())); // end of stream
        }
        sock.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.shared.check_open()?;
        let mut st = this.shared.lock();
        let sock = st.sockets.get_mut::<tcp::Socket>(this.handle);
        if !sock.may_send() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "connection closed")));
        }
        if sock.can_send() {
            let n = sock.send_slice(data).map_err(io::Error::other)?;
            drop(st);
            this.shared.wake.notify_one();
            return Poll::Ready(Ok(n));
        }
        sock.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        {
            let mut st = this.shared.lock();
            st.sockets.get_mut::<tcp::Socket>(this.handle).close();
        }
        this.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut st = self.shared.lock();
        st.sockets.get_mut::<tcp::Socket>(self.handle).close();
        st.orphans.push((self.handle, Instant::now()));
        drop(st);
        self.shared.wake.notify_one();
    }
}

/// A UDP socket inside the tunnel.
pub struct UdpSocket {
    shared: Arc<Shared>,
    handle: SocketHandle,
    port: u16,
}

impl UdpSocket {
    pub fn local_port(&self) -> u16 {
        self.port
    }

    pub async fn send_to(&self, data: &[u8], to: SocketAddr) -> io::Result<()> {
        poll_fn(|cx| {
            self.shared.check_open()?;
            let mut st = self.shared.lock();
            let sock = st.sockets.get_mut::<udp::Socket>(self.handle);
            if sock.can_send() {
                sock.send_slice(data, IpEndpoint::from(to)).map_err(io::Error::other)?;
                drop(st);
                self.shared.wake.notify_one();
                Poll::Ready(Ok(()))
            } else {
                sock.register_send_waker(cx.waker());
                Poll::Pending
            }
        })
        .await
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| {
            self.shared.check_open()?;
            let mut st = self.shared.lock();
            let sock = st.sockets.get_mut::<udp::Socket>(self.handle);
            if sock.can_recv() {
                let (n, meta) = sock.recv_slice(buf).map_err(io::Error::other)?;
                Poll::Ready(Ok((n, SocketAddr::from(meta.endpoint))))
            } else {
                sock.register_recv_waker(cx.waker());
                Poll::Pending
            }
        })
        .await
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        self.shared.lock().remove_socket(self.handle);
    }
}

/// Accepts TCP connections arriving through the tunnel.
pub struct TcpListener {
    shared: Arc<Shared>,
    port: u16,
}

impl TcpListener {
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        poll_fn(|cx| {
            self.shared.check_open()?;
            let mut st = self.shared.lock();
            let next = {
                let listener = st.listeners.get_mut(&self.port).expect("listener exists while handle lives");
                match listener.ready.pop_front() {
                    Some(h) => Some(h),
                    None => {
                        listener.waker = Some(cx.waker().clone());
                        None
                    }
                }
            };
            let Some(handle) = next else { return Poll::Pending };
            let sock = st.sockets.get::<tcp::Socket>(handle);
            let peer = sock.remote_endpoint().map(SocketAddr::from).unwrap_or_else(|| SocketAddr::from(([0u8; 4], 0)));
            let local = sock.local_endpoint().map(SocketAddr::from).unwrap_or_else(|| SocketAddr::from(([0u8; 4], self.port)));
            drop(st);
            self.shared.wake.notify_one();
            Poll::Ready(Ok((TcpStream { shared: self.shared.clone(), handle, local, peer }, peer)))
        })
        .await
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut st = self.shared.lock();
        if let Some(listener) = st.listeners.remove(&self.port) {
            for handle in listener.pending.into_iter().chain(listener.ready) {
                st.sockets.remove(handle);
            }
        }
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pair() -> (WgTunnel, WgTunnel) {
        let server_key = generate_private_key();
        let client_key = generate_private_key();
        let server = WgTunnel::new(TunnelConfig {
            private_key: server_key,
            peer_public_key: public_key(&client_key),
            preshared_key: None,
            endpoint: None,
            bind: Some("127.0.0.1:0".parse().unwrap()),
            addresses: vec![("10.66.0.1".parse().unwrap(), 24)],
            mtu: 1420,
            persistent_keepalive: None,
        })
        .await
        .unwrap();
        let client = WgTunnel::new(TunnelConfig {
            private_key: client_key,
            peer_public_key: public_key(&server_key),
            preshared_key: None,
            endpoint: Some(server.local_udp_addr().unwrap()),
            bind: Some("127.0.0.1:0".parse().unwrap()),
            addresses: vec![("10.66.0.2".parse().unwrap(), 32)],
            mtu: 1420,
            persistent_keepalive: Some(25),
        })
        .await
        .unwrap();
        (server, client)
    }

    #[tokio::test]
    async fn tcp_echo_through_tunnel() {
        let (server, client) = pair().await;
        let listener = server.listen_tcp(7, 4).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        let n = s.read(&mut buf).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        s.write_all(&buf[..n]).await.unwrap();
                    }
                    s.shutdown().await.unwrap();
                });
            }
        });

        let stream = client.connect_tcp("10.66.0.1:7".parse().unwrap()).await.unwrap();
        let payload: Vec<u8> = (0..2 * 1024 * 1024u32).map(|i| (i * 31 % 251) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            wr.write_all(&payload).await.unwrap();
            wr.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), rd.read_to_end(&mut got)).await.unwrap().unwrap();
        writer.await.unwrap();
        assert_eq!(got.len(), expected.len());
        assert!(got == expected, "echoed data differs");
        assert!(client.stats().since_handshake.is_some());
    }

    /// Keeps the last smoltcp trace lines so a stall can be explained.
    struct RingLog(std::sync::Mutex<VecDeque<String>>, Instant);

    impl log::Log for RingLog {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }
        fn log(&self, record: &log::Record) {
            let mut q = self.0.lock().unwrap();
            let tag = TRACE_TAG.with(|t| t.get());
            q.push_back(format!("{:>9.3} [{tag}] {}", self.1.elapsed().as_secs_f64(), record.args()));
            if q.len() > 200_000 {
                q.pop_front();
            }
        }
        fn flush(&self) {}
    }

    /// With `SUPERNET_TRACE` set, capture smoltcp traces into a ring buffer.
    fn trace_ring() -> Option<&'static RingLog> {
        static RING: std::sync::OnceLock<&'static RingLog> = std::sync::OnceLock::new();
        std::env::var_os("SUPERNET_TRACE")?;
        Some(RING.get_or_init(|| {
            let ring: &'static RingLog = Box::leak(Box::new(RingLog(std::sync::Mutex::new(VecDeque::new()), Instant::now())));
            log::set_logger(ring).unwrap();
            log::set_max_level(log::LevelFilter::Trace);
            ring
        }))
    }

    fn dump_trace(ring: Option<&RingLog>) {
        if let Some(ring) = ring {
            let q = ring.0.lock().unwrap();
            let dump: Vec<&str> = q.iter().map(String::as_str).collect();
            std::fs::write("../../local/stall-trace.txt", dump.join("
")).unwrap();
        }
    }

    fn stall_limit(default_ms: u64) -> Duration {
        Duration::from_millis(std::env::var("SUPERNET_STALL_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(default_ms))
    }

    /// Many large echoes in a row; run with `--ignored` when hunting stalls.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn stress_echo() {
        let ring = trace_ring();
        let (server, client) = pair().await;
        let listener = server.listen_tcp(7, 8).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 32 * 1024];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = s.shutdown().await;
                });
            }
        });
        let payload: Arc<Vec<u8>> = Arc::new((0..4 * 1024 * 1024u32).map(|i| (i * 7 % 253) as u8).collect());
        for round in 0..40 {
            let started = Instant::now();
            let stream = client.connect_tcp("10.66.0.1:7".parse().unwrap()).await.unwrap();
            let (mut rd, mut wr) = tokio::io::split(stream);
            let data = payload.clone();
            let writer = tokio::spawn(async move {
                wr.write_all(&data).await.unwrap();
                wr.shutdown().await.unwrap();
            });
            let mut got = Vec::new();
            let res = tokio::time::timeout(stall_limit(20_000), rd.read_to_end(&mut got)).await;
            if res.is_err() {
                dump_trace(ring);
                eprintln!("client udp {:?} server udp {:?}", client.local_udp_addr(), server.local_udp_addr());
            }
            assert!(
                res.is_ok(),
                "round {round}: stalled after {} of {} bytes
client {:?}
server {:?}",
                got.len(),
                payload.len(),
                client.stats(),
                server.stats()
            );
            writer.await.unwrap();
            assert!(got == *payload, "round {round}: data differs");
            eprintln!("round {round}: {:?} client drops {:?} server drops {:?}", started.elapsed(), client.stats().drops, server.stats().drops);
        }
    }

    /// Bulk echo over a lossy link: TCP inside the tunnel must recover every
    /// loss and deliver the data intact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn echo_survives_packet_loss() {
        let ring = trace_ring();
        let (server, client) = pair().await;
        let listener = server.listen_tcp(7, 4).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 32 * 1024];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = s.shutdown().await;
                });
            }
        });
        // Handshake first so the test measures data recovery, not handshake retries.
        drop(client.connect_tcp("10.66.0.1:7".parse().unwrap()).await.unwrap());
        TEST_LOSS_PER_MILLE.store(20, Ordering::Relaxed); // 2 %
        let payload: Vec<u8> = (0..1024 * 1024u32).map(|i| (i * 13 % 251) as u8).collect();
        for round in 0..3 {
            let stream = client.connect_tcp("10.66.0.1:7".parse().unwrap()).await.unwrap();
            let (mut rd, mut wr) = tokio::io::split(stream);
            let data = payload.clone();
            let writer = tokio::spawn(async move {
                wr.write_all(&data).await.unwrap();
                wr.shutdown().await.unwrap();
            });
            let mut got = Vec::new();
            let started = Instant::now();
            let res = tokio::time::timeout(stall_limit(60_000), rd.read_to_end(&mut got)).await;
            if res.is_err() {
                dump_trace(ring);
                eprintln!("client udp {:?} server udp {:?}", client.local_udp_addr(), server.local_udp_addr());
            }
            assert!(res.is_ok(), "round {round}: stalled after {} bytes", got.len());
            writer.await.unwrap();
            assert!(got == payload, "round {round}: data differs");
            eprintln!("lossy round {round}: {:?}", started.elapsed());
        }
        TEST_LOSS_PER_MILLE.store(0, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn udp_round_trip_and_refused_port() {
        let (server, client) = pair().await;
        let srv = server.bind_udp(Some(53)).unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, from) = srv.recv_from(&mut buf).await.unwrap();
                srv.send_to(&buf[..n], from).await.unwrap();
            }
        });
        let sock = client.bind_udp(None).unwrap();
        sock.send_to(b"ping", "10.66.0.1:53".parse().unwrap()).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(10), sock.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from, "10.66.0.1:53".parse::<SocketAddr>().unwrap());

        let err = client.connect_tcp("10.66.0.1:9".parse().unwrap()).await.err().expect("nothing listens on 9");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }
}
