//! Userspace TCP/IP stack for TUN mode.
//!
//! Raw IP packets from a TUN device go in; TCP connections (with the address
//! the application meant to reach) and UDP datagrams come out. Replies are
//! turned back into IP packets for the TUN device.
//!
//! * TCP runs on smoltcp in "any IP" mode: when a SYN arrives, a socket is
//!   made to listen on exactly that destination, then the packet is handed to
//!   smoltcp, which completes the handshake as if it were the destination.
//! * UDP bypasses smoltcp: datagrams are parsed and built directly, which is
//!   all a transparent relay needs.

pub mod sysnet;

use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, IpProtocol, IpVersion, Ipv4Address, Ipv4Packet, Ipv4Repr,
    Ipv6Address, Ipv6Packet, Ipv6Repr, TcpPacket, UdpPacket, UdpRepr,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Notify};

const TCP_RX_BUFFER: usize = 256 * 1024;
const TCP_TX_BUFFER: usize = 128 * 1024;
const QUEUE: usize = 4096;
const ORPHAN_LINGER: Duration = Duration::from_secs(30);
/// A listener that never completed its handshake is dropped after this.
const HALF_OPEN_LIMIT: Duration = Duration::from_secs(15);

/// A UDP datagram seen on the TUN device.
#[derive(Debug, Clone)]
pub struct UdpDatagram {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

/// The packet side of the stack, to be wired to a TUN device.
pub struct PacketPorts {
    /// Packets read from the TUN device go here.
    pub to_stack: mpsc::Sender<Vec<u8>>,
    /// Packets to write to the TUN device come out here.
    pub from_stack: mpsc::Receiver<Vec<u8>>,
}

pub struct NetStack {
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

struct Shared {
    state: Mutex<State>,
    wake: Notify,
    out: mpsc::Sender<Vec<u8>>,
    closed: AtomicBool,
}

struct State {
    iface: Interface,
    device: QueueDevice,
    sockets: SocketSet<'static>,
    epoch: Instant,
    /// Listeners created for an incoming SYN, keyed by (client, destination).
    half_open: HashMap<(SocketAddr, SocketAddr), (SocketHandle, Instant)>,
    ready: VecDeque<(SocketHandle, SocketAddr, SocketAddr)>,
    accept_waker: Option<Waker>,
    orphans: Vec<(SocketHandle, Instant)>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn check_open(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            Err(io::Error::new(io::ErrorKind::NotConnected, "stack closed"))
        } else {
            Ok(())
        }
    }
}

impl NetStack {
    /// Create the stack. Returns the packet ports for the TUN device and the
    /// stream of UDP datagrams.
    pub fn new(mtu: usize) -> (NetStack, PacketPorts, mpsc::Receiver<UdpDatagram>) {
        let (to_stack, from_tun) = mpsc::channel::<Vec<u8>>(QUEUE);
        let (to_tun, from_stack) = mpsc::channel::<Vec<u8>>(QUEUE);
        let (udp_tx, udp_rx) = mpsc::channel::<UdpDatagram>(QUEUE);

        let mut device = QueueDevice { rx: VecDeque::new(), tx: VecDeque::new(), mtu };
        let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
        cfg.random_seed = rand_seed();
        let mut iface = Interface::new(cfg, &mut device, SmolInstant::ZERO);
        iface.set_any_ip(true);
        // Placeholder addresses: with any-IP every destination is accepted,
        // but routes need an address to point at.
        let v4 = Ipv4Address::new(198, 18, 0, 1);
        let v6 = Ipv6Address::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 1);
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::Ipv4(v4), 15));
            let _ = a.push(IpCidr::new(IpAddress::Ipv6(v6), 64));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(v4);
        let _ = iface.routes_mut().add_default_ipv6_route(v6);

        let state = State {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            epoch: Instant::now(),
            half_open: HashMap::new(),
            ready: VecDeque::new(),
            accept_waker: None,
            orphans: Vec::new(),
        };
        let shared = Arc::new(Shared { state: Mutex::new(state), wake: Notify::new(), out: to_tun, closed: AtomicBool::new(false) });
        let task = tokio::spawn(drive(shared.clone(), from_tun, udp_tx));
        (NetStack { shared, task }, PacketPorts { to_stack, from_stack }, udp_rx)
    }

    /// Next TCP connection: (stream, client address, intended destination).
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr, SocketAddr)> {
        poll_fn(|cx| {
            self.shared.check_open()?;
            let mut st = self.shared.lock();
            match st.ready.pop_front() {
                Some((handle, src, dst)) => {
                    drop(st);
                    Poll::Ready(Ok((TcpStream { shared: self.shared.clone(), handle }, src, dst)))
                }
                None => {
                    st.accept_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
        .await
    }

    /// Send a UDP reply: `from` is the address the client talked to.
    pub fn send_udp(&self, from: SocketAddr, to: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let packet = build_udp(from, to, payload)?;
        self.shared.out.try_send(packet).map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "tun queue full"))
    }
}

impl Drop for NetStack {
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::Release);
        {
            let mut st = self.shared.lock();
            for (_, s) in st.sockets.iter_mut() {
                #[allow(irrefutable_let_patterns)] // only TCP sockets are compiled in
                if let smoltcp::socket::Socket::Tcp(t) = s {
                    t.abort();
                }
            }
            if let Some(w) = st.accept_waker.take() {
                w.wake();
            }
        }
        self.task.abort();
    }
}

fn rand_seed() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(Instant::now().elapsed().as_nanos());
    h.finish()
}

enum Classified {
    Udp(UdpDatagram),
    TcpSyn { src: SocketAddr, dst: SocketAddr },
    Other,
    Drop,
}

/// Look at a raw IP packet: UDP is taken out, a fresh TCP SYN noted.
fn classify(packet: &[u8]) -> Classified {
    let Some(&first) = packet.first() else { return Classified::Drop };
    let (src_ip, dst_ip, proto, payload): (IpAddr, IpAddr, IpProtocol, &[u8]) = match IpVersion::of_packet(packet) {
        Ok(IpVersion::Ipv4) => {
            let Ok(p) = Ipv4Packet::new_checked(packet) else { return Classified::Drop };
            if p.more_frags() || p.frag_offset() != 0 {
                return Classified::Other; // fragments: let smoltcp reassemble or drop
            }
            let header = p.header_len() as usize;
            let total = (p.total_len() as usize).min(packet.len());
            (IpAddr::V4(p.src_addr()), IpAddr::V4(p.dst_addr()), p.next_header(), &packet[header..total])
        }
        Ok(IpVersion::Ipv6) => {
            let Ok(p) = Ipv6Packet::new_checked(packet) else { return Classified::Drop };
            (IpAddr::V6(p.src_addr()), IpAddr::V6(p.dst_addr()), p.next_header(), p.payload())
        }
        _ => {
            let _ = first;
            return Classified::Drop;
        }
    };
    if !forwardable(src_ip, dst_ip) {
        return Classified::Drop;
    }
    match proto {
        IpProtocol::Udp => {
            let Ok(u) = UdpPacket::new_checked(payload) else { return Classified::Drop };
            Classified::Udp(UdpDatagram {
                src: SocketAddr::new(src_ip, u.src_port()),
                dst: SocketAddr::new(dst_ip, u.dst_port()),
                payload: u.payload().to_vec(),
            })
        }
        IpProtocol::Tcp => {
            let Ok(t) = TcpPacket::new_checked(payload) else { return Classified::Drop };
            if t.syn() && !t.ack() {
                Classified::TcpSyn { src: SocketAddr::new(src_ip, t.src_port()), dst: SocketAddr::new(dst_ip, t.dst_port()) }
            } else {
                Classified::Other
            }
        }
        _ => Classified::Other,
    }
}

/// Whether a packet the OS put on the TUN may be relayed at all.
///
/// Multicast and broadcast (SSDP, mDNS, LLMNR, NetBIOS…) must never be
/// relayed: re-sent from a socket they follow the multicast routes straight
/// back into the TUN and multiply — on the first real Windows run this was a
/// storm of 140k packets in two seconds that exhausted the system's socket
/// buffers. Link-local and unspecified addresses never leave the local link
/// either. (Loopback never reaches a real TUN; the in-memory tests use it.)
fn forwardable(src: IpAddr, dst: IpAddr) -> bool {
    let ok = |ip: IpAddr| match ip {
        IpAddr::V4(v4) => !(v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified() || v4.is_link_local()),
        IpAddr::V6(v6) => {
            !(v6.is_multicast() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    };
    ok(dst) && !src.is_multicast() && !src.is_unspecified()
}

/// Build an IPv4/IPv6 + UDP packet with valid checksums.
fn build_udp(from: SocketAddr, to: SocketAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let udp = UdpRepr { src_port: from.port(), dst_port: to.port() };
    let caps = ChecksumCapabilities::default();
    let udp_len = udp.header_len() + payload.len();
    match (from.ip(), to.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let ip = Ipv4Repr { src_addr: src, dst_addr: dst, next_header: IpProtocol::Udp, payload_len: udp_len, hop_limit: 64 };
            let mut buf = vec![0u8; ip.buffer_len() + udp_len];
            let mut packet = Ipv4Packet::new_unchecked(&mut buf);
            ip.emit(&mut packet, &caps);
            let mut u = UdpPacket::new_unchecked(packet.payload_mut());
            udp.emit(&mut u, &IpAddress::Ipv4(src), &IpAddress::Ipv4(dst), payload.len(), |b| b.copy_from_slice(payload), &caps);
            Ok(buf)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let ip = Ipv6Repr { src_addr: src, dst_addr: dst, next_header: IpProtocol::Udp, payload_len: udp_len, hop_limit: 64 };
            let mut buf = vec![0u8; ip.buffer_len() + udp_len];
            let mut packet = Ipv6Packet::new_unchecked(&mut buf);
            ip.emit(&mut packet);
            let mut u = UdpPacket::new_unchecked(packet.payload_mut());
            udp.emit(&mut u, &IpAddress::Ipv6(src), &IpAddress::Ipv6(dst), payload.len(), |b| b.copy_from_slice(payload), &caps);
            Ok(buf)
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "UDP reply mixes IPv4 and IPv6")),
    }
}

impl State {
    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.epoch.elapsed().as_micros() as i64)
    }

    /// Make a socket listen on `dst` so the SYN from `src` is accepted.
    fn prepare_listener(&mut self, src: SocketAddr, dst: SocketAddr) {
        if self.half_open.contains_key(&(src, dst)) {
            return; // SYN retransmission
        }
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER]),
            tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER]),
        );
        sock.set_nagle_enabled(false);
        sock.set_timeout(Some(SmolDuration::from_secs(120)));
        sock.set_keep_alive(Some(SmolDuration::from_secs(60)));
        if sock.listen(IpListenEndpoint { addr: Some(IpAddress::from(dst.ip())), port: dst.port() }).is_err() {
            return;
        }
        let handle = self.sockets.add(sock);
        self.half_open.insert((src, dst), (handle, Instant::now()));
    }

    fn pump(&mut self, out: &mpsc::Sender<Vec<u8>>) -> Duration {
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        while let Some(packet) = self.device.tx.pop_front() {
            // If the TUN side cannot keep up, drop: TCP retransmits.
            let _ = out.try_send(packet);
        }
        self.promote_established();
        self.reap();
        self.iface
            .poll_delay(self.now(), &self.sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(Duration::from_secs(1))
            .clamp(Duration::from_millis(1), Duration::from_secs(1))
    }

    fn promote_established(&mut self) {
        let mut done = Vec::new();
        for (&key, &(handle, since)) in &self.half_open {
            let state = self.sockets.get::<tcp::Socket>(handle).state();
            match state {
                tcp::State::Established | tcp::State::CloseWait => done.push((key, Some(handle))),
                tcp::State::Listen | tcp::State::SynReceived if since.elapsed() < HALF_OPEN_LIMIT => {}
                _ => done.push((key, None)),
            }
        }
        for ((src, dst), promoted) in done {
            let (handle, _) = self.half_open.remove(&(src, dst)).expect("present");
            match promoted {
                Some(h) => self.ready.push_back((h, src, dst)),
                None => {
                    self.sockets.remove(handle);
                }
            }
        }
        if !self.ready.is_empty() {
            if let Some(w) = self.accept_waker.take() {
                w.wake();
            }
        }
    }

    fn reap(&mut self) {
        let mut i = 0;
        while i < self.orphans.len() {
            let (handle, since) = self.orphans[i];
            let sock = self.sockets.get_mut::<tcp::Socket>(handle);
            if matches!(sock.state(), tcp::State::Closed | tcp::State::TimeWait) {
                self.orphans.swap_remove(i);
                self.sockets.remove(handle);
                continue;
            }
            if since.elapsed() > ORPHAN_LINGER {
                sock.abort();
            }
            i += 1;
        }
    }
}

async fn drive(shared: Arc<Shared>, mut from_tun: mpsc::Receiver<Vec<u8>>, udp_tx: mpsc::Sender<UdpDatagram>) {
    loop {
        if shared.closed.load(Ordering::Acquire) {
            break;
        }
        let delay = shared.lock().pump(&shared.out);
        tokio::select! {
            packet = from_tun.recv() => {
                let Some(packet) = packet else { break };
                let mut st = shared.lock();
                let mut next = Some(packet);
                // Take everything already queued before running the stack.
                while let Some(packet) = next {
                    match classify(&packet) {
                        Classified::Udp(d) => {
                            let _ = udp_tx.try_send(d);
                        }
                        Classified::TcpSyn { src, dst } => {
                            st.prepare_listener(src, dst);
                            st.device.push_rx(packet);
                        }
                        Classified::Other => st.device.push_rx(packet),
                        Classified::Drop => {}
                    }
                    next = from_tun.try_recv().ok();
                }
            }
            _ = shared.wake.notified() => {}
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl QueueDevice {
    fn push_rx(&mut self, packet: Vec<u8>) {
        if self.rx.len() < QUEUE {
            self.rx.push_back(packet);
        }
    }
}

struct QueueRx(Vec<u8>);
struct QueueTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for QueueRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for QueueTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0u8; len];
        let r = f(&mut packet);
        self.0.push_back(packet);
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = QueueRx;
    type TxToken<'a> = QueueTx<'a>;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((QueueRx(packet), QueueTx(&mut self.tx)))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.tx.len() >= QUEUE {
            None
        } else {
            Some(QueueTx(&mut self.tx))
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// A TCP connection from an application, accepted on its intended destination.
pub struct TcpStream {
    shared: Arc<Shared>,
    handle: SocketHandle,
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
            this.shared.wake.notify_one();
            return Poll::Ready(Ok(()));
        }
        if !sock.may_recv() {
            return Poll::Ready(Ok(()));
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
        this.shared.lock().sockets.get_mut::<tcp::Socket>(this.handle).close();
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

#[cfg(test)]
mod tests;
