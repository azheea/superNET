//! TUN mode without a real adapter: a small TCP/IP stack plays the
//! applications behind the TUN device and talks to the engine's packet ports.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use supernet_core::config::{GroupConfig, GroupKind};
use supernet_core::{dns, Engine, Profile};
use supernet_netstack::PacketPorts;
use supernet_testnode::TestNode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

struct Queue {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}
struct QRx(Vec<u8>);
struct QTx<'a>(&'a mut VecDeque<Vec<u8>>);
impl RxToken for QRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for QTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut p = vec![0u8; len];
        let r = f(&mut p);
        self.0.push_back(p);
        r
    }
}
impl Device for Queue {
    type RxToken<'a> = QRx;
    type TxToken<'a> = QTx<'a>;
    fn receive(&mut self, _: SmolInstant) -> Option<(QRx, QTx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((QRx(p), QTx(&mut self.tx)))
    }
    fn transmit(&mut self, _: SmolInstant) -> Option<QTx<'_>> {
        Some(QTx(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = 1500;
        c
    }
}

/// "Applications" behind the TUN device, with address 172.19.0.2.
struct Apps {
    iface: Interface,
    dev: Queue,
    sockets: SocketSet<'static>,
    epoch: Instant,
    ports: PacketPorts,
}

impl Apps {
    fn new(ports: PacketPorts) -> Apps {
        let mut dev = Queue { rx: VecDeque::new(), tx: VecDeque::new() };
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, SmolInstant::ZERO);
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::v4(172, 19, 0, 2), 30));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(172, 19, 0, 1));
        Apps { iface, dev, sockets: SocketSet::new(Vec::new()), epoch: Instant::now(), ports }
    }

    async fn step(&mut self) {
        while let Ok(p) = self.ports.from_stack.try_recv() {
            self.dev.rx.push_back(p);
        }
        let now = SmolInstant::from_micros(self.epoch.elapsed().as_micros() as i64);
        self.iface.poll(now, &mut self.dev, &mut self.sockets);
        while let Some(p) = self.dev.tx.pop_front() {
            self.ports.to_stack.send(p).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    fn udp(&mut self, port: u16) -> SocketHandle {
        let mut s = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 16384]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 16384]),
        );
        s.bind(port).unwrap();
        self.sockets.add(s)
    }

    /// Send one datagram and wait for one reply: (payload, from).
    async fn udp_exchange(&mut self, h: SocketHandle, to: SocketAddr, data: &[u8]) -> (Vec<u8>, SocketAddr) {
        self.sockets.get_mut::<udp::Socket>(h).send_slice(data, IpEndpoint::from(to)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            assert!(Instant::now() < deadline, "no UDP reply from {to}");
            self.step().await;
            let s = self.sockets.get_mut::<udp::Socket>(h);
            if s.can_recv() {
                let mut buf = [0u8; 4096];
                let (n, meta) = s.recv_slice(&mut buf).unwrap();
                return (buf[..n].to_vec(), SocketAddr::from(meta.endpoint));
            }
        }
    }

    /// Resolve through the TUN's DNS (any server address works: it is hijacked).
    async fn resolve(&mut self, name: &str) -> Ipv4Addr {
        let h = self.udp(5353);
        let query = dns::build_query(42, name, dns::TYPE_A).unwrap();
        let (answer, _) = self.udp_exchange(h, "8.8.8.8:53".parse().unwrap(), &query).await;
        self.sockets.remove(h);
        let (ips, _) = dns::parse_response(42, &answer).unwrap();
        match ips.first() {
            Some(IpAddr::V4(v4)) => *v4,
            other => panic!("unexpected answer {other:?}"),
        }
    }

    /// One HTTP/1.1 request over a fresh TCP connection; returns the response.
    async fn http(&mut self, dst: SocketAddr, host: &str, local_port: u16) -> String {
        let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 65536]), tcp::SocketBuffer::new(vec![0; 65536]));
        let IpAddr::V4(ip) = dst.ip() else { panic!() };
        s.connect(self.iface.context(), (ip, dst.port()), local_port).unwrap();
        let h = self.sockets.add(s);
        let request = format!("GET /via-tun HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        let (mut sent, mut out) = (false, Vec::new());
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(Instant::now() < deadline, "HTTP to {dst} stalled: {}", String::from_utf8_lossy(&out));
            self.step().await;
            let s = self.sockets.get_mut::<tcp::Socket>(h);
            if !sent && s.can_send() {
                s.send_slice(request.as_bytes()).unwrap();
                sent = true;
            }
            if s.can_recv() {
                let mut buf = [0u8; 8192];
                let n = s.recv_slice(&mut buf).unwrap();
                out.extend_from_slice(&buf[..n]);
            }
            if sent && !s.may_recv() && !out.is_empty() {
                break;
            }
        }
        self.sockets.remove(h);
        String::from_utf8_lossy(&out).into_owned()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tun_mode_routes_tcp_udp_and_dns() {
    let node = TestNode::start("127.0.0.1:0".parse().unwrap(), supernet_wg::generate_private_key(), supernet_wg::generate_private_key())
        .await
        .unwrap();

    // Direct targets on this machine.
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = http.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = [0u8; 2048];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\ndirect-ok\n").await;
            });
        }
    });
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        loop {
            let (n, from) = echo.recv_from(&mut b).await.unwrap();
            echo.send_to(&b[..n], from).await.unwrap();
        }
    });

    let profile = Profile {
        nodes: vec![node.client_node("测试节点")],
        groups: vec![GroupConfig { name: "代理".into(), kind: GroupKind::Select, nodes: vec!["测试节点".into()] }],
        selected: BTreeMap::new(),
        rules: vec!["DOMAIN-SUFFIX,example.com,代理".into(), "MATCH,DIRECT".into()],
        ..Profile::default()
    };
    let (engine, _) = Engine::new(profile, None).unwrap();
    let ports = engine.start_tun(1500).await.unwrap();
    let mut apps = Apps::new(ports);

    // DNS is answered with fake addresses.
    let fake = apps.resolve("www.example.com").await;
    assert!(supernet_core::tun::FakeDns::contains(fake), "{fake}");
    assert_eq!(apps.resolve("www.example.com").await, fake, "stable mapping");

    // TCP by fake address → rule by domain → WireGuard node.
    let page = apps.http(SocketAddr::new(IpAddr::V4(fake), 80), "www.example.com", 41000).await;
    assert!(page.contains("superNET test node") && page.contains("host: www.example.com"), "{page}");

    // TCP to a plain address → MATCH,DIRECT.
    let page = apps.http(SocketAddr::new("127.0.0.1".parse().unwrap(), http_port), "local", 41001).await;
    assert!(page.contains("direct-ok"), "{page}");

    // UDP direct, and UDP through the node to its echo service.
    let h = apps.udp(6000);
    let (reply, from) = apps.udp_exchange(h, echo_addr, b"udp-direct").await;
    assert_eq!((reply.as_slice(), from), (&b"udp-direct"[..], echo_addr));
    let echo_fake = apps.resolve("echo.example.com").await;
    let to = SocketAddr::new(IpAddr::V4(echo_fake), 7);
    let (reply, from) = apps.udp_exchange(h, to, b"udp-via-node").await;
    assert_eq!((reply.as_slice(), from), (&b"udp-via-node"[..], to), "replies come from the address the app used");

    let logs: Vec<String> = engine.logs(0).into_iter().map(|l| l.message).collect();
    assert!(logs.iter().any(|l| l.contains("www.example.com:80 → 代理 → 测试节点")), "{logs:?}");
    assert!(logs.iter().any(|l| l.contains("echo.example.com:7") && l.contains("[UDP]")), "{logs:?}");

    engine.stop_tun().await;
    assert!(!engine.tun_active().await);
}
