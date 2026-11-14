use super::*;
use smoltcp::iface::SocketSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// An application-side TCP/IP stack talking to the NetStack over its ports,
/// like a program behind a TUN device.
struct App {
    iface: Interface,
    device: QueueDevice,
    sockets: SocketSet<'static>,
    epoch: Instant,
}

impl App {
    fn new() -> App {
        let mut device = QueueDevice { rx: VecDeque::new(), tx: VecDeque::new(), mtu: 1500 };
        let mut iface = Interface::new(IfaceConfig::new(HardwareAddress::Ip), &mut device, SmolInstant::ZERO);
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::v4(10, 1, 0, 2), 24));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(10, 1, 0, 1));
        App { iface, device, sockets: SocketSet::new(Vec::new()), epoch: Instant::now() }
    }

    fn poll(&mut self, ports: &mut PacketPorts) {
        while let Ok(p) = ports.from_stack.try_recv() {
            self.device.rx.push_back(p);
        }
        let now = SmolInstant::from_micros(self.epoch.elapsed().as_micros() as i64);
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        while let Some(p) = self.device.tx.pop_front() {
            ports.to_stack.try_send(p).unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_to_any_destination_is_accepted_and_relayed() {
    let (stack, mut ports, _udp) = NetStack::new(1500);
    let mut app = App::new();
    let dests: Vec<SocketAddr> = vec!["203.0.113.10:80".parse().unwrap(), "198.18.4.5:443".parse().unwrap()];
    let mut handles = Vec::new();
    for (i, dst) in dests.iter().enumerate() {
        let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 65536]), tcp::SocketBuffer::new(vec![0; 65536]));
        let IpAddr::V4(ip) = dst.ip() else { unreachable!() };
        s.connect(app.iface.context(), (ip, dst.port()), 40000 + i as u16).unwrap();
        handles.push(app.sockets.add(s));
    }

    // Accept both on the stack side and echo whatever arrives.
    let server = tokio::spawn(async move {
        let mut seen = Vec::new();
        for _ in 0..2 {
            let (mut stream, src, dst) = stack.accept().await.unwrap();
            seen.push((src, dst));
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    stream.write_all(&buf[..n]).await.unwrap();
                }
            });
        }
        (stack, seen)
    });

    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut sent = vec![0usize; 2];
    let mut got = vec![Vec::new(); 2];
    let deadline = Instant::now() + Duration::from_secs(20);
    while got.iter().any(|g| g.len() < payload.len()) {
        assert!(Instant::now() < deadline, "relay stalled: {:?}", got.iter().map(Vec::len).collect::<Vec<_>>());
        app.poll(&mut ports);
        for (i, h) in handles.iter().enumerate() {
            let s = app.sockets.get_mut::<tcp::Socket>(*h);
            if s.can_send() && sent[i] < payload.len() {
                sent[i] += s.send_slice(&payload[sent[i]..]).unwrap();
            }
            if s.can_recv() {
                let mut buf = [0u8; 16384];
                let n = s.recv_slice(&mut buf).unwrap();
                got[i].extend_from_slice(&buf[..n]);
            }
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    for g in &got {
        assert!(*g == payload, "data differs");
    }
    let (_stack, seen) = server.await.unwrap();
    let mut dsts: Vec<SocketAddr> = seen.iter().map(|(_, d)| *d).collect();
    dsts.sort();
    let mut expected = dests.clone();
    expected.sort();
    assert_eq!(dsts, expected, "the stack must report the original destinations");
    assert!(seen.iter().all(|(src, _)| src.ip() == "10.1.0.2".parse::<IpAddr>().unwrap()));
}

#[tokio::test]
async fn udp_is_delivered_and_replies_are_built() {
    let (stack, mut ports, mut udp) = NetStack::new(1500);
    let src: SocketAddr = "10.1.0.2:5353".parse().unwrap();
    let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
    ports.to_stack.send(build_udp(src, dst, b"query").unwrap()).await.unwrap();
    let d = tokio::time::timeout(Duration::from_secs(5), udp.recv()).await.unwrap().unwrap();
    assert_eq!((d.src, d.dst, d.payload.as_slice()), (src, dst, &b"query"[..]));

    stack.send_udp(dst, src, b"answer").unwrap();
    let packet = tokio::time::timeout(Duration::from_secs(5), ports.from_stack.recv()).await.unwrap().unwrap();
    match classify(&packet) {
        Classified::Udp(r) => assert_eq!((r.src, r.dst, r.payload.as_slice()), (dst, src, &b"answer"[..])),
        _ => panic!("expected a UDP packet"),
    }
    // Checksums must be valid for the OS to accept the packet.
    let ip = Ipv4Packet::new_checked(&packet).unwrap();
    assert!(ip.verify_checksum());
    let u = UdpPacket::new_checked(ip.payload()).unwrap();
    assert!(u.verify_checksum(&IpAddress::Ipv4(ip.src_addr()), &IpAddress::Ipv4(ip.dst_addr())));

    let v6a: SocketAddr = "[fd00::2]:4000".parse().unwrap();
    let v6b: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    assert!(matches!(classify(&build_udp(v6a, v6b, b"x").unwrap()), Classified::Udp(_)));
    assert!(build_udp(src, v6b, b"x").is_err());
}

#[test]
fn multicast_and_broadcast_are_never_relayed() {
    let me: SocketAddr = "172.19.0.1:50000".parse().unwrap();
    for dst in ["224.0.0.251:5353", "239.255.255.250:1900", "255.255.255.255:67", "169.254.1.1:80", "[ff02::fb]:5353", "[fe80::1]:53"] {
        let dst: SocketAddr = dst.parse().unwrap();
        let src = if dst.is_ipv6() { "[fd00::1]:50000".parse().unwrap() } else { me };
        let packet = build_udp(src, dst, b"x").unwrap();
        assert!(matches!(classify(&packet), Classified::Drop), "{dst} must be dropped");
    }
    let packet = build_udp(me, "223.5.5.5:53".parse().unwrap(), b"x").unwrap();
    assert!(matches!(classify(&packet), Classified::Udp(_)));
}

/// Prints what TUN mode would pin to on this machine; another TUN holding the
/// default route must be reported, never silently used.
#[cfg(windows)]
#[test]
fn default_interface_is_physical_or_explained() {
    match crate::sysnet::default_interface_index() {
        Ok(i) => println!("default interface index {i}"),
        Err(e) => {
            println!("refused: {e}");
            assert!(e.to_string().contains("请先关闭"), "{e}");
        }
    }
}

#[test]
fn default_route_is_read_from_proc() {
    let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
    assert_eq!(crate::sysnet::default_route_interface(table).as_deref(), Some("eth0"));
    assert_eq!(crate::sysnet::default_route_interface("Iface\n"), None);
}
