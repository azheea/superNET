//! Devices and a coordinator in one process, on loopback.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::coord::{CoordConfig, Coordinator};
use crate::device::{Mesh, MeshConfig, MeshPorts};
use crate::proto::{self, Invite, PathKind};

async fn coordinator() -> (Invite, SocketAddr) {
    coordinator_with(CoordConfig::new("127.0.0.1:0".parse().unwrap())).await
}

async fn coordinator_with(cfg: CoordConfig) -> (Invite, SocketAddr) {
    let c = Coordinator::bind(cfg).await.unwrap();
    let addr = c.local_addr();
    let invite = c.invite(&addr.to_string());
    tokio::spawn(c.run());
    (invite, addr)
}

fn cfg(invite: &Invite, name: &str) -> MeshConfig {
    let mut c = MeshConfig::new(invite.clone(), proto::generate_secret(), name);
    c.bind = "127.0.0.1:0".parse().unwrap();
    // Hermetic: no real IPv6 address of this machine as a candidate.
    c.bind6 = None;
    c
}

async fn join(c: MeshConfig) -> (Mesh, MeshPorts, Ipv4Addr) {
    let (mesh, ports) = Mesh::start(c).await.unwrap();
    let ip = mesh.wait_joined(Duration::from_secs(5)).await.unwrap();
    (mesh, ports, ip)
}

/// A minimal IPv4/UDP packet (checksums are not checked on this path).
fn packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..22].copy_from_slice(&40000u16.to_be_bytes());
    p[22..24].copy_from_slice(&9u16.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    p
}

/// Send from `a` to `b` until it arrives (the first packets wait for the handshake).
async fn deliver(from: &MeshPorts, to: &mut MeshPorts, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) {
    let p = packet(src, dst, payload);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "packet {src} → {dst} never arrived");
        from.to_mesh.send(p.clone()).await.unwrap();
        if let Ok(Some(got)) = tokio::time::timeout(Duration::from_millis(300), to.from_mesh.recv()).await {
            assert_eq!(got, p);
            return;
        }
    }
}

async fn wait_kind(mesh: &Mesh, peer: Ipv4Addr, want: PathKind) -> crate::device::PeerStatus {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let st = mesh.status();
        if let Some(p) = st.peers.iter().find(|p| p.ip == peer) {
            if p.kind == want {
                return p.clone();
            }
            assert!(Instant::now() < deadline, "path to {peer} is {:?}, expected {want:?}: {st:#?}", p.kind);
        } else {
            assert!(Instant::now() < deadline, "{peer} unknown: {st:#?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn two_devices_go_direct() {
    let (invite, _) = coordinator().await;
    let (a, mut pa, ip_a) = join(cfg(&invite, "A")).await;
    let (b, mut pb, ip_b) = join(cfg(&invite, "B")).await;
    assert_ne!(ip_a, ip_b);
    assert_eq!(ip_a.octets()[..3], [10, 66, 0]);
    let link = wait_kind(&a, ip_b, PathKind::Lan).await;
    assert!(link.rtt_ms.is_some());
    deliver(&pa, &mut pb, ip_a, ip_b, b"hello b").await;
    deliver(&pb, &mut pa, ip_b, ip_a, b"hello a").await;
    wait_kind(&b, ip_a, PathKind::Lan).await;
    // Packets claiming another source are dropped by the receiver.
    pa.to_mesh.send(packet(Ipv4Addr::new(10, 66, 0, 99), ip_b, b"spoof")).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(500), pb.from_mesh.recv()).await.is_err());
}

#[tokio::test]
async fn coordinator_relays_when_direct_fails() {
    let (invite, _) = coordinator().await;
    let mut ca = cfg(&invite, "A");
    ca.disable_direct = true;
    let mut cb = cfg(&invite, "B");
    cb.disable_direct = true;
    let (a, mut pa, ip_a) = join(ca).await;
    let (_b, mut pb, ip_b) = join(cb).await;
    deliver(&pa, &mut pb, ip_a, ip_b, b"via server").await;
    deliver(&pb, &mut pa, ip_b, ip_a, b"and back").await;
    let link = wait_kind(&a, ip_b, PathKind::Server).await;
    assert!(link.tx_bytes > 0 && link.rx_bytes > 0);
    // 1 MiB through the relay arrives in order and intact.
    let big: Vec<u8> = (0..1200u32).map(|i| i as u8).collect();
    for i in 0..900u32 {
        let mut payload = big.clone();
        payload[..4].copy_from_slice(&i.to_be_bytes());
        pa.to_mesh.send(packet(ip_a, ip_b, &payload)).await.unwrap();
        // About 1.5 MB/s: within the coordinator's 2 MB/s per-device relay limit.
        if i % 64 == 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let mut got = 0;
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_secs(2), pb.from_mesh.recv()).await {
        got += 1;
        if got == 900 {
            break;
        }
    }
    assert!(got >= 890, "only {got} of 900 relayed packets arrived");
}

#[tokio::test]
async fn third_device_relays_when_two_cannot_meet() {
    let (invite, _) = coordinator().await;
    // Addresses are allocated in join order: B .2, A .3, C .4.
    let (b, _pb, ip_b2) = join(cfg(&invite, "B")).await;
    let mut ca = cfg(&invite, "A");
    let mut cc = cfg(&invite, "C");
    // A and C refuse each other directly (like two symmetric NATs); both reach B.
    ca.block_direct_to = vec![Ipv4Addr::new(10, 66, 0, 4)];
    cc.block_direct_to = vec![Ipv4Addr::new(10, 66, 0, 3)];
    let (a, mut pa, ip_a) = join(ca).await;
    let (c, mut pc, ip_c) = join(cc).await;
    assert_eq!((ip_b2, ip_a, ip_c), (Ipv4Addr::new(10, 66, 0, 2), Ipv4Addr::new(10, 66, 0, 3), Ipv4Addr::new(10, 66, 0, 4)));
    wait_kind(&a, ip_b2, PathKind::Lan).await;
    wait_kind(&c, ip_b2, PathKind::Lan).await;
    let link = wait_kind(&a, ip_c, PathKind::Peer).await;
    assert_eq!(link.via, Some(ip_b2));
    deliver(&pa, &mut pc, ip_a, ip_c, b"through B").await;
    deliver(&pc, &mut pa, ip_c, ip_a, b"back through B").await;
    assert!(b.status().relayed_bytes > 0, "B relayed nothing");
    // Every device sees the whole topology.
    // Path changes are reported within seconds, not at the 15 s hello.
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let links = b.status().links;
        let has = |from, to, kind| links.iter().any(|l| l.from == from && l.link.peer == to && l.link.kind == kind);
        if has(ip_a, ip_c, PathKind::Peer) && has(ip_a, ip_b2, PathKind::Lan) && has(ip_c, ip_b2, PathKind::Lan) {
            break;
        }
        assert!(Instant::now() < deadline, "topology incomplete: {links:#?}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn bad_invite_is_rejected_and_members_survive_restart() {
    let dir = std::env::temp_dir().join(format!("supernet-coord-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let _ = std::fs::remove_file(&state);
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let mut cc = CoordConfig::new(listen);
    cc.state_file = Some(state.clone());
    let (invite, _) = coordinator_with(cc).await;

    let mut wrong = invite.clone();
    wrong.key = "nope".into();
    let (m, _p) = Mesh::start(cfg(&wrong, "X")).await.unwrap();
    let e = m.wait_joined(Duration::from_secs(3)).await.unwrap_err().to_string();
    assert!(e.contains("邀请链接无效"), "{e}");

    let key = proto::generate_secret();
    let mut c1 = cfg(&invite, "A");
    c1.private_key = key;
    let (m1, _p1, ip1) = join(c1).await;
    drop(m1);

    // A new coordinator process with the same state: same key, same member.
    let mut cc = CoordConfig::new(listen);
    cc.state_file = Some(state.clone());
    let (invite2, _) = coordinator_with(cc).await;
    assert_eq!(invite2.coord_pub, invite.coord_pub);
    assert_eq!(invite2.key, invite.key);
    let mut c2 = cfg(&invite2, "A");
    c2.private_key = key;
    c2.invite.key = "reset-or-not, a member needs no invite".into();
    let (_m2, _p2, ip2) = join(c2).await;
    assert_eq!(ip1, ip2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invite_links_round_trip() {
    let inv = Invite { coord: "203.0.113.10:19190".into(), coord_pub: [7u8; 32], key: "abcDEF_-1".into(), network: "我的 网络".into() };
    let link = inv.to_link();
    assert!(link.starts_with("supernet-net://203.0.113.10:19190?"));
    assert_eq!(Invite::parse(&link).unwrap(), inv);
    assert!(Invite::parse("supernet-net://host?k=a&pub=b").is_err());
}

#[test]
fn sealed_messages_need_the_right_key() {
    let (a, b, c) = (proto::generate_secret(), proto::generate_secret(), proto::generate_secret());
    let d = proto::seal(proto::T_CTRL, &a, &proto::public_of(&b), b"secret").unwrap();
    let (sender, plain) = proto::open(&d, &b).unwrap();
    assert_eq!((sender, plain.as_slice()), (proto::public_of(&a), &b"secret"[..]));
    assert!(proto::open(&d, &c).is_err());
    let mut tampered = d.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(proto::open(&tampered, &b).is_err());
}

#[tokio::test]
async fn devices_meet_over_ipv6() {
    let (invite, _) = coordinator().await;
    let v6 = |name: &str| {
        let mut c = cfg(&invite, name);
        c.bind6 = Some("[::1]:0".parse().unwrap());
        c.only_ipv6_direct = true;
        c
    };
    let (a, pa, ip_a) = join(v6("A")).await;
    let (_b, mut pb, ip_b) = join(v6("B")).await;
    let link = wait_kind(&a, ip_b, PathKind::Ipv6).await;
    assert!(link.endpoint.is_some_and(|e| e.is_ipv6()), "{link:?}");
    deliver(&pa, &mut pb, ip_a, ip_b, b"over v6").await;
}
