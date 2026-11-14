//! End to end: proxy client → superNET engine → rules → WireGuard → test node.
//! Everything runs on 127.0.0.1; no network access or admin rights needed.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use supernet_core::config::{GroupConfig, GroupKind};
use supernet_core::{dns, Engine, Mode, Profile};
use supernet_testnode::TestNode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const T: Duration = Duration::from_secs(20);

/// A DNS server for direct lookups that records every name it is asked.
async fn recording_dns() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else { continue };
            if let Some(q) = dns::parse_query(&buf[..n]) {
                log.lock().unwrap().push(q.name.clone());
                let answer = dns::build_answer(&buf[..n], &q, &["127.0.0.1".parse::<IpAddr>().unwrap()], 60);
                let _ = sock.send_to(&answer, from).await;
            }
        }
    });
    (addr, seen)
}

/// A local HTTP server reached through DIRECT.
async fn direct_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let body = "direct-ok\n";
                let _ = s
                    .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
                    .await;
            });
        }
    });
    port
}

async fn http_get(proxy: SocketAddr, url: &str) -> String {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    let host = url.trim_start_matches("http://").split('/').next().unwrap();
    s.write_all(format!("GET {url} HTTP/1.1\r\nHost: {host}\r\nProxy-Connection: keep-alive\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = String::new();
    tokio::time::timeout(T, s.read_to_string(&mut out)).await.unwrap().unwrap();
    out
}

/// SOCKS5 CONNECT by domain; returns the stream or the reply code.
async fn socks5(proxy: SocketAddr, domain: &str, port: u16) -> Result<TcpStream, u8> {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 0]);
    let mut req = vec![5, 1, 0, 3, domain.len() as u8];
    req.extend_from_slice(domain.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    tokio::time::timeout(T, s.read_exact(&mut reply)).await.unwrap().unwrap();
    if reply[1] == 0 {
        Ok(s)
    } else {
        Err(reply[1])
    }
}

async fn http_connect(proxy: SocketAddr, target: &str) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tokio::time::timeout(T, s.read_exact(&mut b)).await.unwrap().unwrap();
        head.push(b[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
    s
}

async fn echo_round_trip(s: TcpStream, size: usize) {
    let payload: Vec<u8> = (0..size).map(|i| (i * 7 % 253) as u8).collect();
    let (mut rd, mut wr) = s.into_split();
    let data = payload.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&data).await.unwrap();
        wr.shutdown().await.unwrap();
    });
    let mut got = Vec::with_capacity(size);
    tokio::time::timeout(Duration::from_secs(60), rd.read_to_end(&mut got)).await.unwrap().unwrap();
    writer.await.unwrap();
    assert_eq!(got.len(), payload.len());
    assert!(got == payload, "echo mismatch");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_routes_through_wireguard_node() {
    let node = TestNode::start(
        "127.0.0.1:0".parse().unwrap(),
        supernet_wg::generate_private_key(),
        supernet_wg::generate_private_key(),
    )
    .await
    .unwrap();
    let (dns_addr, dns_seen) = recording_dns().await;
    let direct_port = direct_server().await;

    let profile = Profile {
        listen: "127.0.0.1:0".parse().unwrap(),
        dns: supernet_core::config::DnsConfig { direct: vec![format!("udp://{dns_addr}")] },
        nodes: vec![node.client_node("测试节点")],
        groups: vec![GroupConfig { name: "代理".into(), kind: GroupKind::Select, nodes: vec!["测试节点".into(), "DIRECT".into()] }],
        selected: BTreeMap::new(),
        rules: vec![
            "DOMAIN,blocked.test,REJECT".into(),
            "DOMAIN-SUFFIX,example.com,代理".into(),
            "IP-CIDR,10.66.0.0/24,代理,no-resolve".into(),
            "MATCH,DIRECT".into(),
        ],
        ..Profile::default()
    };
    let (engine, warnings) = Engine::new(profile, None).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    let proxy = engine.start().await.unwrap();

    // Plain HTTP through the node; the domain is resolved by the node's DNS.
    let page = http_get(proxy, "http://www.example.com/hello?x=1").await;
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert!(page.contains("superNET test node"), "{page}");
    assert!(page.contains("host: www.example.com"), "{page}");
    assert!(page.contains("path: /hello?x=1"), "{page}");

    // SOCKS5 by domain, 4 MiB echo: checks integrity through both stacks.
    let s = socks5(proxy, "echo.example.com", 7).await.expect("socks5 connect");
    echo_round_trip(s, 4 * 1024 * 1024).await;

    // HTTP CONNECT to an address in the node's network (IP rule).
    let s = http_connect(proxy, "10.66.0.1:7").await;
    echo_round_trip(s, 64 * 1024).await;

    // Direct traffic never reaches the node and uses the direct DNS.
    let hits_before = node.http_requests();
    let page = http_get(proxy, &format!("http://direct.test:{direct_port}/")).await;
    assert!(page.contains("direct-ok"), "{page}");
    assert_eq!(node.http_requests(), hits_before);
    {
        let seen = dns_seen.lock().unwrap();
        assert!(seen.iter().any(|n| n == "direct.test"), "{seen:?}");
        assert!(!seen.iter().any(|n| n.ends_with("example.com")), "proxied names leaked to local DNS: {seen:?}");
    }

    // REJECT rule.
    assert_eq!(socks5(proxy, "blocked.test", 80).await.err(), Some(0x02));
    assert!(http_get(proxy, "http://blocked.test/").await.starts_with("HTTP/1.1 403"));

    // Route explanation, modes and group selection.
    let r = engine.explain("www.example.com:443").await.unwrap();
    assert_eq!((r.outbound.as_str(), r.chain.as_str()), ("测试节点", "代理 → 测试节点"));
    assert_eq!(r.rule, "DOMAIN-SUFFIX,example.com");
    engine.set_mode(Mode::Global);
    assert_eq!(engine.explain("direct.test:80").await.unwrap().outbound, "测试节点");
    engine.set_mode(Mode::Direct);
    assert_eq!(engine.explain("www.example.com:443").await.unwrap().outbound, "DIRECT");
    engine.set_mode(Mode::Rule);
    engine.select("代理", "DIRECT").unwrap();
    assert_eq!(engine.explain("www.example.com:443").await.unwrap().chain, "代理 → DIRECT");
    engine.select("代理", "测试节点").unwrap();
    assert!(engine.select("代理", "不存在").is_err());

    // Latency probe against the node's /generate_204.
    let mut profile = engine.profile();
    profile.test_url = "http://probe.example.com/generate_204".into();
    engine.apply(profile).await.unwrap();
    let rtt = engine.probe("测试节点").await.unwrap();
    assert!(rtt < Duration::from_secs(5), "{rtt:?}");

    let nodes = engine.nodes();
    assert!(nodes[0].active && nodes[0].since_handshake_secs.is_some(), "{nodes:?}");
    let status = engine.status().await;
    assert!(status.total_download >= 4 * 1024 * 1024, "{status:?}");
    assert!(status.total_upload >= 4 * 1024 * 1024, "{status:?}");

    // Finished connections leave the list.
    let mut left = usize::MAX;
    for _ in 0..50 {
        left = engine.connections().len();
        if left == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(left, 0, "{:?}", engine.connections());

    // A live connection shows up and can be closed from the engine.
    let mut s = socks5(proxy, "echo.example.com", 7).await.unwrap();
    s.write_all(b"hi").await.unwrap();
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await.unwrap();
    let conns = engine.connections();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].target, "echo.example.com:7");
    assert!(engine.close_connection(conns[0].id));
    let mut rest = Vec::new();
    let n = tokio::time::timeout(T, s.read_to_end(&mut rest)).await.unwrap().unwrap_or(0);
    assert_eq!(n, 0);

    engine.stop().await;
    assert!(TcpStream::connect(proxy).await.is_err(), "listener still open after stop");
    assert!(engine.logs(0).iter().any(|l| l.message.contains("www.example.com:80 → 代理 → 测试节点")));
}
