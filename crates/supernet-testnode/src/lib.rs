//! A WireGuard node that runs anywhere without root: it terminates the tunnel
//! in userspace and serves a few things on its own tunnel address 10.66.0.1:
//!
//! * TCP 7  – echo
//! * UDP 7  – echo
//! * TCP 80 – HTTP: `/generate_204` answers 204, anything else a text page
//!   naming the requested host and path
//! * UDP 53 – DNS: every A query resolves to 10.66.0.1
//!
//! It cannot reach the internet; it exists to test clients end to end.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use supernet_core::config::{encode_key, NodeConfig, NodeKind, WireGuardNode};
use supernet_core::dns;
use supernet_wg::{public_key, TunnelConfig, WgTunnel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

pub const NODE_IP: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);
pub const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);

pub struct TestNode {
    _tunnel: Arc<WgTunnel>,
    udp_addr: SocketAddr,
    server_key: [u8; 32],
    client_key: [u8; 32],
    http_requests: Arc<AtomicU64>,
    tasks: Vec<JoinHandle<()>>,
}

impl TestNode {
    pub async fn start(listen: SocketAddr, server_key: [u8; 32], client_key: [u8; 32]) -> io::Result<TestNode> {
        let tunnel = Arc::new(
            WgTunnel::new(TunnelConfig {
                private_key: server_key,
                peer_public_key: public_key(&client_key),
                preshared_key: None,
                endpoint: None,
                bind: Some(listen),
                addresses: vec![(IpAddr::V4(NODE_IP), 24)],
                mtu: 1420,
                persistent_keepalive: None,
            })
            .await?,
        );
        let udp_addr = tunnel.local_udp_addr()?;
        let http_requests = Arc::new(AtomicU64::new(0));
        let mut tasks = Vec::new();

        let echo = tunnel.listen_tcp(7, 16)?;
        tasks.push(tokio::spawn(async move {
            while let Ok((mut stream, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 32 * 1024];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = stream.shutdown().await;
                });
            }
        }));

        let http = tunnel.listen_tcp(80, 16)?;
        let hits = http_requests.clone();
        tasks.push(tokio::spawn(async move {
            while let Ok((stream, _)) = http.accept().await {
                hits.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(serve_http(stream));
            }
        }));

        let udp_echo = tunnel.bind_udp(Some(7))?;
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = udp_echo.recv_from(&mut buf).await {
                let _ = udp_echo.send_to(&buf[..n], from).await;
            }
        }));

        let dns_sock = tunnel.bind_udp(Some(53))?;
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            while let Ok((n, from)) = dns_sock.recv_from(&mut buf).await {
                let query = &buf[..n];
                if let Some(q) = dns::parse_query(query) {
                    let answer = dns::build_answer(query, &q, &[IpAddr::V4(NODE_IP)], 60);
                    let _ = dns_sock.send_to(&answer, from).await;
                }
            }
        }));

        Ok(TestNode { _tunnel: tunnel, udp_addr, server_key, client_key, http_requests, tasks })
    }

    /// The UDP address clients should use as Endpoint.
    pub fn endpoint(&self) -> SocketAddr {
        if self.udp_addr.ip().is_unspecified() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.udp_addr.port())
        } else {
            self.udp_addr
        }
    }

    /// Client node settings for this server.
    pub fn client_node(&self, name: &str) -> NodeConfig {
        NodeConfig {
            name: name.to_string(),
            kind: NodeKind::Wireguard(WireGuardNode {
                endpoint: self.endpoint().to_string(),
                private_key: encode_key(&self.client_key),
                public_key: encode_key(&public_key(&self.server_key)),
                preshared_key: None,
                address: vec![format!("{CLIENT_IP}/32").parse().unwrap()],
                allowed_ips: supernet_core::config::default_allowed_ips(),
                dns: vec![IpAddr::V4(NODE_IP)],
                mtu: supernet_core::config::default_mtu(),
                keepalive: Some(25),
            }),
        }
    }

    /// Number of HTTP connections served on port 80.
    pub fn http_requests(&self) -> u64 {
        self.http_requests.load(Ordering::Relaxed)
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

async fn serve_http(mut stream: supernet_wg::TcpStream) {
    let mut head = Vec::new();
    let mut buf = [0u8; 2048];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
        if head.len() > 64 * 1024 {
            return;
        }
    }
    let text = String::from_utf8_lossy(&head);
    let path = text.split_whitespace().nth(1).unwrap_or("/").to_string();
    let host = text
        .lines()
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("host")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_default();
    let response = if path == "/generate_204" {
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
    } else {
        let body = format!("superNET test node\nhost: {host}\npath: {path}\n");
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    };
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}
