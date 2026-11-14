//! A small Hysteria2 server for tests: TLS 1.3 + ALPN h3, answers the
//! HTTP/3 auth request with a fixed status, and relays `0x401` TCP requests
//! to real local sockets.

use super::*;
use rustls::pki_types::PrivateKeyDer;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

struct TestServer {
    addr: SocketAddr,
    cert_sha256: [u8; 32],
}

/// QPACK header block for `:status <code>`: literal with a static name
/// reference (index 24, a `:status` entry) and a plain string value.
fn status_headers_frame(code: u16) -> Vec<u8> {
    let value = code.to_string();
    let mut block = vec![0x00, 0x00, 0x5F, 24 - 15, value.len() as u8];
    block.extend_from_slice(value.as_bytes());
    // `hysteria-udp: true` as a literal name/value (12-byte name: 0x27, 0x05).
    block.extend_from_slice(&[0x27, 12 - 7]);
    block.extend_from_slice(b"hysteria-udp");
    block.push(4);
    block.extend_from_slice(b"true");
    let mut frame = Vec::new();
    put_varint(&mut frame, 0x01); // HEADERS
    put_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    frame
}

async fn start_server(auth_status: u16) -> TestServer {
    let certified = rcgen::generate_simple_self_signed(vec!["hy2.test".to_string()]).unwrap();
    let cert_der = certified.cert.der().clone();
    let cert_sha256: [u8; 32] = Sha256::digest(cert_der.as_ref()).into();
    let key = PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap()));
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                // Our HTTP/3 control stream with empty SETTINGS.
                if let Ok(mut ctl) = conn.open_uni().await {
                    let _ = ctl.write_all(&[0x00, 0x04, 0x00]).await;
                    std::mem::forget(ctl); // keep it open for the connection's life
                }
                let uni = conn.clone();
                tokio::spawn(async move {
                    while let Ok(mut s) = uni.accept_uni().await {
                        tokio::spawn(async move { while let Ok(Some(_)) = s.read_chunk(4096, true).await {} });
                    }
                });
                // UDP: echo every datagram (fragments included) unchanged.
                let dg = conn.clone();
                tokio::spawn(async move {
                    while let Ok(d) = dg.read_datagram().await {
                        let _ = dg.send_datagram(d);
                    }
                });
                while let Ok((send, recv)) = conn.accept_bi().await {
                    tokio::spawn(serve_stream(send, recv, auth_status));
                }
            });
        }
    });
    TestServer { addr, cert_sha256 }
}

async fn serve_stream(mut send: quinn::SendStream, mut recv: quinn::RecvStream, auth_status: u16) {
    let Ok(kind) = read_varint(&mut recv).await else { return };
    match kind {
        0x01 => {
            // The auth request: a HEADERS frame (we only check its shape).
            let len = read_varint(&mut recv).await.unwrap();
            let mut block = vec![0u8; len as usize];
            recv.read_exact(&mut block).await.unwrap();
            send.write_all(&status_headers_frame(auth_status)).await.unwrap();
            let _ = send.finish();
        }
        TCP_REQUEST_ID => {
            let len = read_varint(&mut recv).await.unwrap();
            let mut target = vec![0u8; len as usize];
            recv.read_exact(&mut target).await.unwrap();
            let pad = read_varint(&mut recv).await.unwrap();
            let mut skip = vec![0u8; pad as usize];
            recv.read_exact(&mut skip).await.unwrap();
            let target = String::from_utf8(target).unwrap();
            match TcpStream::connect(&target).await {
                Ok(tcp) => {
                    send.write_all(&[0x00, 0x00, 0x00]).await.unwrap();
                    let (mut rd, mut wr) = tcp.into_split();
                    let up = async {
                        let _ = tokio::io::copy(&mut recv, &mut wr).await;
                        let _ = wr.shutdown().await;
                    };
                    let down = async {
                        let _ = tokio::io::copy(&mut rd, &mut send).await;
                        let _ = send.finish();
                    };
                    tokio::join!(up, down);
                }
                Err(e) => {
                    let msg = e.to_string();
                    let mut reply = vec![0x01];
                    put_varint(&mut reply, msg.len() as u64);
                    reply.extend_from_slice(msg.as_bytes());
                    reply.push(0x00);
                    send.write_all(&reply).await.unwrap();
                    let _ = send.finish();
                }
            }
        }
        _ => {}
    }
}

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut rd, mut wr) = s.into_split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
                let _ = wr.shutdown().await;
            });
        }
    });
    addr
}

fn config(server: &TestServer, cert: CertCheck) -> Hy2Config {
    Hy2Config { server: server.addr, server_name: "hy2.test".into(), password: "secret".into(), cert, down_mbps: 0 }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_through_hysteria2_with_pinned_cert() {
    let server = start_server(233).await;
    let echo = echo_server().await;
    let client = Hy2Client::new(config(&server, CertCheck::PinSha256(server.cert_sha256))).unwrap();

    for round in 0..3 {
        let stream = client.connect_tcp(&echo.to_string()).await.unwrap();
        let payload: Vec<u8> = (0..1024 * 1024u32).map(|i| (i * 7 + round) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let data = payload.clone();
        let writer = tokio::spawn(async move {
            wr.write_all(&data).await.unwrap();
            wr.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(20), rd.read_to_end(&mut got)).await.unwrap().unwrap();
        writer.await.unwrap();
        assert!(got == payload, "round {round}: echo differs");
    }
    assert!(client.rtt().await.is_some(), "connection is reused");

    let err = client.connect_tcp("127.0.0.1:1").await.err().expect("closed port");
    assert!(format!("{err:#}").contains("无法连接"), "{err:#}");
    assert_eq!(fetch_cert_sha256(server.addr, "hy2.test").await.unwrap(), server.cert_sha256);
}

#[tokio::test]
async fn wrong_pin_and_failed_auth_are_rejected() {
    let server = start_server(233).await;
    let echo = echo_server().await;
    let wrong = Hy2Client::new(config(&server, CertCheck::PinSha256([7u8; 32]))).unwrap();
    assert!(wrong.connect_tcp(&echo.to_string()).await.is_err(), "a wrong pin must fail");
    let webpki = Hy2Client::new(config(&server, CertCheck::WebPki)).unwrap();
    assert!(webpki.connect_tcp(&echo.to_string()).await.is_err(), "self-signed must fail web PKI");

    let refusing = start_server(404).await;
    let client = Hy2Client::new(config(&refusing, CertCheck::Insecure)).unwrap();
    let err = client.connect_tcp(&echo.to_string()).await.err().expect("auth refused");
    assert!(format!("{err:#}").contains("认证失败"), "{err:#}");
}

#[test]
fn varints_and_hex() {
    for v in [0u64, 63, 64, 1025, 16_383, 16_384, 1 << 29, 1 << 40] {
        let mut buf = Vec::new();
        put_varint(&mut buf, v);
        let back = tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(read_varint(&mut buf.as_slice())).unwrap();
        assert_eq!(back, v);
    }
    let d = [0xABu8; 32];
    assert_eq!(parse_hex_sha256(&hex(&d)).unwrap(), d);
    assert!(parse_hex_sha256("zz").is_err());
}

#[tokio::test]
async fn udp_datagrams_and_fragments() {
    let server = start_server(233).await;
    let client = Hy2Client::new(config(&server, CertCheck::PinSha256(server.cert_sha256))).unwrap();
    let mut udp = client.udp_session().await.unwrap();
    udp.send_to(b"ping", "1.1.1.1:53").unwrap();
    let (data, addr) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from()).await.unwrap().unwrap();
    assert_eq!((data.as_slice(), addr.as_str()), (&b"ping"[..], "1.1.1.1:53"));

    let big: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
    udp.send_to(&big, "example.com:443").unwrap();
    let (data, addr) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from()).await.unwrap().unwrap();
    assert_eq!(addr, "example.com:443");
    assert!(data == big, "fragmented datagram not reassembled");
}
