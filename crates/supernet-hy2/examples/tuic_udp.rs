//! Manual check of TUIC UDP relay against a real server:
//!
//!   cargo run -p supernet-hy2 --example tuic_udp -- SERVER:PORT UUID PASSWORD PIN_SHA256 [DNS:53]
//!
//! Sends a DNS query for www.example.com through the server and prints the
//! answer's size and source; also opens one TCP stream (HTTP HEAD).

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use supernet_hy2::tuic::{parse_uuid, TuicClient, TuicConfig};
use supernet_hy2::{parse_hex_sha256, CertCheck};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [server, uuid, password, pin] = [&a[0], &a[1], &a[2], &a[3]];
    let dns = a.get(4).cloned().unwrap_or_else(|| "223.5.5.5:53".into());
    let client = TuicClient::new(TuicConfig {
        server: server.parse()?,
        server_name: "supernet.local".into(),
        uuid: parse_uuid(uuid)?,
        password: password.clone(),
        cert: CertCheck::PinSha256(parse_hex_sha256(pin)?),
    })?;

    // UDP: a DNS query (A www.example.com).
    let mut udp = client.udp_session().await?;
    let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["www", "example", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    for i in 0..3 {
        let started = Instant::now();
        udp.send_to(&q, &dns)?;
        let (answer, from) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from()).await.context("UDP 超时")?.context("会话关闭")?;
        let ok = answer.get(0..2) == Some(&[0x12, 0x34][..]) && answer.len() > q.len();
        println!("UDP #{i}: {} 字节，来自 {from}，{} ms，{}", answer.len(), started.elapsed().as_millis(), if ok { "DNS 应答正确" } else { "应答异常" });
    }

    // TCP: HTTP HEAD through the server.
    let started = Instant::now();
    let mut s = client.connect_tcp("www.baidu.com:80").await?;
    s.write_all(b"HEAD / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n").await?;
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf)).await??;
    println!("TCP: {}（{} ms）", String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or(""), started.elapsed().as_millis());
    println!("RTT: {:?}", client.rtt().await);
    Ok(())
}
