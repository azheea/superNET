//! The local proxy port: HTTP (CONNECT and absolute-form requests) and
//! SOCKS5 (CONNECT) on one listener, told apart by the first byte.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::engine::{Inner, OpenError};
use crate::outbound::{parse_http_url, BoxStream};
use crate::stats::{ConnGuard, Counted};
use crate::target::{Host, Target};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HEAD: usize = 64 * 1024;

pub(crate) async fn handle(inner: Arc<Inner>, sock: TcpStream, peer: SocketAddr) {
    let _ = sock.set_nodelay(true);
    let mut first = [0u8; 1];
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, sock.peek(&mut first)).await {
        Ok(Ok(1)) => {}
        _ => return,
    }
    let result = match first[0] {
        0x05 => socks5(inner, sock).await,
        0x04 => Err(anyhow::anyhow!("不支持 SOCKS4，请改用 SOCKS5 或 HTTP")),
        _ => http(inner, sock).await,
    };
    if let Err(e) = result {
        tracing::debug!("client {peer}: {e:#}");
    }
}

pub(crate) async fn relay<S>(mut client: S, mut out: Counted<BoxStream>, guard: ConnGuard) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::select! {
        r = tokio::io::copy_bidirectional(&mut client, &mut out) => { r?; }
        _ = guard.cancel.notified() => {}
    }
    Ok(())
}

// ---------------------------------------------------------------- HTTP

struct Request {
    method: String,
    uri: String,
    version: String,
    headers: Vec<(String, String)>,
}

async fn read_head(sock: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(HANDSHAKE_TIMEOUT, sock.read(&mut chunk)).await.context("读取请求头超时")??;
        if n == 0 {
            bail!("请求头读完前连接已关闭");
        }
        let scan_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf[scan_from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(scan_from + pos + 4);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HEAD {
            bail!("请求头过长");
        }
    }
}

fn parse_head(head: &[u8]) -> Result<Request> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let (Some(method), Some(uri), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        bail!("请求行格式错误：{first}");
    };
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();
    Ok(Request { method: method.to_string(), uri: uri.to_string(), version: version.to_string(), headers })
}

fn simple_response(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn failure_response(err: &OpenError) -> Vec<u8> {
    match err {
        OpenError::Rejected => simple_response("403 Forbidden", "superNET: blocked by rule\n"),
        OpenError::Failed(e) => simple_response("502 Bad Gateway", &format!("superNET: {e:#}\n")),
    }
}

async fn http(inner: Arc<Inner>, mut sock: TcpStream) -> Result<()> {
    let (head, rest) = read_head(&mut sock).await?;
    let req = parse_head(&head)?;

    if req.method.eq_ignore_ascii_case("CONNECT") {
        let target = Target::parse(&req.uri, Some(443)).with_context(|| format!("CONNECT 目标无效：{}", req.uri))?;
        match inner.open(&target, "http").await {
            Ok((mut out, guard)) => {
                sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                if !rest.is_empty() {
                    out.write_all(&rest).await?;
                }
                relay(sock, out, guard).await
            }
            Err(e) => {
                let _ = sock.write_all(&failure_response(&e)).await;
                bail!("CONNECT {target} 失败");
            }
        }
    } else {
        let Ok((target, path)) = parse_http_url(&req.uri) else {
            let _ = sock.write_all(&simple_response("400 Bad Request", "superNET proxy port: send proxy requests here\n")).await;
            bail!("不是代理请求：{} {}", req.method, req.uri);
        };
        // Forward one request in origin form. `Connection: close` keeps a
        // keep-alive client from sending its next request (maybe for another
        // host) down this connection.
        let mut out_head = format!("{} {} {}\r\n", req.method, path, req.version);
        let mut has_host = false;
        for (k, v) in &req.headers {
            let lower = k.to_ascii_lowercase();
            if matches!(lower.as_str(), "proxy-connection" | "proxy-authorization" | "connection" | "keep-alive") {
                continue;
            }
            has_host |= lower == "host";
            out_head += &format!("{k}: {v}\r\n");
        }
        if !has_host {
            out_head += &format!("Host: {}\r\n", authority(&target));
        }
        out_head += "Connection: close\r\n\r\n";

        match inner.open(&target, "http").await {
            Ok((mut out, guard)) => {
                out.write_all(out_head.as_bytes()).await?;
                if !rest.is_empty() {
                    out.write_all(&rest).await?;
                }
                relay(sock, out, guard).await
            }
            Err(e) => {
                let _ = sock.write_all(&failure_response(&e)).await;
                bail!("{} {target} 失败", req.method);
            }
        }
    }
}

fn authority(target: &Target) -> String {
    if target.port == 80 {
        target.host.to_string()
    } else {
        target.to_string()
    }
}

// ---------------------------------------------------------------- SOCKS5

async fn socks5(inner: Arc<Inner>, mut sock: TcpStream) -> Result<()> {
    let target = match tokio::time::timeout(HANDSHAKE_TIMEOUT, socks5_handshake(&mut sock)).await {
        Ok(r) => r?,
        Err(_) => bail!("SOCKS5 握手超时"),
    };
    match inner.open(&target, "socks5").await {
        Ok((out, guard)) => {
            socks5_reply(&mut sock, 0x00).await?;
            relay(sock, out, guard).await
        }
        Err(e) => {
            let code = match &e {
                OpenError::Rejected => 0x02,
                OpenError::Failed(err) => failure_code(err),
            };
            let _ = socks5_reply(&mut sock, code).await;
            bail!("SOCKS5 CONNECT {target} 失败");
        }
    }
}

async fn socks5_handshake(sock: &mut TcpStream) -> Result<Target> {
    let mut hello = [0u8; 2];
    sock.read_exact(&mut hello).await?;
    let mut methods = vec![0u8; hello[1] as usize];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        sock.write_all(&[0x05, 0xFF]).await?;
        bail!("客户端只支持需要认证的 SOCKS5");
    }
    sock.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        bail!("SOCKS5 版本错误");
    }
    let host = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await?;
            Host::Ip(IpAddr::V4(Ipv4Addr::from(a)))
        }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            match std::str::from_utf8(&name).ok().and_then(Host::new) {
                Some(h) => h,
                None => {
                    socks5_reply(sock, 0x08).await?;
                    bail!("SOCKS5 域名无效");
                }
            }
        }
        0x04 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await?;
            Host::Ip(IpAddr::V6(Ipv6Addr::from(a)))
        }
        other => {
            socks5_reply(sock, 0x08).await?;
            bail!("SOCKS5 地址类型 {other} 不支持");
        }
    };
    let mut port = [0u8; 2];
    sock.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    if req[1] != 0x01 {
        // UDP ASSOCIATE arrives with the TUN mode (M2).
        socks5_reply(sock, 0x07).await?;
        bail!("SOCKS5 命令 {} 暂不支持", req[1]);
    }
    if port == 0 {
        socks5_reply(sock, 0x01).await?;
        bail!("SOCKS5 端口为 0");
    }
    Ok(Target::new(host, port))
}

async fn socks5_reply(sock: &mut TcpStream, code: u8) -> std::io::Result<()> {
    sock.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await
}

fn failure_code(err: &anyhow::Error) -> u8 {
    for cause in err.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return match io.kind() {
                std::io::ErrorKind::ConnectionRefused => 0x05,
                std::io::ErrorKind::TimedOut => 0x04,
                std::io::ErrorKind::AddrNotAvailable => 0x03,
                _ => 0x01,
            };
        }
    }
    0x04
}
