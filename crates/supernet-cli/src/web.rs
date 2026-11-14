//! The web console: the app's own UI, served by the headless `supernet`
//! (`--web 127.0.0.1:9090`), for machines without a screen.
//!
//! - Static files: the frontend embedded at build time (build.rs).
//! - `POST /api/<command>` with the command's JSON arguments: the same
//!   commands as the app (supernet-control). Every API call needs
//!   `Authorization: Bearer <token>`; the token is printed at start as part of
//!   the console's link (`#token=…`, never sent to the server in the URL).
//!
//! It speaks plain HTTP: keep it on 127.0.0.1 and reach it through
//! `ssh -L 9090:127.0.0.1:9090 server`, which is also what the start message says.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use supernet_control::Controller;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

mod assets {
    include!(concat!(env!("OUT_DIR"), "/web_assets.rs"));
}

const MAX_BODY: usize = 1 << 20;

/// The console's token: `--web-token`, else the one saved in the data folder
/// (made on first use, owner-only), so links keep working across restarts.
pub fn token(data_dir: &Path, given: Option<String>) -> Result<String> {
    if let Some(t) = given.filter(|t| t.len() >= 16) {
        return Ok(t);
    }
    let path = data_dir.join("web-token");
    if let Ok(t) = std::fs::read_to_string(&path) {
        let t = t.trim().to_string();
        if t.len() >= 16 {
            return Ok(t);
        }
    }
    let mut bytes = [0u8; 24];
    getrandom(&mut bytes)?;
    let t: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(&path, &t).with_context(|| format!("保存 {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(t)
}

fn getrandom(buf: &mut [u8]) -> Result<()> {
    use rand_core::RngCore;
    rand_core::OsRng.try_fill_bytes(buf).map_err(|e| anyhow::anyhow!("随机数：{e}"))
}

pub async fn serve(addr: SocketAddr, token: String, ctl: Arc<Controller>) -> Result<()> {
    let listener = TcpListener::bind(addr).await.with_context(|| format!("网页控制台监听 {addr}"))?;
    let token = Arc::new(token);
    loop {
        let (sock, _) = listener.accept().await?;
        let (token, ctl) = (token.clone(), ctl.clone());
        tokio::spawn(async move {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(120), handle(sock, &token, &ctl)).await;
        });
    }
}

struct Request {
    method: String,
    path: String,
    auth: Option<String>,
    body: Vec<u8>,
}

async fn read_request(sock: &mut TcpStream) -> Result<Option<Request>> {
    let mut buf = Vec::with_capacity(4096);
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 64 * 1024 {
            anyhow::bail!("请求头太大");
        }
        let mut chunk = [0u8; 4096];
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split_whitespace();
    let method = first.next().unwrap_or_default().to_string();
    let path = first.next().unwrap_or("/").to_string();
    let mut len = 0usize;
    let mut auth = None;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else { continue };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "content-length" => len = v.parse().unwrap_or(0),
            "authorization" => auth = v.strip_prefix("Bearer ").map(str::to_string),
            _ => {}
        }
    }
    if len > MAX_BODY {
        anyhow::bail!("请求太大");
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let mut chunk = vec![0u8; (len - body.len()).min(64 * 1024)];
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(len);
    Ok(Some(Request { method, path, auth, body }))
}

/// Equal without leaking how much of the token matched.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn handle(mut sock: TcpStream, token: &str, ctl: &Controller) -> Result<()> {
    let Some(req) = read_request(&mut sock).await? else { return Ok(()) };
    let path = req.path.split(['?', '#']).next().unwrap_or("/").to_string();
    let (status, ctype, body): (&str, &str, Vec<u8>) = if let Some(cmd) = path.strip_prefix("/api/") {
        if req.method != "POST" {
            ("405 Method Not Allowed", "application/json", br#"{"error":"POST only"}"#.to_vec())
        } else if !req.auth.as_deref().is_some_and(|a| same(a, token)) {
            ("401 Unauthorized", "application/json", json!({ "error": "未授权：请用启动时打印的完整链接打开（带 #token=…）" }).to_string().into_bytes())
        } else {
            let args: Value = if req.body.is_empty() { json!({}) } else { serde_json::from_slice(&req.body).unwrap_or(json!({})) };
            match ctl.dispatch(cmd, &args).await {
                Ok(v) => ("200 OK", "application/json", json!({ "ok": v }).to_string().into_bytes()),
                Err(e) => ("400 Bad Request", "application/json", json!({ "error": e }).to_string().into_bytes()),
            }
        }
    } else if req.method == "GET" {
        static_file(&path)
    } else {
        ("405 Method Not Allowed", "text/plain; charset=utf-8", b"method not allowed".to_vec())
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n\
         Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(&body).await?;
    sock.shutdown().await.ok();
    Ok(())
}

fn static_file(path: &str) -> (&'static str, &'static str, Vec<u8>) {
    let rel = path.trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    if assets::ASSETS.is_empty() {
        let page = "<!doctype html><meta charset=utf-8><title>superNET</title><p>这个 supernet 构建时没有前端：先在 app/ 里运行 npm run build，再重新编译。</p>";
        return ("200 OK", "text/html; charset=utf-8", page.as_bytes().to_vec());
    }
    // Unknown paths get the app (it has no routes of its own, but be forgiving).
    let (name, data) = assets::ASSETS
        .iter()
        .find(|(n, _)| *n == rel)
        .or_else(|| assets::ASSETS.iter().find(|(n, _)| *n == "index.html"))
        .map(|(n, d)| (*n, *d))
        .unwrap_or(("", &[]));
    if name.is_empty() {
        return ("404 Not Found", "text/plain; charset=utf-8", b"not found".to_vec());
    }
    let ctype = match name.rsplit('.').next().unwrap_or_default() {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "json" => "application/json",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    };
    let mut body = data.to_vec();
    if name == "index.html" {
        // Tells the frontend to talk to this server instead of Tauri.
        let html = String::from_utf8_lossy(&body).replacen("<head>", "<head><script>window.__SUPERNET_WEB__=1</script>", 1);
        body = html.into_bytes();
    }
    ("200 OK", ctype, body)
}
