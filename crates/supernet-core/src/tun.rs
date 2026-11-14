//! TUN mode: everything a TUN device captures goes through the same rules
//! and outbounds as the local proxy port.
//!
//! DNS (UDP port 53, any server) is answered here with fake addresses from
//! 198.18.0.0/15 that remember the name, so rules still see domains and names
//! sent to a node are never resolved locally.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use supernet_netstack::{NetStack, UdpDatagram};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::dns;
use crate::engine::{Inner, OpenError, Out};
use crate::outbound::UdpOut;
use crate::target::{Host, Target};

const FAKE_BASE: u32 = u32::from_be_bytes([198, 18, 0, 0]);
const FAKE_SIZE: u32 = 1 << 17; // 198.18.0.0/15
/// 198.18.0.0–198.18.0.255 are left for the adapter itself.
const FAKE_FIRST: u32 = 256;
const FAKE_TTL: u32 = 10;
const UDP_IDLE: Duration = Duration::from_secs(60);

/// Fake-IP DNS: one address per name, recycled oldest-first when the pool wraps.
pub struct FakeDns {
    inner: Mutex<FakeInner>,
}

struct FakeInner {
    next: u32,
    by_name: HashMap<String, u32>,
    by_ip: HashMap<u32, String>,
}

impl Default for FakeDns {
    fn default() -> Self {
        Self { inner: Mutex::new(FakeInner { next: FAKE_FIRST, by_name: HashMap::new(), by_ip: HashMap::new() }) }
    }
}

impl FakeDns {
    pub fn contains(ip: Ipv4Addr) -> bool {
        u32::from(ip).wrapping_sub(FAKE_BASE) < FAKE_SIZE
    }

    pub fn ip_for(&self, name: &str) -> Ipv4Addr {
        let mut f = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(offset) = f.by_name.get(name) {
            return Ipv4Addr::from(FAKE_BASE + offset);
        }
        let offset = f.next;
        f.next = if offset + 1 >= FAKE_SIZE - 1 { FAKE_FIRST } else { offset + 1 };
        if let Some(old) = f.by_ip.insert(offset, name.to_string()) {
            f.by_name.remove(&old);
        }
        f.by_name.insert(name.to_string(), offset);
        Ipv4Addr::from(FAKE_BASE + offset)
    }

    pub fn name_for(&self, ip: Ipv4Addr) -> Option<String> {
        let f = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        f.by_ip.get(&u32::from(ip).wrapping_sub(FAKE_BASE)).cloned()
    }

    /// Answer a DNS query: A gets a fake address, every other type an empty
    /// answer (no IPv6, no HTTPS/SVCB records carrying real addresses).
    pub fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        let q = dns::parse_query(query)?;
        let ips: Vec<IpAddr> = if q.qtype == dns::TYPE_A && !q.name.is_empty() {
            vec![IpAddr::V4(self.ip_for(&q.name))]
        } else {
            Vec::new()
        };
        Some(dns::build_answer(query, &q, &ips, FAKE_TTL))
    }

    /// The target an application meant, given the address it connected to.
    pub fn target_for(&self, dst: SocketAddr) -> Option<Target> {
        match dst.ip() {
            IpAddr::V4(v4) if Self::contains(v4) => self.name_for(v4).map(|n| Target::new(Host::Domain(n), dst.port())),
            ip => Some(Target::new(Host::Ip(ip), dst.port())),
        }
    }
}

pub(crate) struct TunRuntime {
    tasks: Vec<JoinHandle<()>>,
    _stack: Arc<NetStack>,
}

impl Drop for TunRuntime {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

pub(crate) fn start(inner: Arc<Inner>, stack: NetStack, udp: mpsc::Receiver<UdpDatagram>) -> TunRuntime {
    let stack = Arc::new(stack);
    let fake = Arc::new(FakeDns::default());
    let tcp = tokio::spawn(tcp_loop(inner.clone(), stack.clone(), fake.clone()));
    let udp = tokio::spawn(udp_loop(inner, stack.clone(), fake, udp));
    TunRuntime { tasks: vec![tcp, udp], _stack: stack }
}

async fn tcp_loop(inner: Arc<Inner>, stack: Arc<NetStack>, fake: Arc<FakeDns>) {
    while let Ok((mut stream, _src, dst)) = stack.accept().await {
        let inner = inner.clone();
        let fake = fake.clone();
        tokio::spawn(async move {
            let Some(mut target) = fake.target_for(dst) else {
                // A fake address we no longer know (pool recycled): reset.
                return;
            };
            // Apps with their own DNS (e.g. browser DoH) connect by real IP;
            // recover the name from the first bytes so domain rules still apply.
            let mut first = Vec::new();
            let mut ip_hint = None;
            if let Host::Ip(ip) = target.host {
                first = peek_first_bytes(&mut stream).await;
                if let Some(name) = sniff_host(&first) {
                    target = Target::new(Host::Domain(name), target.port);
                    ip_hint = Some(ip);
                }
            }
            match inner.open_with_hint(&target, "tun", ip_hint).await {
                Ok((mut out, guard)) => {
                    use tokio::io::AsyncWriteExt;
                    if !first.is_empty() && out.write_all(&first).await.is_err() {
                        return;
                    }
                    let _ = crate::inbound::relay(stream, out, guard).await;
                }
                Err(OpenError::Rejected) | Err(OpenError::Failed(_)) => {}
            }
        });
    }
}

/// Whatever the client sends within 300 ms (empty for server-speaks-first protocols).
async fn peek_first_bytes(stream: &mut supernet_netstack::TcpStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf)).await {
        Ok(Ok(n)) => {
            buf.truncate(n);
            buf
        }
        _ => Vec::new(),
    }
}

/// Host name from a TLS ClientHello (SNI) or an HTTP/1 request (Host header).
pub fn sniff_host(data: &[u8]) -> Option<String> {
    let name = if data.first() == Some(&0x16) { tls_sni(data)? } else { http_host(data)? };
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    match crate::target::Host::new(&name)? {
        Host::Domain(d) => Some(d),
        Host::Ip(_) => None,
    }
}

fn http_host(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data.get(..data.len().min(2048))?).ok()?;
    let method = text.split(' ').next()?;
    if !matches!(method, "GET" | "POST" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "PATCH" | "CONNECT") {
        return None;
    }
    text.split("\r\n").skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case("host").then(|| v.trim().rsplit_once(':').map_or(v.trim(), |(h, _)| h).to_string())
    })
}

fn tls_sni(data: &[u8]) -> Option<String> {
    // TLS record header (5) + handshake header (4): ClientHello is type 1.
    if *data.get(5)? != 0x01 {
        return None;
    }
    let mut p = 9 + 2 + 32; // client version + random
    let session = *data.get(p)? as usize;
    p += 1 + session;
    let suites = u16::from_be_bytes([*data.get(p)?, *data.get(p + 1)?]) as usize;
    p += 2 + suites;
    let compression = *data.get(p)? as usize;
    p += 1 + compression;
    let ext_total = u16::from_be_bytes([*data.get(p)?, *data.get(p + 1)?]) as usize;
    p += 2;
    let end = (p + ext_total).min(data.len());
    while p + 4 <= end {
        let kind = u16::from_be_bytes([data[p], data[p + 1]]);
        let len = u16::from_be_bytes([data[p + 2], data[p + 3]]) as usize;
        p += 4;
        if kind == 0 {
            // server_name: list length (2), type (1) = host_name, name length (2), name
            let name_len = u16::from_be_bytes([*data.get(p + 3)?, *data.get(p + 4)?]) as usize;
            return String::from_utf8(data.get(p + 5..p + 5 + name_len)?.to_vec()).ok();
        }
        p += len;
    }
    None
}

type Sessions = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>>>;

static TRACE_DNS: AtomicBool = AtomicBool::new(false);

/// Log every DNS query the TUN sees (diagnostics; `supernet tun-test`).
pub fn set_dns_trace(on: bool) {
    TRACE_DNS.store(on, Ordering::Relaxed);
}

async fn udp_loop(inner: Arc<Inner>, stack: Arc<NetStack>, fake: Arc<FakeDns>, mut udp: mpsc::Receiver<UdpDatagram>) {
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    while let Some(d) = udp.recv().await {
        if d.dst.port() == 53 {
            let answer = fake.answer(&d.payload);
            if TRACE_DNS.load(Ordering::Relaxed) {
                let q = dns::parse_query(&d.payload);
                inner.logs.push(
                    "info",
                    format!(
                        "DNS {} → {} {} 类型 {} {}字节 {}",
                        d.src,
                        d.dst,
                        q.as_ref().map_or("?", |q| q.name.as_str()),
                        q.as_ref().map_or(0, |q| q.qtype),
                        d.payload.len(),
                        if answer.is_some() { "已应答" } else { "无法解析，未应答" }
                    ),
                );
            }
            if let Some(answer) = answer {
                let _ = stack.send_udp(d.dst, d.src, &answer);
            }
            continue;
        }
        let key = (d.src, d.dst);
        let existing = sessions.lock().unwrap_or_else(|e| e.into_inner()).get(&key).cloned();
        let tx = match existing {
            Some(tx) => tx,
            None => {
                let Some(target) = fake.target_for(d.dst) else { continue };
                let (tx, rx) = mpsc::channel(256);
                sessions.lock().unwrap_or_else(|e| e.into_inner()).insert(key, tx.clone());
                tokio::spawn(udp_session(inner.clone(), stack.clone(), sessions.clone(), key, target, rx));
                tx
            }
        };
        let _ = tx.try_send(d.payload);
    }
}

async fn udp_session(
    inner: Arc<Inner>,
    stack: Arc<NetStack>,
    sessions: Sessions,
    key: (SocketAddr, SocketAddr),
    target: Target,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    let (app, seen_dst) = key;
    let result = async {
        let (info, out, resolver) = inner.decide(&target).await;
        let mut link = match out {
            Out::Reject => return Ok(()),
            Out::Direct => UdpOut::direct(&target, &info.resolved, &resolver).await?,
            Out::Node(node) => node.udp(&target, &resolver).await?,
        };
        inner.logs.push("info", format!("{target} → {}（{}）[UDP]", info.chain, info.rule));
        let mut buf = vec![0u8; 65_536];
        loop {
            tokio::select! {
                packet = rx.recv() => match packet {
                    Some(p) => link.send(&p).await?,
                    None => break,
                },
                n = link.recv(&mut buf) => {
                    let n = n?;
                    // Replies always appear to come from the address the app used.
                    let _ = stack.send_udp(seen_dst, app, &buf[..n]);
                }
                _ = tokio::time::sleep(UDP_IDLE) => break,
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(e) = result {
        tracing::debug!("udp {target}: {e:#}");
    }
    sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_dns_maps_both_ways() {
        let f = FakeDns::default();
        let a = f.ip_for("www.example.com");
        assert!(FakeDns::contains(a));
        assert_eq!(f.ip_for("www.example.com"), a, "stable per name");
        assert_ne!(f.ip_for("other.example.com"), a);
        assert_eq!(f.name_for(a).as_deref(), Some("www.example.com"));
        assert_eq!(
            f.target_for(SocketAddr::new(IpAddr::V4(a), 443)),
            Some(Target::new(Host::Domain("www.example.com".into()), 443))
        );
        assert_eq!(f.target_for("8.8.8.8:53".parse().unwrap()), Some(Target::new(Host::Ip("8.8.8.8".parse().unwrap()), 53)));
        assert!(!FakeDns::contains("198.20.0.1".parse().unwrap()));

        let q = dns::build_query(7, "www.example.com", dns::TYPE_A).unwrap();
        let (ips, _) = dns::parse_response(7, &f.answer(&q).unwrap()).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(a)]);
        let q6 = dns::build_query(8, "www.example.com", dns::TYPE_AAAA).unwrap();
        let (ips, _) = dns::parse_response(8, &f.answer(&q6).unwrap()).unwrap();
        assert!(ips.is_empty(), "no IPv6 answers in TUN mode");
    }

    #[test]
    fn sniffs_http_host_and_tls_sni() {
        assert_eq!(sniff_host(b"GET / HTTP/1.1\r\nHost: Example.COM:8080\r\nAccept: */*\r\n\r\n").as_deref(), Some("example.com"));
        assert_eq!(sniff_host(b"SSH-2.0-OpenSSH\r\n"), None);
        assert_eq!(sniff_host(b"GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n"), None, "IP hosts give no name");
        // A minimal TLS 1.2 ClientHello with SNI "sni.example.org".
        let name = b"sni.example.org";
        let mut sni_ext = vec![0x00, 0x00];
        let list_len = (name.len() + 3) as u16;
        sni_ext.extend_from_slice(&(list_len + 2).to_be_bytes());
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // compression
        body.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&sni_ext);
        let mut hs = vec![0x01, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend_from_slice(&body);
        let mut record = vec![0x16, 0x03, 0x01, (hs.len() >> 8) as u8, hs.len() as u8];
        record.extend_from_slice(&hs);
        assert_eq!(sniff_host(&record).as_deref(), Some("sni.example.org"));
        assert_eq!(sniff_host(&record[..20]), None, "truncated hello");
    }

    #[test]
    fn fake_pool_recycles_oldest() {
        let f = FakeDns::default();
        let first = f.ip_for("first.test");
        {
            let mut g = f.inner.lock().unwrap();
            g.next = FAKE_SIZE - 2; // jump to the end of the pool
        }
        let last = f.ip_for("last.test");
        let wrapped = f.ip_for("wrapped.test");
        assert_eq!(u32::from(last) - FAKE_BASE, FAKE_SIZE - 2);
        assert_eq!(wrapped, first, "the pool wraps to its first address");
        assert_eq!(f.name_for(first).as_deref(), Some("wrapped.test"));
        assert_eq!(f.name_for(wrapped).as_deref(), Some("wrapped.test"));
        assert!(f.inner.lock().unwrap().by_name.get("first.test").is_none(), "old name forgotten");
    }
}
