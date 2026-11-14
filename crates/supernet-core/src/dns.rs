//! Minimal DNS: A/AAAA queries over UDP, a small TTL cache, and the direct
//! resolver used for direct traffic and IP rules.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use rand_core::{OsRng, RngCore};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const MIN_TTL: u32 = 30;
const MAX_TTL: u32 = 600;

/// Build a recursive query for one name.
pub fn build_query(id: u16, name: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut msg = Vec::with_capacity(32 + name.len());
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&[0x01, 0x00]); // RD
    msg.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // 1 question
    encode_name(&mut msg, name)?;
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(msg)
}

fn encode_name(out: &mut Vec<u8>, name: &str) -> io::Result<()> {
    let name = name.trim_end_matches('.');
    if name.len() > 253 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "domain too long"));
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad domain {name}")));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Skip a (possibly compressed) name; returns the offset after it.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    for _ in 0..128 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            msg.get(pos + 1)?;
            return Some(pos + 2);
        }
        pos += 1 + len;
    }
    None
}

/// Read an uncompressed or compressed name (used by servers parsing queries).
fn read_name(msg: &[u8], mut pos: usize) -> Option<String> {
    let mut labels = Vec::new();
    for _ in 0..128 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some(labels.join("."));
        }
        if len & 0xC0 == 0xC0 {
            pos = ((len & 0x3F) << 8) | *msg.get(pos + 1)? as usize;
            continue;
        }
        labels.push(String::from_utf8_lossy(msg.get(pos + 1..pos + 1 + len)?).to_ascii_lowercase());
        pos += 1 + len;
    }
    None
}

fn u16_at(msg: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]))
}

fn u32_at(msg: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_be_bytes(msg.get(pos..pos + 4)?.try_into().ok()?))
}

/// Addresses and the smallest TTL from a response to query `id`.
pub fn parse_response(id: u16, msg: &[u8]) -> Result<(Vec<IpAddr>, u32)> {
    let parsed = (|| -> Option<Result<(Vec<IpAddr>, u32)>> {
        if u16_at(msg, 0)? != id || msg.get(2)? & 0x80 == 0 {
            return Some(Err(anyhow::anyhow!("不是对应的 DNS 回应")));
        }
        let rcode = msg.get(3)? & 0x0F;
        if rcode == 3 {
            return Some(Ok((Vec::new(), MIN_TTL))); // NXDOMAIN
        }
        if rcode != 0 {
            return Some(Err(anyhow::anyhow!("DNS 服务器返回错误码 {rcode}")));
        }
        let qd = u16_at(msg, 4)?;
        let an = u16_at(msg, 6)?;
        let mut pos = 12;
        for _ in 0..qd {
            pos = skip_name(msg, pos)? + 4;
        }
        let mut ips = Vec::new();
        let mut ttl = MAX_TTL;
        for _ in 0..an {
            pos = skip_name(msg, pos)?;
            let rtype = u16_at(msg, pos)?;
            let rttl = u32_at(msg, pos + 4)?;
            let rdlen = u16_at(msg, pos + 8)? as usize;
            let data = msg.get(pos + 10..pos + 10 + rdlen)?;
            match (rtype, rdlen) {
                (TYPE_A, 4) => ips.push(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
                (TYPE_AAAA, 16) => ips.push(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?))),
                _ => {}
            }
            if matches!(rtype, TYPE_A | TYPE_AAAA) {
                ttl = ttl.min(rttl);
            }
            pos += 10 + rdlen;
        }
        Some(Ok((ips, ttl.clamp(MIN_TTL, MAX_TTL))))
    })();
    parsed.unwrap_or_else(|| bail!("DNS 回应格式错误"))
}

/// A parsed question, for small DNS servers (the test node).
pub struct Question {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    /// Byte range of the question section, copied into the answer.
    question_end: usize,
}

pub fn parse_query(msg: &[u8]) -> Option<Question> {
    if msg.get(2)? & 0x80 != 0 || u16_at(msg, 4)? != 1 {
        return None;
    }
    let name = read_name(msg, 12)?;
    let end = skip_name(msg, 12)?;
    let qtype = u16_at(msg, end)?;
    Some(Question { id: u16_at(msg, 0)?, name, qtype, question_end: end + 4 })
}

/// Answer `q` with `ips` (those matching the query type).
pub fn build_answer(query: &[u8], q: &Question, ips: &[IpAddr], ttl: u32) -> Vec<u8> {
    let answers: Vec<&IpAddr> = ips
        .iter()
        .filter(|ip| matches!((ip, q.qtype), (IpAddr::V4(_), TYPE_A) | (IpAddr::V6(_), TYPE_AAAA)))
        .collect();
    let mut msg = Vec::with_capacity(q.question_end + answers.len() * 28);
    msg.extend_from_slice(&q.id.to_be_bytes());
    msg.extend_from_slice(&[0x81, 0x80]); // response, RD, RA
    msg.extend_from_slice(&[0, 1]);
    msg.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    msg.extend_from_slice(&[0, 0, 0, 0]);
    msg.extend_from_slice(&query[12..q.question_end]);
    for ip in answers {
        msg.extend_from_slice(&[0xC0, 12]); // pointer to the question name
        let (rtype, data): (u16, Vec<u8>) = match ip {
            IpAddr::V4(v4) => (TYPE_A, v4.octets().to_vec()),
            IpAddr::V6(v6) => (TYPE_AAAA, v6.octets().to_vec()),
        };
        msg.extend_from_slice(&rtype.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&ttl.to_be_bytes());
        msg.extend_from_slice(&(data.len() as u16).to_be_bytes());
        msg.extend_from_slice(&data);
    }
    msg
}

/// Anything that can send and receive datagrams: an OS socket or a socket
/// inside a WireGuard tunnel.
pub(crate) trait Datagram {
    async fn send_dgram(&self, data: &[u8], to: SocketAddr) -> io::Result<()>;
    async fn recv_dgram(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
}

impl Datagram for tokio::net::UdpSocket {
    async fn send_dgram(&self, data: &[u8], to: SocketAddr) -> io::Result<()> {
        self.send_to(data, to).await.map(|_| ())
    }
    async fn recv_dgram(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }
}

impl Datagram for supernet_wg::UdpSocket {
    async fn send_dgram(&self, data: &[u8], to: SocketAddr) -> io::Result<()> {
        self.send_to(data, to).await
    }
    async fn recv_dgram(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }
}

/// One query/response exchange with one retry.
pub(crate) async fn exchange<S: Datagram>(sock: &S, server: SocketAddr, name: &str, qtype: u16) -> Result<(Vec<IpAddr>, u32)> {
    let id = (OsRng.next_u32() & 0xFFFF) as u16;
    let query = build_query(id, name, qtype)?;
    let mut buf = vec![0u8; 4096];
    for _attempt in 0..2 {
        sock.send_dgram(&query, server).await?;
        let deadline = tokio::time::Instant::now() + QUERY_TIMEOUT;
        loop {
            match tokio::time::timeout_at(deadline, sock.recv_dgram(&mut buf)).await {
                Err(_) => break, // retry
                Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                Ok(Err(e)) => return Err(e.into()),
                Ok(Ok((n, from))) => {
                    if from != server || u16_at(&buf[..n], 0) != Some(id) {
                        continue; // stale or spoofed
                    }
                    return parse_response(id, &buf[..n]);
                }
            }
        }
    }
    bail!("DNS 服务器 {server} 没有回应")
}

/// Look up `name` on `servers`: A first, AAAA only when there was no A record.
pub(crate) async fn lookup_via<S: Datagram>(sock: &S, servers: &[SocketAddr], name: &str, want_v4: bool, want_v6: bool) -> Result<(Vec<IpAddr>, u32)> {
    let mut last_err = None;
    for server in servers {
        let mut result = (Vec::new(), MAX_TTL);
        let mut ok = false;
        for (wanted, qtype) in [(want_v4, TYPE_A), (want_v6, TYPE_AAAA)] {
            if !wanted || (qtype == TYPE_AAAA && !result.0.is_empty()) {
                continue;
            }
            match exchange(sock, *server, name, qtype).await {
                Ok((ips, ttl)) => {
                    ok = true;
                    result.0.extend(ips);
                    result.1 = result.1.min(ttl);
                }
                Err(e) => last_err = Some(e),
            }
        }
        if ok {
            return Ok(result);
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("没有可用的 DNS 服务器")))
}

/// TTL cache keyed by name.
#[derive(Default)]
pub struct Cache {
    entries: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
}

impl Cache {
    pub fn get(&self, name: &str) -> Option<Vec<IpAddr>> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.get(name).filter(|(_, exp)| *exp > Instant::now()).map(|(ips, _)| ips.clone())
    }

    pub fn put(&self, name: &str, ips: Vec<IpAddr>, ttl: u32) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() > 4096 {
            let now = Instant::now();
            entries.retain(|_, (_, exp)| *exp > now);
        }
        entries.insert(name.to_string(), (ips, Instant::now() + Duration::from_secs(ttl as u64)));
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Upstream {
    System,
    Udp(SocketAddr),
}

impl Upstream {
    pub fn parse(s: &str) -> Result<Upstream> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("system") {
            return Ok(Upstream::System);
        }
        let s = s.strip_prefix("udp://").unwrap_or(s);
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(Upstream::Udp(addr));
        }
        let ip: IpAddr = s.parse().with_context(|| format!("DNS 服务器“{s}”无效（填 system 或 IP 地址）"))?;
        Ok(Upstream::Udp(SocketAddr::new(ip, 53)))
    }
}

/// Resolver for direct connections and for evaluating IP rules.
pub struct DirectResolver {
    upstreams: Vec<Upstream>,
    cache: Cache,
}

impl DirectResolver {
    pub fn new(upstreams: Vec<Upstream>) -> Self {
        let upstreams = if upstreams.is_empty() { vec![Upstream::System] } else { upstreams };
        Self { upstreams, cache: Cache::default() }
    }

    pub async fn resolve(&self, name: &str) -> Result<Vec<IpAddr>> {
        if let Some(ips) = self.cache.get(name) {
            return Ok(ips);
        }
        // Ask every upstream at once and take the first non-empty answer: the
        // Windows resolver alone was seen taking 11 s for a cold lookup.
        let mut queries = tokio::task::JoinSet::new();
        for upstream in self.effective_upstreams() {
            let name = name.to_string();
            queries.spawn(async move { query_upstream(&upstream, &name).await });
        }
        let mut last_err = None;
        let mut empty = None;
        while let Some(joined) = queries.join_next().await {
            match joined {
                Ok(Ok((mut ips, ttl))) if !ips.is_empty() => {
                    queries.abort_all();
                    // Prefer IPv4: the common case, and what most direct paths support.
                    ips.sort_by_key(|ip| ip.is_ipv6());
                    ips.dedup();
                    self.cache.put(name, ips.clone(), ttl);
                    return Ok(ips);
                }
                // "No such name" only counts once nobody has a positive answer.
                Ok(Ok((_, ttl))) => empty = Some(ttl),
                Ok(Err(e)) => last_err = Some(e),
                Err(e) => last_err = Some(anyhow::anyhow!("DNS 查询任务失败：{e}")),
            }
        }
        if let Some(ttl) = empty {
            self.cache.put(name, Vec::new(), ttl);
            return Ok(Vec::new());
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("无法解析 {name}")).context(format!("解析 {name}")))
    }
}

/// Public resolvers used in TUN mode when only `system` is configured.
const TUN_FALLBACK_DNS: [&str; 2] = ["223.5.5.5:53", "119.29.29.29:53"];

impl DirectResolver {
    /// In TUN mode the system resolver would send its queries into our own
    /// TUN (and get fake answers), so only explicit servers are used.
    fn effective_upstreams(&self) -> Vec<Upstream> {
        if supernet_netstack::sysnet::bypass_interface().is_none() {
            return self.upstreams.clone();
        }
        let explicit: Vec<Upstream> = self.upstreams.iter().filter(|u| **u != Upstream::System).cloned().collect();
        if explicit.is_empty() {
            TUN_FALLBACK_DNS.iter().map(|s| Upstream::Udp(s.parse().expect("valid"))).collect()
        } else {
            explicit
        }
    }
}

async fn query_upstream(upstream: &Upstream, name: &str) -> Result<(Vec<IpAddr>, u32)> {
    match upstream {
        Upstream::System => tokio::net::lookup_host((name, 0))
            .await
            .map(|addrs| (addrs.map(|a| a.ip()).collect::<Vec<_>>(), 60))
            .map_err(anyhow::Error::from),
        Upstream::Udp(server) => {
            let bind: SocketAddr = if server.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
            let sock = tokio::net::UdpSocket::from_std(supernet_netstack::sysnet::udp_bind(bind)?)?;
            lookup_via(&sock, &[*server], name, true, true).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_answer_round_trip() {
        let query = build_query(0x1234, "www.Example.com", TYPE_A).unwrap();
        let q = parse_query(&query).unwrap();
        assert_eq!(q.name, "www.example.com");
        assert_eq!(q.qtype, TYPE_A);
        let ips: Vec<IpAddr> = vec!["10.66.0.1".parse().unwrap(), "fd66::1".parse().unwrap()];
        let answer = build_answer(&query, &q, &ips, 5);
        let (got, ttl) = parse_response(0x1234, &answer).unwrap();
        assert_eq!(got, vec![ips[0]]);
        assert_eq!(ttl, MIN_TTL); // clamped up from 5
        assert!(parse_response(0x9999, &answer).is_err());
        assert!(parse_response(0x1234, &answer[..20]).is_err());
    }

    #[test]
    fn upstream_parsing() {
        assert_eq!(Upstream::parse("system").unwrap(), Upstream::System);
        assert_eq!(Upstream::parse("223.5.5.5").unwrap(), Upstream::Udp("223.5.5.5:53".parse().unwrap()));
        assert_eq!(Upstream::parse("udp://[::1]:5353").unwrap(), Upstream::Udp("[::1]:5353".parse().unwrap()));
        assert!(Upstream::parse("dns.example").is_err());
    }
}
