//! Live connection list, traffic counters and the in-memory log.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

#[derive(Clone, Debug, Serialize)]
pub struct ConnInfo {
    pub id: u64,
    pub inbound: &'static str,
    pub target: String,
    pub rule: String,
    /// Policy and the node it resolved to, e.g. `代理 → 东京`.
    pub chain: String,
    pub upload: u64,
    pub download: u64,
    pub started_ms: u64,
}

struct Entry {
    info: ConnInfo,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    cancel: Arc<Notify>,
}

#[derive(Default)]
pub struct Tracker {
    next_id: AtomicU64,
    entries: Mutex<HashMap<u64, Entry>>,
    pub total_up: Arc<AtomicU64>,
    pub total_down: Arc<AtomicU64>,
}

/// Removes the connection from the list when dropped.
pub struct ConnGuard {
    tracker: Arc<Tracker>,
    pub id: u64,
    pub up: Arc<AtomicU64>,
    pub down: Arc<AtomicU64>,
    pub cancel: Arc<Notify>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.tracker.entries.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.id);
    }
}

impl Tracker {
    pub fn register(self: &Arc<Self>, inbound: &'static str, target: String, rule: String, chain: String) -> ConnGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let cancel = Arc::new(Notify::new());
        let info = ConnInfo { id, inbound, target, rule, chain, upload: 0, download: 0, started_ms: now_ms() };
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, Entry { info, up: up.clone(), down: down.clone(), cancel: cancel.clone() });
        ConnGuard { tracker: self.clone(), id, up, down, cancel }
    }

    pub fn list(&self) -> Vec<ConnInfo> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut list: Vec<ConnInfo> = entries
            .values()
            .map(|e| ConnInfo { upload: e.up.load(Ordering::Relaxed), download: e.down.load(Ordering::Relaxed), ..e.info.clone() })
            .collect();
        list.sort_by_key(|c| std::cmp::Reverse(c.id));
        list
    }

    pub fn close(&self, id: u64) -> bool {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        match entries.get(&id) {
            Some(e) => {
                e.cancel.notify_one();
                true
            }
            None => false,
        }
    }

    pub fn close_all(&self) {
        for e in self.entries.lock().unwrap_or_else(|e| e.into_inner()).values() {
            e.cancel.notify_one();
        }
    }

    pub fn count(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Wraps the outbound side: bytes written are uploads, bytes read are downloads.
pub struct Counted<S> {
    inner: S,
    up: [Arc<AtomicU64>; 2],
    down: [Arc<AtomicU64>; 2],
}

impl<S> Counted<S> {
    pub fn new(inner: S, guard: &ConnGuard, tracker: &Tracker) -> Self {
        Self {
            inner,
            up: [guard.up.clone(), tracker.total_up.clone()],
            down: [guard.down.clone(), tracker.total_down.clone()],
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = (buf.filled().len() - before) as u64;
        if n > 0 {
            for c in &self.down {
                c.fetch_add(n, Ordering::Relaxed);
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &res {
            for c in &self.up {
                c.fetch_add(*n as u64, Ordering::Relaxed);
            }
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LogLine {
    pub seq: u64,
    pub time_ms: u64,
    pub level: &'static str,
    pub message: String,
}

/// The most recent log lines, for the UI.
pub struct LogBuffer {
    lines: Mutex<(u64, VecDeque<LogLine>)>,
    capacity: usize,
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self { lines: Mutex::new((0, VecDeque::new())), capacity: 1000 }
    }
}

impl LogBuffer {
    pub fn push(&self, level: &'static str, message: String) {
        match level {
            "error" => tracing::error!("{message}"),
            "warn" => tracing::warn!("{message}"),
            _ => tracing::info!("{message}"),
        }
        let mut guard = self.lines.lock().unwrap_or_else(|e| e.into_inner());
        guard.0 += 1;
        let seq = guard.0;
        guard.1.push_back(LogLine { seq, time_ms: now_ms(), level, message });
        while guard.1.len() > self.capacity {
            guard.1.pop_front();
        }
    }

    /// Lines with `seq > after`.
    pub fn since(&self, after: u64) -> Vec<LogLine> {
        let guard = self.lines.lock().unwrap_or_else(|e| e.into_inner());
        guard.1.iter().filter(|l| l.seq > after).cloned().collect()
    }
}
