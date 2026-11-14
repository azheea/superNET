import { useEffect, useRef } from "react";

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export function formatSpeed(bytesPerSec: number): string {
  return `${formatBytes(Math.max(0, Math.round(bytesPerSec)))}/s`;
}

export function formatDuration(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s} 秒`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} 分 ${s % 60} 秒`;
  return `${Math.floor(m / 60)} 时 ${m % 60} 分`;
}

export function formatTime(ms: number): string {
  return new Date(ms).toLocaleTimeString("zh-CN", { hour12: false });
}

/** Run `fn` now and then every `ms` while mounted. */
export function usePolling(fn: () => void | Promise<void>, ms: number) {
  const saved = useRef(fn);
  saved.current = fn;
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      if (!alive) return;
      try {
        await saved.current();
      } catch {
        // Errors surface through the page's own state.
      }
    };
    tick();
    const id = setInterval(tick, ms);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [ms]);
}
