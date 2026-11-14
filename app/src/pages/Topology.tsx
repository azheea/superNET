import { useRef } from "react";
import { tokens } from "@fluentui/react-components";
import type { MeshStatus, PathKind } from "../api";
import { formatSpeed } from "../util";

/** What each path kind looks like on the map. */
export const pathStyle: Record<PathKind, { label: string; color: string; dash?: string }> = {
  lan: { label: "局域网直连", color: tokens.colorPaletteGreenForeground1 },
  ipv6: { label: "IPv6 直连", color: tokens.colorPaletteTealForeground2 },
  direct: { label: "公网直连", color: tokens.colorBrandForeground1 },
  peer: { label: "设备中继", color: tokens.colorPaletteDarkOrangeForeground1, dash: "7 5" },
  server: { label: "服务器中继", color: tokens.colorPalettePurpleForeground2, dash: "7 5" },
  down: { label: "不通", color: tokens.colorNeutralStroke1, dash: "2 6" },
};

const rank: Record<PathKind, number> = { lan: 0, ipv6: 1, direct: 2, peer: 3, server: 4, down: 5 };

interface Edge {
  a: string;
  b: string;
  kind: PathKind;
  rtt: number | null;
  via: string | null;
  bytes: number;
  rate: number;
}

const W = 680;
const H = 470;

/**
 * The whole network as this device knows it: its own links (live) and the
 * links every other device reported through the coordinator.
 */
export function Topology({ status, selected, onSelect }: { status: MeshStatus; selected: string | null; onSelect: (ip: string | null) => void }) {
  // Byte counters from the previous poll, for traffic rates.
  const prev = useRef<{ t: number; bytes: Map<string, number> }>({ t: 0, bytes: new Map() });
  const me = status.me;
  if (!me) return null;

  const members = status.members.length ? status.members : [me];
  const server = members.find((m) => m.server);
  const others = members.filter((m) => m.ip !== me.ip && !m.server);

  // Positions: this device in the middle, the server on top, the rest around.
  const cx = W / 2;
  const cy = H / 2 + 14;
  const R = Math.min(W, H) / 2 - 62;
  const pos = new Map<string, { x: number; y: number }>();
  pos.set(me.ip, { x: cx, y: cy });
  if (server) pos.set(server.ip, { x: cx, y: cy - R });
  const slots = others.length + (server ? 1 : 0);
  // With the server on top, an odd number of others would put one straight below
  // this device, on the same line as the server link: turn the ring a little.
  const skew = server && others.length % 2 === 1 ? (25 * Math.PI) / 180 : 0;
  others.forEach((m, i) => {
    const angle = -Math.PI / 2 + skew + ((i + (server ? 1 : 0.5)) * 2 * Math.PI) / Math.max(slots, 1);
    pos.set(m.ip, { x: cx + R * 1.18 * Math.cos(angle), y: cy + R * Math.sin(angle) });
  });

  // Edges: ours from live peer state, the others' from their reports.
  const now = performance.now();
  const dt = prev.current.t ? (now - prev.current.t) / 1000 : 0;
  const nextBytes = new Map<string, number>();
  const rateOf = (key: string, bytes: number) => {
    nextBytes.set(key, bytes);
    const before = prev.current.bytes.get(key);
    return dt > 0 && before !== undefined && bytes >= before ? (bytes - before) / dt : 0;
  };
  const edges = new Map<string, Edge>();
  const put = (e: Edge) => {
    const key = [e.a, e.b].sort().join("|");
    const cur = edges.get(key);
    if (!cur || rank[e.kind] < rank[cur.kind] || (e.a === me.ip && cur.a !== me.ip)) edges.set(key, e);
  };
  for (const p of status.peers) {
    const bytes = p.tx_bytes + p.rx_bytes;
    put({ a: me.ip, b: p.ip, kind: p.kind, rtt: p.rtt_ms, via: p.via, bytes, rate: rateOf(`me>${p.ip}`, bytes) });
  }
  for (const l of status.links) {
    if (l.from === me.ip || l.peer === me.ip) continue;
    const bytes = l.tx_bytes + l.rx_bytes;
    const e: Edge = { a: l.from, b: l.peer, kind: l.kind, rtt: l.rtt_ms, via: l.via, bytes, rate: rateOf(`${l.from}>${l.peer}`, bytes) };
    const key = [e.a, e.b].sort().join("|");
    if (!edges.has(key) || rank[e.kind] < rank[edges.get(key)!.kind]) edges.set(key, e);
  }
  prev.current = { t: now, bytes: nextBytes };

  const relaying = new Set<string>();
  for (const e of edges.values()) {
    if (e.kind === "peer" && e.via) relaying.add(e.via);
  }
  if (status.relayed_bytes > 0) relaying.add(me.ip);

  const name = (ip: string) => members.find((m) => m.ip === ip)?.name ?? ip;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="组网拓扑图" style={{ maxHeight: 460, userSelect: "none" }} onClick={() => onSelect(null)}>
      {[...edges.values()].map((e) => {
        const a = pos.get(e.a);
        const b = pos.get(e.b);
        if (!a || !b) return null;
        const st = pathStyle[e.kind];
        // Relayed links bend through the relay (a device, or the server).
        const viaIp = e.kind === "peer" ? e.via : e.kind === "server" ? server?.ip ?? null : null;
        const via = viaIp ? pos.get(viaIp) : undefined;
        let d = `M ${a.x} ${a.y} L ${b.x} ${b.y}`;
        let mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
        if (via && viaIp !== e.a && viaIp !== e.b) {
          const c = { x: 2 * via.x - (a.x + b.x) / 2, y: 2 * via.y - (a.y + b.y) / 2 };
          d = `M ${a.x} ${a.y} Q ${c.x} ${c.y} ${b.x} ${b.y}`;
          // The curve passes through the relay at t = 0.5; label it away from that node.
          const t = 0.28;
          mid = {
            x: (1 - t) * (1 - t) * a.x + 2 * (1 - t) * t * c.x + t * t * b.x,
            y: (1 - t) * (1 - t) * a.y + 2 * (1 - t) * t * c.y + t * t * b.y,
          };
        }
        // Labels sit beside the line (its normal, towards the upper side), not on it.
        const len = Math.hypot(b.x - a.x, b.y - a.y) || 1;
        let off = { x: ((a.y - b.y) / len) * 11, y: ((b.x - a.x) / len) * 11 };
        if (off.y > 0) off = { x: -off.x, y: -off.y };
        off.y += 3;
        const width = 1.6 + Math.min(5, Math.log10(1 + e.rate / 1024) * 1.6);
        const flowing = e.kind !== "down" && e.rate > 512;
        const speed = Math.max(0.35, 3 / (1 + Math.log10(1 + e.rate / 8192)));
        // "Not reachable" needs no label: the dotted line and the legend say it.
        const label = e.kind === "down" ? "" : [e.kind === "peer" && e.via ? `经 ${name(e.via)}` : null, e.rtt != null ? `${e.rtt} ms` : null, e.rate > 512 ? formatSpeed(e.rate) : null].filter(Boolean).join(" · ");
        return (
          <g key={`${e.a}|${e.b}`}>
            <path d={d} fill="none" stroke={st.color} strokeWidth={width} strokeDasharray={st.dash} strokeLinecap="round" opacity={e.kind === "down" ? 0.7 : 0.9} />
            {flowing && (
              <path
                d={d}
                fill="none"
                stroke={tokens.colorNeutralBackground1}
                strokeWidth={Math.max(1, width - 1)}
                strokeDasharray="3 25"
                strokeLinecap="round"
                style={{ animation: `sn-flow ${speed.toFixed(2)}s linear infinite` }}
              />
            )}
            {label && (
              <text x={mid.x + off.x} y={mid.y + off.y} textAnchor="middle" fontSize={11} fill={tokens.colorNeutralForeground2} stroke={tokens.colorNeutralBackground1} strokeWidth={3} paintOrder="stroke">
                {label}
              </text>
            )}
          </g>
        );
      })}
      {members.map((m) => {
        const p = pos.get(m.ip);
        if (!p) return null;
        const isMe = m.ip === me.ip;
        const r = isMe ? 30 : 24;
        const online = isMe || m.online;
        return (
          <g
            key={m.ip}
            transform={`translate(${p.x} ${p.y})`}
            style={{ cursor: "pointer" }}
            onClick={(ev) => {
              ev.stopPropagation();
              onSelect(m.ip);
            }}
          >
            {selected === m.ip && <circle r={r + 6} fill="none" stroke={tokens.colorBrandStroke1} strokeWidth={2} />}
            {m.server ? (
              <rect x={-r} y={-r * 0.8} width={2 * r} height={1.6 * r} rx={6} fill={tokens.colorNeutralBackground1} stroke={online ? tokens.colorPalettePurpleBorderActive : tokens.colorNeutralStroke1} strokeWidth={2} />
            ) : (
              <circle r={r} fill={isMe ? tokens.colorBrandBackground : tokens.colorNeutralBackground1} stroke={online ? tokens.colorBrandStroke1 : tokens.colorNeutralStroke1} strokeWidth={2} strokeDasharray={online ? undefined : "3 3"} />
            )}
            <text textAnchor="middle" dy="0.35em" fontSize={isMe ? 13 : 12} fontWeight={600} fill={isMe ? tokens.colorNeutralForegroundOnBrand : online ? tokens.colorNeutralForeground1 : tokens.colorNeutralForeground4}>
              {isMe ? "本机" : m.server ? "服务器" : [...m.name][0] ?? "?"}
            </text>
            <text y={r + 15} textAnchor="middle" fontSize={12} fill={online ? tokens.colorNeutralForeground1 : tokens.colorNeutralForeground4}>
              {m.name}
            </text>
            <text y={r + 29} textAnchor="middle" fontSize={11} fill={tokens.colorNeutralForeground3}>
              {m.ip}
              {online ? "" : " · 离线"}
            </text>
            {relaying.has(m.ip) && (
              <g transform={`translate(${r * 0.75} ${-r * 0.85})`}>
                <rect x={-14} y={-9} width={28} height={17} rx={8} fill={tokens.colorPaletteDarkOrangeBackground3} />
                <text textAnchor="middle" dy="0.32em" fontSize={10} fill="#fff">
                  中继
                </text>
              </g>
            )}
          </g>
        );
      })}
    </svg>
  );
}
