// Typed wrappers around the Tauri commands. Outside Tauri (plain `npm run dev`
// in a browser) a small in-memory mock answers instead, so the UI can be
// previewed without the native shell.

import { invoke } from "@tauri-apps/api/core";

export type Mode = "rule" | "global" | "direct";

export interface Status {
  running: boolean;
  listen: string | null;
  mode: Mode;
  connections: number;
  total_upload: number;
  total_download: number;
}

export interface NodeStatus {
  name: string;
  kind: "wireguard" | "hysteria2";
  endpoint: string;
  active: boolean;
  since_handshake_secs: number | null;
  tx_bytes: number;
  rx_bytes: number;
}

export interface GroupView {
  name: string;
  nodes: string[];
  selected: string;
}

export interface Overview {
  status: Status;
  mode: Mode;
  port: number;
  system_proxy: boolean;
  system_proxy_supported: boolean;
  allow_lan: boolean;
  tun: boolean;
  tun_active: boolean;
  is_admin: boolean;
  nodes: NodeStatus[];
  groups: GroupView[];
  warnings: string[];
}

export interface RouteInfo {
  target: string;
  rule: string;
  policy: string;
  chain: string;
  outbound: string;
  resolved: string[];
}

export interface ConnInfo {
  id: number;
  inbound: string;
  target: string;
  rule: string;
  chain: string;
  upload: number;
  download: number;
  started_ms: number;
}

export interface LogLine {
  seq: number;
  time_ms: number;
  level: "info" | "warn" | "error";
  message: string;
}

export interface Settings {
  port: number;
  allow_lan: boolean;
  auto_connect: boolean;
  dns: string[];
  test_url: string;
  geoip: string | null;
}

export interface Exported {
  config: string;
  link: string;
}

export type PathKind = "lan" | "ipv6" | "direct" | "peer" | "server" | "down";

export interface MemberView {
  ip: string;
  name: string;
  pubkey: string;
  endpoints: string[];
  online: boolean;
  relay: boolean;
  server: boolean;
  last_seen_s: number | null;
}

export interface LinkView {
  from: string;
  peer: string;
  kind: PathKind;
  rtt_ms: number | null;
  via: string | null;
  tx_bytes: number;
  rx_bytes: number;
}

export interface PeerStatus {
  ip: string;
  name: string;
  online: boolean;
  server: boolean;
  relay: boolean;
  kind: PathKind;
  rtt_ms: number | null;
  via: string | null;
  endpoint: string | null;
  candidates: string[];
  tx_bytes: number;
  rx_bytes: number;
  handshake_s: number | null;
}

export interface MeshStatus {
  network: string;
  coordinator: string;
  me: MemberView | null;
  observed: string | null;
  prefix: number;
  peers: PeerStatus[];
  links: LinkView[];
  members: MemberView[];
  relayed_bytes: number;
  last_error: string | null;
  coord_seen_s: number | null;
}

export interface MeshView {
  configured: boolean;
  enabled: boolean;
  relay: boolean;
  name: string;
  coordinator: string | null;
  network: string | null;
  tun_active: boolean;
  running: boolean;
  status: MeshStatus | null;
}

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
// Served by the headless `supernet --web` (it marks index.html).
const inWeb = typeof window !== "undefined" && "__SUPERNET_WEB__" in window;

/** The web console's token: from the start link (#token=…), then kept for this browser. */
function webToken(): string {
  const key = "supernet-web-token";
  const m = /token=([0-9a-zA-Z_-]+)/.exec(window.location.hash);
  if (m) {
    try {
      localStorage.setItem(key, m[1]);
    } catch {
      /* private mode: the link still works for this tab */
    }
    // Keep the token out of the address bar (screenshots, history).
    history.replaceState(null, "", window.location.pathname + window.location.search);
    (window as unknown as { __supernetToken?: string }).__supernetToken = m[1];
    return m[1];
  }
  const kept = (window as unknown as { __supernetToken?: string }).__supernetToken;
  if (kept) return kept;
  try {
    return localStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
}

async function web<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const r = await fetch(`/api/${cmd}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${webToken()}` },
    body: JSON.stringify(args ?? {}),
  });
  const j = (await r.json().catch(() => ({}))) as { ok?: T; error?: string };
  if (!r.ok) throw j.error ?? `${r.status} ${r.statusText}`;
  return j.ok as T;
}

function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (inTauri) return invoke<T>(cmd, args);
  return inWeb ? web<T>(cmd, args) : mock<T>(cmd, args ?? {});
}

export const api = {
  overview: () => call<Overview>("overview"),
  connect: () => call<Status>("connect"),
  disconnect: () => call<Status>("disconnect"),
  setMode: (mode: Mode) => call<void>("set_mode", { mode }),
  setSystemProxy: (enabled: boolean) => call<void>("set_system_proxy", { enabled }),
  setTun: (enabled: boolean) => call<void>("set_tun", { enabled }),
  restartAsAdmin: () => call<void>("restart_as_admin"),
  selectNode: (group: string, node: string) => call<void>("select_node", { group, node }),
  importNode: (text: string, name: string) => call<string>("import_node", { text, name }),
  removeNode: (name: string) => call<void>("remove_node", { name }),
  exportNode: (name: string) => call<Exported>("export_node", { name }),
  probeNode: (name: string) => call<number>("probe_node", { name }),
  getRules: () => call<string>("get_rules"),
  saveRules: (text: string) => call<string[]>("save_rules", { text }),
  explain: (target: string) => call<RouteInfo>("explain", { target }),
  connections: () => call<ConnInfo[]>("connections"),
  closeConnection: (id: number) => call<boolean>("close_connection", { id }),
  logs: (after: number) => call<LogLine[]>("logs", { after }),
  meshStatus: () => call<MeshView>("mesh_status"),
  meshJoin: (link: string, name: string) => call<void>("mesh_join", { link, name }),
  meshUpdate: (enabled: boolean, relay: boolean, name: string) => call<void>("mesh_update", { enabled, relay, name }),
  meshLeave: () => call<void>("mesh_leave"),
  getSettings: () => call<Settings>("get_settings"),
  saveSettings: (settings: Settings) => call<string[]>("save_settings", { settings }),
};

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : JSON.stringify(e);
}

// ---------------------------------------------------------------- mock

const state = {
  running: false,
  mode: "rule" as Mode,
  systemProxy: false,
  tun: false,
  rules: "DOMAIN-SUFFIX,github.com,代理\nIP-CIDR,10.66.0.0/24,代理,no-resolve\nMATCH,DIRECT",
  nodes: [{ name: "东京", endpoint: "203.0.113.10:51820" }],
  selected: "东京",
  up: 0,
  down: 0,
  seq: 0,
  mesh: true,
  meshRelay: true,
  meshBytes: 0,
  settings: { port: 7890, allow_lan: false, auto_connect: false, dns: ["system"], test_url: "http://www.gstatic.com/generate_204", geoip: null } as Settings,
};

async function mock<T>(cmd: string, args: Record<string, unknown>): Promise<T> {
  await new Promise((r) => setTimeout(r, 120));
  if (state.running) {
    state.up += 20_000 + Math.random() * 40_000;
    state.down += 200_000 + Math.random() * 600_000;
  }
  const status = (): Status => ({
    running: state.running,
    listen: state.running ? `127.0.0.1:${state.settings.port}` : null,
    mode: state.mode,
    connections: state.running ? 3 : 0,
    total_upload: Math.round(state.up),
    total_download: Math.round(state.down),
  });
  const r = (v: unknown) => v as T;
  switch (cmd) {
    case "overview":
      return r({
        status: status(),
        mode: state.mode,
        port: state.settings.port,
        system_proxy: state.systemProxy,
        system_proxy_supported: true,
        allow_lan: state.settings.allow_lan,
        tun: state.tun,
        tun_active: state.running && state.tun,
        is_admin: false,
        nodes: state.nodes.map((n) => ({ ...n, kind: "wireguard" as const, active: state.running, since_handshake_secs: state.running ? 12 : null, tx_bytes: Math.round(state.up), rx_bytes: Math.round(state.down) })),
        groups: state.nodes.length ? [{ name: "代理", nodes: state.nodes.map((n) => n.name), selected: state.selected }] : [],
        warnings: [],
      });
    case "connect":
      state.running = true;
      return r(status());
    case "disconnect":
      state.running = false;
      return r(status());
    case "set_mode":
      state.mode = args.mode as Mode;
      return r(undefined);
    case "set_tun":
      state.tun = args.enabled as boolean;
      return r(undefined);
    case "restart_as_admin":
      return r(undefined);
    case "set_system_proxy":
      state.systemProxy = args.enabled as boolean;
      return r(undefined);
    case "select_node":
      state.selected = args.node as string;
      return r(undefined);
    case "import_node": {
      const name = (args.name as string) || `节点 ${state.nodes.length + 1}`;
      state.nodes.push({ name, endpoint: "198.51.100.7:51820" });
      return r(name);
    }
    case "remove_node":
      state.nodes = state.nodes.filter((n) => n.name !== args.name);
      return r(undefined);
    case "export_node":
      return r({ config: "[Interface]\nPrivateKey = …\n\n[Peer]\nPublicKey = …", link: "supernet://example#%E4%B8%9C%E4%BA%AC" });
    case "probe_node":
      return r(40 + Math.round(Math.random() * 80));
    case "get_rules":
      return r(state.rules);
    case "save_rules":
      state.rules = args.text as string;
      return r([]);
    case "explain":
      return r({ target: String(args.target), rule: "DOMAIN-SUFFIX,github.com", policy: "代理", chain: `代理 → ${state.selected}`, outbound: state.selected, resolved: [] });
    case "connections":
      return r(
        state.running
          ? [
              { id: 3, inbound: "http", target: "api.github.com:443", rule: "DOMAIN-SUFFIX,github.com", chain: `代理 → ${state.selected}`, upload: 4_210, download: 88_304, started_ms: Date.now() - 4_000 },
              { id: 2, inbound: "socks5", target: "10.66.0.5:22", rule: "IP-CIDR,10.66.0.0/24", chain: `代理 → ${state.selected}`, upload: 12_000, download: 9_800, started_ms: Date.now() - 95_000 },
              { id: 1, inbound: "http", target: "www.baidu.com:443", rule: "MATCH", chain: "DIRECT", upload: 2_400, download: 310_000, started_ms: Date.now() - 20_000 },
            ]
          : [],
      );
    case "close_connection":
      return r(true);
    case "logs": {
      const after = args.after as number;
      if (!state.running || Math.random() < 0.5) return r([]);
      state.seq += 1;
      return r(state.seq > after ? [{ seq: state.seq, time_ms: Date.now(), level: "info", message: `api.github.com:443 → 代理 → ${state.selected}（DOMAIN-SUFFIX,github.com）` }] : []);
    }
    case "mesh_status":
      return r(mockMesh());
    case "mesh_join":
      state.mesh = true;
      return r(undefined);
    case "mesh_update":
      state.meshRelay = args.relay as boolean;
      return r(undefined);
    case "mesh_leave":
      state.mesh = false;
      return r(undefined);
    case "get_settings":
      return r({ ...state.settings });
    case "save_settings":
      state.settings = args.settings as Settings;
      return r([]);
  }
  throw new Error(`mock: unknown command ${cmd}`);
}

/** A five-device network with every kind of path, for previewing the UI. */
function mockMesh(): MeshView {
  state.meshBytes += 40_000 + Math.random() * 400_000;
  const b = Math.round(state.meshBytes);
  const m = (ip: string, name: string, extra: Partial<MemberView> = {}): MemberView => ({
    ip, name, pubkey: "…", endpoints: [], online: true, relay: true, server: false, last_seen_s: 3, ...extra,
  });
  const members = [
    m("10.66.0.1", "服务器", { server: true, relay: false }),
    m("10.66.0.3", "台式机"),
    m("10.66.0.4", "笔记本"),
    m("10.66.0.5", "手机"),
    m("10.66.0.6", "公司电脑"),
    m("10.66.0.7", "NAS", { online: false }),
  ];
  const peer = (ip: string, name: string, kind: PathKind, rtt: number | null, via: string | null, k: number): PeerStatus => ({
    ip, name, online: kind !== "down", server: ip === "10.66.0.1", relay: true, kind, rtt_ms: rtt, via,
    endpoint: kind === "lan" ? "192.168.31.20:41641" : kind === "ipv6" ? "[2001:db8::5]:41641" : null,
    candidates: ["192.168.31.20:41641", "117.136.0.8:30112"], tx_bytes: Math.round(b * k), rx_bytes: Math.round(b * k * 1.7), handshake_s: 12,
  });
  const peers = [
    peer("10.66.0.1", "服务器", "direct", 168, null, 0.05),
    peer("10.66.0.4", "笔记本", "lan", 2, null, 1),
    peer("10.66.0.5", "手机", "ipv6", 31, null, 0.3),
    peer("10.66.0.6", "公司电脑", "peer", 58, "10.66.0.4", 0.2),
    peer("10.66.0.7", "NAS", "down", null, null, 0),
  ];
  const link = (from: string, to: string, kind: PathKind, rtt: number | null, via: string | null = null): LinkView => ({
    from, peer: to, kind, rtt_ms: rtt, via, tx_bytes: b / 3, rx_bytes: b / 2,
  });
  return {
    configured: state.mesh, enabled: true, relay: state.meshRelay, name: "台式机", coordinator: "203.0.113.10:19190",
    network: "superNET", tun_active: true, running: state.mesh,
    status: state.mesh
      ? {
          network: "superNET", coordinator: "203.0.113.10:19190", me: members[1], observed: "198.51.100.5:41641", prefix: 24,
          peers, members, relayed_bytes: Math.round(b / 9), last_error: null, coord_seen_s: 2,
          links: [
            link("10.66.0.4", "10.66.0.5", "direct", 44),
            link("10.66.0.4", "10.66.0.6", "lan", 3),
            link("10.66.0.5", "10.66.0.6", "server", 210),
            link("10.66.0.4", "10.66.0.1", "direct", 170),
          ],
        }
      : null,
  };
}
