import { useState } from "react";
import {
  Badge,
  Body1,
  Button,
  Caption1,
  Field,
  Input,
  MessageBar,
  MessageBarBody,
  Spinner,
  Subtitle1,
  Switch,
  makeStyles,
  tokens,
} from "@fluentui/react-components";
import { api, errorText, type MeshView, type PeerStatus } from "../api";
import { useNotify } from "../App";
import { formatBytes, usePolling } from "../util";
import { PageHeader, usePageStyles } from "./common";
import { Topology, pathStyle } from "./Topology";

const useStyles = makeStyles({
  legend: { display: "flex", flexWrap: "wrap", gap: tokens.spacingHorizontalL },
  swatch: { display: "inline-block", width: "22px", height: "0", verticalAlign: "middle", marginRight: "6px", borderTopWidth: "3px" },
  table: { width: "100%", borderCollapse: "collapse", "& td, & th": { textAlign: "left", padding: "6px 8px", borderBottom: `1px solid ${tokens.colorNeutralStroke2}` } },
  detail: { display: "grid", gridTemplateColumns: "max-content 1fr", columnGap: tokens.spacingHorizontalL, rowGap: tokens.spacingVerticalXS },
});

export function NetworkPage() {
  const s = usePageStyles();
  const st = useStyles();
  const notify = useNotify();
  const [view, setView] = useState<MeshView | null>(null);
  const [link, setLink] = useState("");
  const [name, setName] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  usePolling(async () => setView(await api.meshStatus()), 1000);

  const act = async (fn: () => Promise<unknown>, ok?: string) => {
    setBusy(true);
    try {
      await fn();
      if (ok) notify(ok);
      setView(await api.meshStatus());
    } catch (e) {
      notify(errorText(e), "error");
    } finally {
      setBusy(false);
    }
  };

  if (!view) return <Spinner label="加载中…" />;
  const status = view.status;
  const me = status?.me;
  const deviceName = name ?? view.name;

  return (
    <div className={s.page}>
      <PageHeader title="组网" hint="网内设备用虚拟地址互相访问：能直连就直连，连不上时由其他设备或服务器转发，全程加密。" />

      {!view.tun_active && (
        <MessageBar intent="warning">
          <MessageBarBody>组网需要开启 TUN 模式：到“概览”页打开 TUN 模式并连接。</MessageBarBody>
        </MessageBar>
      )}
      {status?.last_error && (
        <MessageBar intent="error">
          <MessageBarBody>{status.last_error}</MessageBarBody>
        </MessageBar>
      )}

      {!view.configured ? (
        <section className={s.card}>
          <Subtitle1>加入网络</Subtitle1>
          <Field label="邀请链接" hint="在服务器上运行 supernet-coord invite 获取，形如 supernet-net://…">
            <Input value={link} onChange={(_, d) => setLink(d.value)} placeholder="supernet-net://203.0.113.10:19190?k=…" />
          </Field>
          <Field label="本机名称">
            <Input value={deviceName} onChange={(_, d) => setName(d.value)} />
          </Field>
          <div className={s.row}>
            <Button appearance="primary" disabled={busy || !link.trim()} onClick={() => act(() => api.meshJoin(link, deviceName), "已保存，正在加入网络")}>
              加入
            </Button>
          </div>
        </section>
      ) : (
        <section className={s.card}>
          <div className={s.row}>
            <Subtitle1 className={s.grow}>
              {view.network ?? "superNET"}
              {me ? `：本机 ${me.ip}` : ""}
            </Subtitle1>
            {view.running ? (
              me ? (
                <Badge color="success">已加入</Badge>
              ) : (
                <Badge color="warning">正在连接协调服务…</Badge>
              )
            ) : (
              <Badge color="informative">未运行</Badge>
            )}
          </div>
          <Caption1 className={s.muted}>
            协调服务 {view.coordinator}
            {status?.observed ? `；公网上看到的本机地址 ${status.observed}` : ""}
            {status?.coord_seen_s != null ? `；${status.coord_seen_s} 秒前通信` : ""}
            {status && status.relayed_bytes > 0 ? `；已为别人中继 ${formatBytes(status.relayed_bytes)}` : ""}
          </Caption1>
          <div className={s.row}>
            <Switch checked={view.enabled} disabled={busy} label="启用组网" onChange={(_, d) => act(() => api.meshUpdate(d.checked, view.relay, deviceName))} />
            <Switch checked={view.relay} disabled={busy} label="允许为别人中继" onChange={(_, d) => act(() => api.meshUpdate(view.enabled, d.checked, deviceName))} />
          </div>
          <div className={s.row}>
            <Field label="本机名称">
              <Input value={deviceName} onChange={(_, d) => setName(d.value)} />
            </Field>
            <Button disabled={busy || name === null} onClick={() => act(() => api.meshUpdate(view.enabled, view.relay, deviceName), "名称已更新")}>
              保存名称
            </Button>
            <Button disabled={busy} onClick={() => act(api.meshLeave, "已退出组网")}>
              退出网络
            </Button>
          </div>
        </section>
      )}

      {status && me && (
        <section className={s.card}>
          <Subtitle1>拓扑</Subtitle1>
          <Topology status={status} selected={selected} onSelect={setSelected} />
          <div className={st.legend}>
            {Object.entries(pathStyle).map(([k, v]) => (
              <Caption1 key={k}>
                <span className={st.swatch} style={{ borderTopColor: v.color, borderTopStyle: v.dash ? "dashed" : "solid" }} />
                {v.label}
              </Caption1>
            ))}
            <Caption1 className={s.muted}>线越粗流量越大；点设备看详情</Caption1>
          </div>
          {selected && <PeerDetail ip={selected} view={view} />}
        </section>
      )}

      {status && status.peers.length > 0 && (
        <section className={s.card}>
          <Subtitle1>设备</Subtitle1>
          <table className={st.table}>
            <thead>
              <tr>
                <th>名称</th>
                <th>地址</th>
                <th>路径</th>
                <th>延迟</th>
                <th>发送 / 接收</th>
              </tr>
            </thead>
            <tbody>
              {status.peers.map((p) => (
                <tr key={p.ip} onClick={() => setSelected(p.ip)} style={{ cursor: "pointer" }}>
                  <td>
                    <Body1>{p.name}</Body1>
                  </td>
                  <td>{p.ip}</td>
                  <td style={{ color: pathStyle[p.kind].color }}>{pathLabel(p, status.members)}</td>
                  <td>{p.rtt_ms != null ? `${p.rtt_ms} ms` : "—"}</td>
                  <td>
                    {formatBytes(p.tx_bytes)} / {formatBytes(p.rx_bytes)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}

function pathLabel(p: PeerStatus, members: { ip: string; name: string }[]) {
  if (!p.online) return "离线";
  if (p.kind === "peer" && p.via) return `经 ${members.find((m) => m.ip === p.via)?.name ?? p.via} 中继`;
  return pathStyle[p.kind].label;
}

function PeerDetail({ ip, view }: { ip: string; view: MeshView }) {
  const st = useStyles();
  const status = view.status!;
  const member = status.members.find((m) => m.ip === ip);
  const peer = status.peers.find((p) => p.ip === ip);
  if (ip === status.me?.ip) {
    return (
      <div className={st.detail}>
        <Caption1>本机</Caption1>
        <Body1>
          {status.me.name} · {status.me.ip}
        </Body1>
        <Caption1>公网地址</Caption1>
        <Body1>{status.observed ?? "—"}</Body1>
        <Caption1>为别人中继</Caption1>
        <Body1>{formatBytes(status.relayed_bytes)}</Body1>
      </div>
    );
  }
  if (!member) return null;
  return (
    <div className={st.detail}>
      <Caption1>设备</Caption1>
      <Body1>
        {member.name} · {member.ip}
        {member.server ? "（服务器）" : ""}
      </Body1>
      <Caption1>状态</Caption1>
      <Body1>{member.online ? `在线${member.last_seen_s != null ? `（${member.last_seen_s} 秒前）` : ""}` : "离线"}</Body1>
      {peer && (
        <>
          <Caption1>路径</Caption1>
          <Body1>
            {pathLabel(peer, status.members)}
            {peer.endpoint ? ` · ${peer.endpoint}` : ""}
            {peer.rtt_ms != null ? ` · ${peer.rtt_ms} ms` : ""}
          </Body1>
          <Caption1>候选地址</Caption1>
          <Body1>{peer.candidates.join("，") || "—"}</Body1>
          <Caption1>握手</Caption1>
          <Body1>{peer.handshake_s != null ? `${peer.handshake_s} 秒前` : "还没有"}</Body1>
          <Caption1>流量</Caption1>
          <Body1>
            发 {formatBytes(peer.tx_bytes)} / 收 {formatBytes(peer.rx_bytes)}
          </Body1>
        </>
      )}
      <Caption1>允许中继</Caption1>
      <Body1>{member.relay ? "是" : "否"}</Body1>
    </div>
  );
}
