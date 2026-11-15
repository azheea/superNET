import { useState } from "react";
import {
  Badge,
  Body1,
  Button,
  Caption1,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Field,
  Input,
  MessageBar,
  MessageBarBody,
  Spinner,
  Subtitle1,
  Textarea,
} from "@fluentui/react-components";
import { AddRegular, CopyRegular, DeleteRegular, ShareRegular, TopSpeedRegular } from "@fluentui/react-icons";
import { api, errorText, type Exported, type NodeStatus } from "../api";
import { useNotify } from "../App";
import { formatBytes, usePolling } from "../util";
import { PageHeader, usePageStyles } from "./common";

export function NodesPage() {
  const s = usePageStyles();
  const notify = useNotify();
  const [nodes, setNodes] = useState<NodeStatus[] | null>(null);
  const [latency, setLatency] = useState<Record<string, string>>({});
  const [adding, setAdding] = useState(false);
  const [exported, setExported] = useState<{ name: string; data: Exported } | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);

  const refresh = async () => setNodes((await api.overview()).nodes);
  usePolling(refresh, 2000);

  const probe = async (name: string) => {
    setLatency((l) => ({ ...l, [name]: "测速中…" }));
    try {
      const ms = await api.probeNode(name);
      setLatency((l) => ({ ...l, [name]: `${ms} ms` }));
    } catch (e) {
      setLatency((l) => ({ ...l, [name]: "失败" }));
      notify(errorText(e), "error");
    }
    refresh();
  };

  const exportNode = async (name: string) => {
    try {
      setExported({ name, data: await api.exportNode(name) });
    } catch (e) {
      notify(errorText(e), "error");
    }
  };

  const remove = async (name: string) => {
    try {
      await api.removeNode(name);
      notify(`已删除 ${name}`);
      setRemoving(null);
      refresh();
    } catch (e) {
      notify(errorText(e), "error");
    }
  };

  if (!nodes) return <Spinner label="加载中…" />;

  return (
    <div className={s.page}>
      <PageHeader
        title="节点"
        hint="节点是你自己的 WireGuard 服务器。命中规则的流量从这里出去。"
        actions={
          <Button appearance="primary" icon={<AddRegular />} onClick={() => setAdding(true)}>
            添加节点
          </Button>
        }
      />

      {nodes.length === 0 && (
        <MessageBar intent="info">
          <MessageBarBody>还没有节点。点“添加节点”，粘贴服务器生成的配置或链接。</MessageBarBody>
        </MessageBar>
      )}

      {nodes.map((n) => (
        <section key={n.name} className={s.card}>
          <div className={s.header}>
            <div className={s.grow}>
              <div className={s.row}>
                <Subtitle1>{n.name}</Subtitle1>
                <HandshakeBadge node={n} />
                {latency[n.name] && <Badge appearance="outline">{latency[n.name]}</Badge>}
              </div>
              <Caption1 className={`${s.muted} mono`}>{n.endpoint}</Caption1>
              {n.active && (
                <div>
                  <Caption1 className={s.muted}>
                    已发送 {formatBytes(n.tx_bytes)} · 已接收 {formatBytes(n.rx_bytes)}
                  </Caption1>
                </div>
              )}
            </div>
            <div className={s.row}>
              <Button icon={<TopSpeedRegular />} onClick={() => probe(n.name)}>
                测速
              </Button>
              <Button icon={<ShareRegular />} onClick={() => exportNode(n.name)}>
                导出
              </Button>
              <Button icon={<DeleteRegular />} onClick={() => setRemoving(n.name)}>
                删除
              </Button>
            </div>
          </div>
        </section>
      ))}

      <AddDialog
        open={adding}
        onClose={() => setAdding(false)}
        onAdded={(name) => {
          setAdding(false);
          notify(`已添加 ${name}`);
          refresh();
        }}
      />

      <Dialog open={exported !== null} onOpenChange={(_, d) => !d.open && setExported(null)}>
        <DialogSurface>
          <DialogBody>
            <DialogTitle>导出 {exported?.name}</DialogTitle>
            <DialogContent className={s.page}>
              <MessageBar intent="warning">
                <MessageBarBody>导出内容包含这个节点的私钥，只发给你自己的设备。</MessageBarBody>
              </MessageBar>
              <Field label="supernet:// 链接">
                <Textarea readOnly className="mono" value={exported?.data.link ?? ""} rows={3} />
              </Field>
              <Field label="WireGuard 配置">
                <Textarea readOnly className="mono" value={exported?.data.config ?? ""} rows={10} />
              </Field>
            </DialogContent>
            <DialogActions>
              <Button icon={<CopyRegular />} onClick={() => copy(exported?.data.link ?? "", notify)}>
                复制链接
              </Button>
              <Button icon={<CopyRegular />} onClick={() => copy(exported?.data.config ?? "", notify)}>
                复制配置
              </Button>
              <Button appearance="primary" onClick={() => setExported(null)}>
                关闭
              </Button>
            </DialogActions>
          </DialogBody>
        </DialogSurface>
      </Dialog>

      <Dialog open={removing !== null} onOpenChange={(_, d) => !d.open && setRemoving(null)}>
        <DialogSurface>
          <DialogBody>
            <DialogTitle>删除节点</DialogTitle>
            <DialogContent>
              <Body1>确定删除“{removing}”？删除后需要重新导入配置才能恢复。</Body1>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setRemoving(null)}>取消</Button>
              <Button appearance="primary" onClick={() => removing && remove(removing)}>
                删除
              </Button>
            </DialogActions>
          </DialogBody>
        </DialogSurface>
      </Dialog>
    </div>
  );
}

function HandshakeBadge({ node }: { node: NodeStatus }) {
  if (node.kind === "hysteria2" || node.kind === "tuic") {
    const label = node.kind === "tuic" ? "TUIC" : "Hysteria2";
    return node.active ? <Badge appearance="tint" color="success">{label} · 已连接</Badge> : <Badge appearance="tint" color="informative">{label}</Badge>;
  }
  if (!node.active) return <Badge appearance="tint" color="informative">未使用</Badge>;
  const secs = node.since_handshake_secs;
  if (secs === null) return <Badge appearance="tint" color="warning">握手中</Badge>;
  // WireGuard re-handshakes every two minutes while traffic flows.
  if (secs > 180) return <Badge appearance="tint" color="warning">{Math.round(secs / 60)} 分钟前握手</Badge>;
  return <Badge appearance="tint" color="success">在线</Badge>;
}

async function copy(text: string, notify: ReturnType<typeof useNotify>) {
  try {
    await navigator.clipboard.writeText(text);
    notify("已复制");
  } catch (e) {
    notify(errorText(e), "error");
  }
}

function AddDialog({ open, onClose, onAdded }: { open: boolean; onClose: () => void; onAdded: (name: string) => void }) {
  const s = usePageStyles();
  const [name, setName] = useState("");
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!text.trim()) {
      setError("请粘贴配置或链接");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const added = await api.importNode(text, name);
      setName("");
      setText("");
      onAdded(added);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(_, d) => !d.open && onClose()}>
      <DialogSurface>
        <DialogBody>
          <DialogTitle>添加节点</DialogTitle>
          <DialogContent className={s.page}>
            <Field label="名称" hint="留空则使用链接里的名称或自动编号">
              <Input value={name} onChange={(_, d) => setName(d.value)} placeholder="例如：东京" />
            </Field>
            <Field label="配置" validationState={error ? "error" : "none"} validationMessage={error ?? undefined}>
              <Textarea
                className="mono"
                rows={12}
                value={text}
                onChange={(_, d) => {
                  setText(d.value);
                  setError(null);
                }}
                placeholder={"粘贴 WireGuard 配置：\n[Interface]\nPrivateKey = …\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = …\nEndpoint = 服务器:51820\n\n或 supernet:// 链接\n或 Hysteria2 分享链接：hysteria2://密码@域名:端口/?sni=…\n或 TUIC 分享链接：tuic://UUID:密码@域名:端口/?sni=…"}
              />
            </Field>
          </DialogContent>
          <DialogActions>
            <Button onClick={onClose}>取消</Button>
            <Button appearance="primary" disabled={busy} onClick={submit} icon={busy ? <Spinner size="tiny" /> : undefined}>
              导入
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}
