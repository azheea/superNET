import { useRef, useState, type ReactNode } from "react";
import {
  Body1,
  Button,
  Caption1,
  Dropdown,
  MessageBar,
  MessageBarBody,
  Option,
  Radio,
  RadioGroup,
  Spinner,
  Subtitle1,
  Switch,
  Text,
  makeStyles,
  mergeClasses,
  tokens,
} from "@fluentui/react-components";
import { ArrowDownRegular, ArrowUpRegular, PlugConnectedRegular, PowerRegular } from "@fluentui/react-icons";
import { api, errorText, type Mode, type Overview } from "../api";
import { useNotify } from "../App";
import { formatBytes, formatSpeed, usePolling } from "../util";
import { PageHeader, usePageStyles } from "./common";

const useStyles = makeStyles({
  hero: { flexDirection: "row", alignItems: "center", gap: tokens.spacingHorizontalXL },
  power: { minWidth: "132px", height: "52px", fontSize: tokens.fontSizeBase400 },
  stats: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: tokens.spacingHorizontalM },
  stat: { display: "flex", flexDirection: "column", gap: tokens.spacingVerticalXS },
  value: { fontSize: tokens.fontSizeBase500, fontWeight: tokens.fontWeightSemibold },
  online: { color: tokens.colorPaletteGreenForeground1 },
});

const modeHints: Record<Mode, string> = {
  rule: "按规则分流：命中规则的走节点，其余直连",
  global: "全部流量走当前节点",
  direct: "全部直连，不经过任何节点",
};

export function HomePage() {
  const s = usePageStyles();
  const st = useStyles();
  const notify = useNotify();
  const [ov, setOv] = useState<Overview | null>(null);
  const [busy, setBusy] = useState(false);
  const [speed, setSpeed] = useState({ up: 0, down: 0 });
  const last = useRef<{ t: number; up: number; down: number } | null>(null);

  const refresh = async () => {
    const next = await api.overview();
    const now = performance.now();
    const prev = last.current;
    if (prev && next.status.running) {
      const dt = (now - prev.t) / 1000;
      setSpeed({ up: (next.status.total_upload - prev.up) / dt, down: (next.status.total_download - prev.down) / dt });
    } else if (!next.status.running) {
      setSpeed({ up: 0, down: 0 });
    }
    last.current = { t: now, up: next.status.total_upload, down: next.status.total_download };
    setOv(next);
  };
  usePolling(refresh, 1000);

  const act = async (fn: () => Promise<unknown>, ok?: string) => {
    setBusy(true);
    try {
      await fn();
      if (ok) notify(ok);
      await refresh();
    } catch (e) {
      notify(errorText(e), "error");
    } finally {
      setBusy(false);
    }
  };

  if (!ov) return <Spinner label="加载中…" />;
  const running = ov.status.running;

  return (
    <div className={s.page}>
      <PageHeader title="概览" />

      {ov.warnings.map((w) => (
        <MessageBar key={w} intent="warning">
          <MessageBarBody>{w}</MessageBarBody>
        </MessageBar>
      ))}
      {ov.nodes.length === 0 && (
        <MessageBar intent="info">
          <MessageBarBody>还没有节点。到“节点”页粘贴 WireGuard 配置、supernet://、hysteria2:// 或 tuic:// 链接即可添加。</MessageBarBody>
        </MessageBar>
      )}

      <section className={mergeClasses(s.card, st.hero)}>
        <Button
          className={st.power}
          appearance={running ? "secondary" : "primary"}
          icon={busy ? <Spinner size="tiny" /> : <PowerRegular />}
          disabled={busy}
          onClick={() => act(running ? api.disconnect : api.connect, running ? "已断开" : "已连接")}
        >
          {running ? "断开" : "连接"}
        </Button>
        <div className={s.grow}>
          <Subtitle1 className={running ? st.online : undefined}>{running ? "已连接" : "未连接"}</Subtitle1>
          <div>
            <Caption1 className={s.muted}>
              {running
                ? `本地代理 ${ov.status.listen}（HTTP / SOCKS5）${ov.system_proxy ? "，已设为系统代理" : ""}`
                : `连接后在 127.0.0.1:${ov.port} 提供 HTTP / SOCKS5 代理`}
            </Caption1>
          </div>
        </div>
      </section>

      <section className={st.stats}>
        <Stat label="上传" icon={<ArrowUpRegular />} value={formatSpeed(speed.up)} />
        <Stat label="下载" icon={<ArrowDownRegular />} value={formatSpeed(speed.down)} />
        <Stat label="活动连接" icon={<PlugConnectedRegular />} value={String(ov.status.connections)} />
        <Stat label="累计流量" value={`${formatBytes(ov.status.total_upload)} / ${formatBytes(ov.status.total_download)}`} />
      </section>

      <section className={s.card}>
        <Subtitle1>模式</Subtitle1>
        <RadioGroup layout="horizontal" value={ov.mode} onChange={(_, d) => act(() => api.setMode(d.value as Mode))}>
          <Radio value="rule" label="规则" />
          <Radio value="global" label="全局" />
          <Radio value="direct" label="直连" />
        </RadioGroup>
        <Caption1 className={s.muted}>{modeHints[ov.mode]}</Caption1>
      </section>

      {ov.groups.length > 0 && (
        <section className={s.card}>
          <Subtitle1>出口节点</Subtitle1>
          {ov.groups.map((g) => (
            <div key={g.name} className={s.row}>
              <Body1 style={{ minWidth: 64 }}>{g.name}</Body1>
              <Dropdown
                value={g.selected}
                selectedOptions={[g.selected]}
                onOptionSelect={(_, d) => d.optionValue && act(() => api.selectNode(g.name, d.optionValue!), `${g.name} 已切换到 ${d.optionValue}`)}
              >
                {g.nodes.map((n) => (
                  <Option key={n} value={n}>
                    {n === "DIRECT" ? "DIRECT（直连）" : n}
                  </Option>
                ))}
              </Dropdown>
            </div>
          ))}
        </section>
      )}

      <section className={s.card}>
        <Switch
          checked={ov.tun}
          disabled={busy}
          label={ov.tun_active ? "TUN 模式（运行中）" : "TUN 模式"}
          onChange={(_, d) => act(() => api.setTun(d.checked))}
        />
        <Caption1 className={s.muted}>
          创建一块虚拟网卡接管所有程序（游戏、命令行等）的流量，包括 UDP，并按规则分流。需要管理员权限；断开或退出时自动移除。
        </Caption1>
        {ov.tun && !ov.is_admin && (
          <div className={s.row}>
            <Caption1 className={s.muted}>当前不是管理员。</Caption1>
            <Button size="small" onClick={() => act(api.restartAsAdmin)}>
              以管理员身份重启
            </Button>
          </div>
        )}
      </section>

      <section className={s.card}>
        <Switch
          checked={ov.system_proxy}
          disabled={!ov.system_proxy_supported || busy}
          label="设为系统代理"
          onChange={(_, d) => act(() => api.setSystemProxy(d.checked))}
        />
        <Caption1 className={s.muted}>
          {ov.system_proxy_supported
            ? "连接期间让浏览器等遵守系统代理的应用自动使用 superNET；断开或退出时恢复原设置。"
            : "这个平台暂不支持自动设置系统代理，请在应用里手动填写上面的代理地址。"}
        </Caption1>
      </section>
    </div>
  );
}

function Stat({ label, value, icon }: { label: string; value: string; icon?: ReactNode }) {
  const s = usePageStyles();
  const st = useStyles();
  return (
    <div className={mergeClasses(s.card, st.stat)}>
      <Caption1 className={s.muted}>
        {icon} {label}
      </Caption1>
      <Text className={st.value}>{value}</Text>
    </div>
  );
}
