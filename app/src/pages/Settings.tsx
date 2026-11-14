import { useEffect, useState } from "react";
import { Button, Field, Input, MessageBar, MessageBarBody, Spinner, Switch } from "@fluentui/react-components";
import { api, errorText, type Settings } from "../api";
import { useNotify } from "../App";
import { PageHeader, usePageStyles } from "./common";

export function SettingsPage() {
  const s = usePageStyles();
  const notify = useNotify();
  const [settings, setSettings] = useState<Settings | null>(null);
  const [dns, setDns] = useState("");
  const [port, setPort] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .getSettings()
      .then((v) => {
        setSettings(v);
        setDns(v.dns.join(", "));
        setPort(String(v.port));
      })
      .catch((e) => setError(errorText(e)));
  }, []);

  if (!settings) return error ? <MessageBar intent="error"><MessageBarBody>{error}</MessageBarBody></MessageBar> : <Spinner label="加载中…" />;

  const portNumber = Number(port);
  const portError = !Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535 ? "端口应为 1–65535" : null;

  const save = async () => {
    if (portError) return;
    setBusy(true);
    setError(null);
    try {
      const next: Settings = {
        ...settings,
        port: portNumber,
        dns: dns.split(/[,，\s]+/).filter(Boolean),
      };
      const warnings = await api.saveSettings(next);
      setSettings(next);
      notify(warnings.length ? `已保存，有 ${warnings.length} 条提示` : "设置已保存");
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={s.page}>
      <PageHeader title="设置" actions={<Button appearance="primary" disabled={busy || !!portError} onClick={save}>保存</Button>} />
      {error && (
        <MessageBar intent="error">
          <MessageBarBody>{error}</MessageBarBody>
        </MessageBar>
      )}
      <section className={s.card}>
        <Field label="本地代理端口" hint="HTTP 和 SOCKS5 共用这个端口" validationState={portError ? "error" : "none"} validationMessage={portError ?? undefined}>
          <Input type="number" value={port} onChange={(_, d) => setPort(d.value)} style={{ maxWidth: 160 }} />
        </Field>
        <Switch
          checked={settings.allow_lan}
          onChange={(_, d) => setSettings({ ...settings, allow_lan: d.checked })}
          label="允许局域网内的其他设备使用这个代理（例如手机在 Wi-Fi 设置里填这台电脑的地址）"
        />
        <Switch checked={settings.auto_connect} onChange={(_, d) => setSettings({ ...settings, auto_connect: d.checked })} label="启动时自动连接" />
      </section>
      <section className={s.card}>
        <Field label="直连 DNS" hint="直连流量和 IP 规则使用。填 system（系统 DNS）或服务器 IP，多个用逗号分隔，例如 223.5.5.5, system">
          <Input value={dns} onChange={(_, d) => setDns(d.value)} />
        </Field>
        <Field label="测速地址" hint="只支持 http://，测速时经节点请求这个地址">
          <Input value={settings.test_url} onChange={(_, d) => setSettings({ ...settings, test_url: d.value })} />
        </Field>
        <Field label="GeoIP 数据库" hint="GEOIP 规则需要的 MaxMind 格式文件（.mmdb）路径，不用 GEOIP 规则可以留空">
          <Input value={settings.geoip ?? ""} onChange={(_, d) => setSettings({ ...settings, geoip: d.value || null })} />
        </Field>
      </section>
    </div>
  );
}
