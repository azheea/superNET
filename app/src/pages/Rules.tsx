import { useEffect, useState } from "react";
import {
  Body1,
  Button,
  Caption1,
  Field,
  Input,
  MessageBar,
  MessageBarBody,
  Spinner,
  Subtitle1,
  Textarea,
} from "@fluentui/react-components";
import { ArrowRoutingRegular } from "@fluentui/react-icons";
import { api, errorText, type RouteInfo } from "../api";
import { useNotify } from "../App";
import { PageHeader, usePageStyles } from "./common";

export function RulesPage() {
  const s = usePageStyles();
  const notify = useNotify();
  const [saved, setSaved] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [policies, setPolicies] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [probe, setProbe] = useState("");
  const [route, setRoute] = useState<RouteInfo | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const [rules, ov] = await Promise.all([api.getRules(), api.overview()]);
      setSaved(rules);
      setText(rules);
      setPolicies(["DIRECT", "REJECT", ...ov.groups.map((g) => g.name), ...ov.nodes.map((n) => n.name)]);
    })().catch((e) => setError(errorText(e)));
  }, []);

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const w = await api.saveRules(text);
      setWarnings(w);
      setSaved(text);
      notify(w.length ? `已保存，有 ${w.length} 条提示` : "规则已保存");
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    if (!probe.trim()) {
      setProbeError("请输入域名或 IP");
      return;
    }
    setProbeError(null);
    try {
      setRoute(await api.explain(probe.trim()));
    } catch (e) {
      setRoute(null);
      setProbeError(errorText(e));
    }
  };

  if (saved === null && !error) return <Spinner label="加载中…" />;
  const dirty = saved !== null && text !== saved;

  return (
    <div className={s.page}>
      <PageHeader
        title="规则"
        hint="从上到下匹配，第一条命中的规则生效。语法与 Clash 相同，可以直接粘贴现成的规则列表。"
        actions={
          <>
            <Button disabled={!dirty || busy} onClick={() => saved !== null && setText(saved)}>
              撤销修改
            </Button>
            <Button appearance="primary" disabled={!dirty || busy} onClick={save}>
              保存
            </Button>
          </>
        }
      />

      {error && (
        <MessageBar intent="error">
          <MessageBarBody>{error}</MessageBarBody>
        </MessageBar>
      )}
      {warnings.map((w) => (
        <MessageBar key={w} intent="warning">
          <MessageBarBody>{w}</MessageBarBody>
        </MessageBar>
      ))}

      <section className={s.card}>
        <Textarea
          className="mono"
          resize="vertical"
          rows={16}
          value={text}
          onChange={(_, d) => setText(d.value)}
          textarea={{ spellCheck: false }}
        />
        <Caption1 className={s.muted}>
          支持 DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD、IP-CIDR、IP-CIDR6、GEOIP、DST-PORT、RULE-SET、MATCH。IP 规则加 no-resolve
          表示不为域名做解析。可用策略：{policies.join("、")}。
        </Caption1>
      </section>

      <section className={s.card}>
        <Subtitle1>规则测试</Subtitle1>
        <div className={s.row}>
          <Field className={s.grow} validationState={probeError ? "error" : "none"} validationMessage={probeError ?? undefined}>
            <Input
              value={probe}
              onChange={(_, d) => {
                setProbe(d.value);
                setProbeError(null);
              }}
              onKeyDown={(e) => e.key === "Enter" && test()}
              placeholder="域名或 IP，可带端口，例如 github.com 或 10.66.0.5:22"
            />
          </Field>
          <Button icon={<ArrowRoutingRegular />} onClick={test}>
            测试
          </Button>
        </div>
        {dirty && <Caption1 className={s.muted}>测试使用已保存的规则。</Caption1>}
        {route && (
          <div>
            <Body1>
              {route.target} → <b>{route.chain}</b>
            </Body1>
            <div>
              <Caption1 className={s.muted}>
                命中：{route.rule}
                {route.resolved.length > 0 && `　解析到：${route.resolved.join("、")}`}
              </Caption1>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
