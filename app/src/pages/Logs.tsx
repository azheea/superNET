import { useEffect, useRef, useState } from "react";
import { Button, Caption1, makeStyles, tokens } from "@fluentui/react-components";
import { api, type LogLine } from "../api";
import { formatTime, usePolling } from "../util";
import { PageHeader, usePageStyles } from "./common";

const KEEP = 500;

const useStyles = makeStyles({
  list: { maxHeight: "calc(100vh - 200px)", overflow: "auto", fontSize: tokens.fontSizeBase200, lineHeight: tokens.lineHeightBase300 },
  line: { display: "flex", gap: tokens.spacingHorizontalM, padding: `2px 0`, wordBreak: "break-all" },
  time: { color: tokens.colorNeutralForeground3, flexShrink: 0 },
  warn: { color: tokens.colorPaletteMarigoldForeground1 },
  error: { color: tokens.colorPaletteRedForeground1 },
});

export function LogsPage() {
  const s = usePageStyles();
  const st = useStyles();
  const [lines, setLines] = useState<LogLine[]>([]);
  const lastSeq = useRef(0);
  const listRef = useRef<HTMLDivElement>(null);
  const stick = useRef(true);

  usePolling(async () => {
    const fresh = await api.logs(lastSeq.current);
    if (fresh.length === 0) return;
    lastSeq.current = fresh[fresh.length - 1].seq;
    setLines((old) => [...old, ...fresh].slice(-KEEP));
  }, 1000);

  useEffect(() => {
    const el = listRef.current;
    if (el && stick.current) el.scrollTop = el.scrollHeight;
  }, [lines]);

  return (
    <div className={s.page}>
      <PageHeader title="日志" hint={`显示最近 ${KEEP} 条`} actions={<Button onClick={() => setLines([])}>清空</Button>} />
      <section className={s.card}>
        {lines.length === 0 ? (
          <Caption1 className={s.muted}>暂无日志。</Caption1>
        ) : (
          <div
            ref={listRef}
            className={`${st.list} mono`}
            onScroll={(e) => {
              const el = e.currentTarget;
              stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
            }}
          >
            {lines.map((l) => (
              <div key={l.seq} className={st.line}>
                <span className={st.time}>{formatTime(l.time_ms)}</span>
                <span className={l.level === "warn" ? st.warn : l.level === "error" ? st.error : undefined}>{l.message}</span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
