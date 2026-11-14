import { useState } from "react";
import {
  Button,
  Caption1,
  Table,
  TableBody,
  TableCell,
  TableCellLayout,
  TableHeader,
  TableHeaderCell,
  TableRow,
  Tooltip,
} from "@fluentui/react-components";
import { DismissRegular } from "@fluentui/react-icons";
import { api, errorText, type ConnInfo } from "../api";
import { useNotify } from "../App";
import { formatBytes, formatDuration, usePolling } from "../util";
import { PageHeader, usePageStyles } from "./common";

export function ConnectionsPage() {
  const s = usePageStyles();
  const notify = useNotify();
  const [conns, setConns] = useState<ConnInfo[]>([]);
  usePolling(async () => setConns(await api.connections()), 1000);

  const close = async (id: number) => {
    try {
      await api.closeConnection(id);
      setConns(await api.connections());
    } catch (e) {
      notify(errorText(e), "error");
    }
  };

  return (
    <div className={s.page}>
      <PageHeader title="连接" hint={`当前 ${conns.length} 个连接`} />
      <section className={s.card}>
        {conns.length === 0 ? (
          <Caption1 className={s.muted}>没有活动连接。</Caption1>
        ) : (
          <Table size="small">
            <TableHeader>
              <TableRow>
                <TableHeaderCell style={{ width: "30%" }}>目标</TableHeaderCell>
                <TableHeaderCell style={{ width: "24%" }}>规则</TableHeaderCell>
                <TableHeaderCell>出口</TableHeaderCell>
                <TableHeaderCell style={{ width: 84 }}>上传</TableHeaderCell>
                <TableHeaderCell style={{ width: 84 }}>下载</TableHeaderCell>
                <TableHeaderCell style={{ width: 92 }}>时长</TableHeaderCell>
                <TableHeaderCell style={{ width: 48 }} />
              </TableRow>
            </TableHeader>
            <TableBody>
              {conns.map((c) => (
                <TableRow key={c.id}>
                  <TableCell>
                    <TableCellLayout truncate description={c.inbound}>
                      <span className="mono">{c.target}</span>
                    </TableCellLayout>
                  </TableCell>
                  <TableCell>
                    <TableCellLayout truncate>{c.rule}</TableCellLayout>
                  </TableCell>
                  <TableCell>
                    <TableCellLayout truncate>{c.chain}</TableCellLayout>
                  </TableCell>
                  <TableCell>{formatBytes(c.upload)}</TableCell>
                  <TableCell>{formatBytes(c.download)}</TableCell>
                  <TableCell>{formatDuration(Date.now() - c.started_ms)}</TableCell>
                  <TableCell>
                    <Tooltip content="断开" relationship="label">
                      <Button appearance="subtle" size="small" icon={<DismissRegular />} onClick={() => close(c.id)} />
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </section>
    </div>
  );
}
