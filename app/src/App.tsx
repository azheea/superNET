import { createContext, useCallback, useContext, useState } from "react";
import {
  Tab,
  TabList,
  Text,
  Toast,
  ToastTitle,
  Toaster,
  makeStyles,
  tokens,
  useId,
  useToastController,
} from "@fluentui/react-components";
import {
  DocumentTextRegular,
  GlobeRegular,
  HomeRegular,
  PlugConnectedRegular,
  ServerRegular,
  SettingsRegular,
  TextBulletListLtrRegular,
} from "@fluentui/react-icons";
import { HomePage } from "./pages/Home";
import { NodesPage } from "./pages/Nodes";
import { RulesPage } from "./pages/Rules";
import { ConnectionsPage } from "./pages/Connections";
import { LogsPage } from "./pages/Logs";
import { SettingsPage } from "./pages/Settings";
import { NetworkPage } from "./pages/Network";

type Intent = "success" | "error" | "warning" | "info";
const NotifyContext = createContext<(message: string, intent?: Intent) => void>(() => {});
export const useNotify = () => useContext(NotifyContext);

const useStyles = makeStyles({
  shell: { display: "flex", height: "100%", backgroundColor: tokens.colorNeutralBackground2 },
  nav: {
    width: "188px",
    flexShrink: 0,
    display: "flex",
    flexDirection: "column",
    gap: tokens.spacingVerticalL,
    padding: `${tokens.spacingVerticalXL} ${tokens.spacingHorizontalS}`,
    backgroundColor: tokens.colorNeutralBackground1,
    borderRight: `1px solid ${tokens.colorNeutralStroke2}`,
  },
  brand: { display: "flex", alignItems: "center", gap: tokens.spacingHorizontalS, padding: `0 ${tokens.spacingHorizontalM}` },
  logo: { width: "28px", height: "28px" },
  main: { flex: 1, overflow: "auto", padding: tokens.spacingHorizontalXXL },
});

const pages = [
  { id: "home", label: "概览", icon: <HomeRegular />, render: () => <HomePage /> },
  { id: "nodes", label: "节点", icon: <ServerRegular />, render: () => <NodesPage /> },
  { id: "network", label: "组网", icon: <GlobeRegular />, render: () => <NetworkPage /> },
  { id: "rules", label: "规则", icon: <TextBulletListLtrRegular />, render: () => <RulesPage /> },
  { id: "connections", label: "连接", icon: <PlugConnectedRegular />, render: () => <ConnectionsPage /> },
  { id: "logs", label: "日志", icon: <DocumentTextRegular />, render: () => <LogsPage /> },
  { id: "settings", label: "设置", icon: <SettingsRegular />, render: () => <SettingsPage /> },
];

export function App() {
  const styles = useStyles();
  const [page, setPage] = useState("home");
  const toasterId = useId("toaster");
  const { dispatchToast } = useToastController(toasterId);
  const notify = useCallback(
    (message: string, intent: Intent = "success") =>
      dispatchToast(
        <Toast>
          <ToastTitle>{message}</ToastTitle>
        </Toast>,
        { intent, timeout: intent === "error" ? 6000 : 3000 },
      ),
    [dispatchToast],
  );
  const current = pages.find((p) => p.id === page) ?? pages[0];

  return (
    <NotifyContext.Provider value={notify}>
      <div className={styles.shell}>
        <nav className={styles.nav}>
          <div className={styles.brand}>
            <img className={styles.logo} src="/logo.svg" alt="" />
            <Text weight="semibold" size={500}>
              superNET
            </Text>
          </div>
          <TabList vertical size="large" selectedValue={page} onTabSelect={(_, d) => setPage(d.value as string)}>
            {pages.map((p) => (
              <Tab key={p.id} value={p.id} icon={p.icon}>
                {p.label}
              </Tab>
            ))}
          </TabList>
        </nav>
        <main className={styles.main}>{current.render()}</main>
      </div>
      <Toaster toasterId={toasterId} position="bottom-end" />
    </NotifyContext.Provider>
  );
}
