import type { ReactNode } from "react";
import { Caption1, Title2, makeStyles, tokens } from "@fluentui/react-components";

export const usePageStyles = makeStyles({
  page: { display: "flex", flexDirection: "column", gap: tokens.spacingVerticalL, maxWidth: "980px" },
  header: { display: "flex", alignItems: "center", justifyContent: "space-between", gap: tokens.spacingHorizontalM },
  row: { display: "flex", alignItems: "center", gap: tokens.spacingHorizontalM, flexWrap: "wrap" },
  card: {
    display: "flex",
    flexDirection: "column",
    gap: tokens.spacingVerticalM,
    padding: tokens.spacingHorizontalL,
    borderRadius: tokens.borderRadiusLarge,
    backgroundColor: tokens.colorNeutralBackground1,
    boxShadow: tokens.shadow2,
  },
  muted: { color: tokens.colorNeutralForeground3 },
  grow: { flex: 1, minWidth: 0 },
});

export function PageHeader({ title, hint, actions }: { title: string; hint?: string; actions?: ReactNode }) {
  const s = usePageStyles();
  return (
    <div className={s.header}>
      <div>
        <Title2 as="h1">{title}</Title2>
        {hint && (
          <div>
            <Caption1 className={s.muted}>{hint}</Caption1>
          </div>
        )}
      </div>
      {actions && <div className={s.row}>{actions}</div>}
    </div>
  );
}
