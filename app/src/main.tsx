import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { FluentProvider, webDarkTheme, webLightTheme } from "@fluentui/react-components";
import { App } from "./App";
import "./style.css";

function Root() {
  const query = window.matchMedia("(prefers-color-scheme: dark)");
  const [dark, setDark] = useState(query.matches);
  useEffect(() => {
    const onChange = (e: MediaQueryListEvent) => setDark(e.matches);
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, [query]);
  return (
    // No className here: Fluent copies the provider's classes onto the mount
    // node of every popup (dropdown lists, menus, dialogs, tooltips), and a
    // full-height class turned that node into an opaque layer over the whole
    // app (the "black screen"). The height is set in style.css instead.
    <FluentProvider theme={dark ? webDarkTheme : webLightTheme}>
      <App />
    </FluentProvider>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
