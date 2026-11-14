import { defineConfig } from "vite";

// Fluent UI is one large chunk; that is fine for a desktop/mobile app.
export default defineConfig({
  build: { chunkSizeWarningLimit: 1500 },
  server: { port: 5173, strictPort: true },
});
