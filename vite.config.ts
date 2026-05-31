import { resolve } from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  // Setting root to the renderer directory means Vite treats src/renderer/index.html
  // as the project root and will output index.html directly into outDir (dist/).
  // Without this, Vite mirrors the nested path (dist/src/renderer/index.html).
  root: resolve(__dirname, "src/renderer"),
  plugins: [react()],
  resolve: {
    alias: {
      "@shared": resolve(__dirname, "src/shared"),
    },
  },
  build: {
    // Resolve outDir relative to the project root (not the vite root), so the
    // final static files land at opennow-stable/dist/
    outDir: resolve(__dirname, "dist"),
    emptyOutDir: true,
  },
});
