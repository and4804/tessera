/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import type { PluginOption } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// The dev mock lives in ./dev-mock and is ONLY loaded for `vite` (serve). It is never
// imported by src/ and never part of `vite build`.
export default defineConfig(async ({ command }) => {
  const plugins: PluginOption[] = [react()];
  const proxyTarget = process.env.ULPF_API ?? "http://127.0.0.1:8080";
  const useMock = command === "serve" && !process.env.VITEST && process.env.ULPF_NO_MOCK !== "1";
  if (useMock) {
    const { ulpfDevMock } = await import("./dev-mock/plugin");
    plugins.push(ulpfDevMock());
  }
  return {
    plugins,
    resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
    server: {
      port: 5173,
      proxy: useMock
        ? undefined
        : { "/api": { target: proxyTarget, changeOrigin: true, ws: true } }
    },
    worker: { format: "es" as const },
    test: { environment: "node", include: ["src/**/*.test.ts"] },
    build: {
      target: "es2022",
      sourcemap: false,
      chunkSizeWarningLimit: 4000, // monaco is large by nature; it is lazy-loaded
      rollupOptions: {
        output: {
          manualChunks(id: string) {
            if (id.includes("node_modules/monaco-editor") || id.includes("@monaco-editor")) return "monaco";
            if (id.includes("node_modules/echarts") || id.includes("node_modules/zrender")) return "echarts";
            if (id.includes("node_modules/@tanstack")) return "tanstack";
            if (id.includes("node_modules/react") || id.includes("node_modules/scheduler")) return "react";
            return undefined;
          }
        }
      }
    }
  };
});
