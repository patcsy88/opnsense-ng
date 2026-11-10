import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";
import { defineConfig } from "vitest/config";

export function pwaPlugin() {
  return VitePWA({
    registerType: "autoUpdate",
    injectRegister: "auto",
    manifest: {
      name: "OPNsense Firewall Manager",
      short_name: "FW Manager",
      description: "Self-hosted manager for OPNsense firewalls",
      start_url: "/",
      scope: "/",
      display: "standalone",
      background_color: "#0f172a",
      theme_color: "#0f172a",
      icons: [
        { src: "/icons/icon-192.png", sizes: "192x192", type: "image/png" },
        { src: "/icons/icon-512.png", sizes: "512x512", type: "image/png" },
        {
          src: "/icons/icon-maskable-512.png",
          sizes: "512x512",
          type: "image/png",
          purpose: "maskable",
        },
        { src: "/icons/icon.svg", sizes: "any", type: "image/svg+xml" },
      ],
    },
    workbox: {
      // Static build assets only. There is deliberately no runtime caching of data.
      globPatterns: ["**/*.{js,css,html,svg,png,ico,webmanifest}"],
      navigateFallback: "/index.html",
      navigateFallbackDenylist: [/^\/api\//],
      // Serves the offline page when a navigation cannot reach the network.
      importScripts: ["sw-offline.js"],
      runtimeCaching: [{ urlPattern: /^\/api\//, handler: "NetworkOnly" }],
      cleanupOutdatedCaches: true,
      clientsClaim: true,
      skipWaiting: true,
    },
  });
}

export default defineConfig({
  plugins: [react(), tailwindcss(), pwaPlugin()],
  resolve: { alias: { "@": path.resolve(import.meta.dirname, "src") } },
  server: {
    port: 5173,
    proxy: { "/api": { target: "http://localhost:8000", changeOrigin: false } },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    css: false,
  },
});
