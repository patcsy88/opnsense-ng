import { defineConfig } from "@playwright/test";

// Live tests against the disposable stack started by scripts/e2e-live.sh. No mocks.
export default defineConfig({
  testDir: "e2e-live",
  timeout: 180_000,
  workers: 1,
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "https://localhost:18443",
    ignoreHTTPSErrors: true,
    serviceWorkers: "block",
    actionTimeout: 10_000,
  },
});
