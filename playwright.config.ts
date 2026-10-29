import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests/browser",
  workers: 1,
  fullyParallel: false,
  retries: 0,
  timeout: 20_000,
  reporter: "list",
  use: { browserName: "chromium", baseURL: "http://127.0.0.1:4173", headless: true, trace: "off" },
  webServer: {
    command: "npx vite preview --host 127.0.0.1 --port 4173 --strictPort",
    port: 4173,
    reuseExistingServer: false,
    timeout: 20_000,
  },
});
