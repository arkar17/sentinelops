import { defineConfig, devices } from "@playwright/test";

/**
 * Browser E2E against the real API (tests/e2e/server.py) and the Vite app. The API harness
 * refuses any database other than a local, disposable `sentinelops_test` and fakes every
 * external dependency (DNS, probes, email, Telegram).
 *
 *   SENTINELOPS_TEST_DATABASE_URL=postgresql+asyncpg://...@127.0.0.1:5432/sentinelops_test \
 *     npm run e2e                       # Chromium (desktop + mobile)
 *   E2E_WEBKIT=1 npm run e2e            # also WebKit, where installed
 */
const WEB = "http://127.0.0.1:5174";
const API = "http://127.0.0.1:8001";

const projects = [
  { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  { name: "mobile-chromium", use: { ...devices["Pixel 7"] }, testMatch: /a11y\.spec\.ts/ },
];
if (process.env.E2E_WEBKIT === "1") {
  projects.push({ name: "webkit", use: { ...devices["Desktop Safari"] } });
}

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1, // one shared disposable database
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  timeout: 90_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: { baseURL: WEB, trace: "retain-on-failure", screenshot: "only-on-failure" },
  projects,
  webServer: [
    {
      command: "uv run python -m tests.e2e.server",
      cwd: "../api",
      url: `${API}/healthz`,
      reuseExistingServer: false,
      timeout: 120_000,
      stdout: "pipe",
      stderr: "pipe",
    },
    {
      command: "npx vite --host 127.0.0.1 --port 5174",
      url: WEB,
      env: { VITE_API_PROXY_TARGET: API },
      reuseExistingServer: false,
      timeout: 120_000,
    },
  ],
});
