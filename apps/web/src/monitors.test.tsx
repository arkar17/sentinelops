import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "./App.tsx";
import { mockApi, type MockRoute } from "./test-utils.ts";

const ORG = "33333333-3333-4333-8333-333333333333";
const MON = "44444444-4444-4444-8444-444444444444";
const PROJECT = "55555555-5555-4555-8555-555555555555";
const ME = { path: "/api/auth/me", body: { id: "u", email: "a@acme.test", is_platform_admin: false } };

function memberships(role: string): MockRoute {
  return {
    path: "/api/me/organizations",
    body: {
      organizations: [{ organization_id: ORG, slug: "acme", name: "Acme", organization_status: "ACTIVE", role }],
      selected_org_id: ORG,
    },
  };
}

const CONFIG = {
  display_url: "https://api.acme.example/health",
  method: "GET",
  interval_seconds: 60,
  timeout_ms: 10000,
  retry_attempts: 1,
  expected_status: [[200, 299]],
  validation: null,
  latency_threshold_ms: null,
  failure_threshold: 3,
  recovery_threshold: 2,
  tls_warn_days: 14,
  header_count: 2,
  tags: [],
};

function monitor(config: object | null, overrides: object = {}) {
  return {
    id: MON,
    name: "Payments API",
    project_id: PROJECT,
    hostname: "api.acme.example",
    lifecycle: "ACTIVE",
    paused_reason: null,
    attention_reason: null,
    health_state: "UNKNOWN",
    latest: { result: "PASS", failure_category: null, http_status: 200, elapsed_ms: 87, observed_at: "2026-10-31T10:00:00Z" },
    version: 3,
    config,
    ...overrides,
  };
}

function goTo(path: string) {
  window.history.replaceState(null, "", path);
}

afterEach(() => {
  cleanup();
});

describe("monitors", () => {
  it("shows viewers status without configuration or management controls", async () => {
    goTo("/o/acme/monitors");
    mockApi([ME, memberships("VIEWER"), { path: `/api/orgs/${ORG}/monitors`, body: [monitor(null)] }]);
    render(<App />);
    const row = (await screen.findByText("Payments API")).closest("tr");
    expect(row).not.toBeNull();
    expect(within(row as HTMLElement).getByText("Pass")).toBeTruthy();
    expect(within(row as HTMLElement).getByText("200 · 87 ms")).toBeTruthy();
    expect(screen.queryByText("New monitor")).toBeNull();
    expect(screen.queryByText(/health\?/)).toBeNull();
  });

  it("explains monitors waiting for domain verification", async () => {
    goTo("/o/acme/monitors");
    mockApi([
      ME,
      memberships("ORG_ADMIN"),
      { path: `/api/orgs/${ORG}/monitors`, body: [monitor(CONFIG, { lifecycle: "DRAFT", latest: null })] },
    ]);
    render(<App />);
    expect(await screen.findByText("Waiting for domain verification")).toBeTruthy();
    expect(screen.getByText("New monitor")).toBeTruthy();
  });

  it("creates a monitor with the expected payload", async () => {
    goTo("/o/acme/monitors/new");
    const calls = mockApi([
      ME,
      memberships("ORG_ADMIN"),
      { path: `/api/orgs/${ORG}/projects`, body: [{ id: PROJECT, name: "Main", description: null, archived_at: null, created_at: "", version: 1 }] },
      { method: "POST", path: `/api/orgs/${ORG}/monitors`, status: 201, body: monitor(CONFIG) },
      { path: `/api/orgs/${ORG}/monitors/${MON}`, body: monitor(CONFIG) },
      { path: `/api/orgs/${ORG}/monitors/${MON}/measurements?limit=100`, body: [] },
    ]);
    render(<App />);
    await screen.findByRole("heading", { name: "New monitor" });
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Payments API" } });
    fireEvent.change(screen.getByLabelText(/^URL/), { target: { value: "https://api.acme.example/health?key=x" } });
    fireEvent.change(screen.getByLabelText("Response validation (GET only)"), { target: { value: "json_path" } });
    fireEvent.change(screen.getByLabelText("Expected value (JSON)"), { target: { value: '"ok"' } });
    fireEvent.click(screen.getByRole("button", { name: "Create monitor" }));
    await waitFor(() => {
      expect(window.location.pathname).toBe(`/o/acme/monitors/${MON}`);
    });
    const post = calls.find((c) => c.method === "POST");
    expect(JSON.parse(String(post?.init.body))).toEqual({
      name: "Payments API",
      project_id: PROJECT,
      url: "https://api.acme.example/health?key=x",
      method: "GET",
      interval_seconds: 60,
      timeout_ms: 10000,
      retry_attempts: 1,
      expected_status: ["200-299"],
      validation: { type: "json_path", path: "$.status", equals: "ok" },
      latency_threshold_ms: null,
    });
  });

  it("shows detail, history and response-time statistics", async () => {
    goTo(`/o/acme/monitors/${MON}`);
    const rows = [120, 80, 100, 400].map((ms, i) => ({
      id: `m${String(i)}`,
      trigger: i === 0 ? "MANUAL" : "SCHEDULED",
      scheduled_for: null,
      observed_at: "2026-10-31T10:00:00Z",
      result: ms > 300 ? "SLOW" : "PASS",
      failure_category: null,
      http_status: 200,
      elapsed_ms: ms,
      attempt_count: 1,
      tls_not_after: null,
    }));
    mockApi([
      ME,
      memberships("ORG_MEMBER"),
      { path: `/api/orgs/${ORG}/monitors/${MON}`, body: monitor(CONFIG) },
      { path: `/api/orgs/${ORG}/monitors/${MON}/measurements?limit=100`, body: rows },
    ]);
    render(<App />);
    expect(await screen.findByText("100 ms", { selector: ".stat-value" })).toBeTruthy(); // median
    expect(screen.getByText("400 ms", { selector: ".stat-value" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Check now" })).toBeTruthy(); // members may check now
    expect(screen.queryByRole("button", { name: "Pause" })).toBeNull(); // but not pause (OD-04)
    expect(screen.queryByText(/Replace headers/)).toBeNull();
  });

  it("never displays header values and clears them after saving", async () => {
    goTo(`/o/acme/monitors/${MON}`);
    const calls = mockApi([
      ME,
      memberships("ORG_ADMIN"),
      { path: `/api/orgs/${ORG}/monitors/${MON}`, body: monitor(CONFIG) },
      { path: `/api/orgs/${ORG}/monitors/${MON}/measurements?limit=100`, body: [] },
      { method: "PUT", path: `/api/orgs/${ORG}/monitors/${MON}/headers`, body: monitor({ ...CONFIG, header_count: 1 }) },
    ]);
    render(<App />);
    expect(await screen.findByText(/Custom headers: 2 set/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Replace headers" }));
    fireEvent.change(screen.getByLabelText("Header 1 name"), { target: { value: "Authorization" } });
    const value = screen.getByLabelText("Header 1 value") as HTMLInputElement;
    expect(value.type).toBe("password");
    fireEvent.change(value, { target: { value: "Bearer secret-123" } });
    fireEvent.click(screen.getByRole("button", { name: "Save headers" }));
    expect(await screen.findByText("Headers saved.")).toBeTruthy();
    expect(document.body.textContent).not.toContain("secret-123");
    const put = calls.find((c) => c.method === "PUT");
    expect(JSON.parse(String(put?.init.body))).toEqual({
      headers: [{ name: "Authorization", value: "Bearer secret-123" }],
    });
  });
});

describe("domains", () => {
  it("shows the TXT challenge after adding a domain", async () => {
    goTo("/o/acme/domains");
    const domain = {
      id: "d1",
      fqdn: "acme.example",
      method: "DNS_TXT",
      status: "PENDING",
      challenge_expires_at: "2026-11-07T10:00:00Z",
      verified_at: null,
      expires_at: null,
      last_checked_at: null,
      exception_reason: null,
    };
    mockApi([
      ME,
      memberships("ORG_OWNER"),
      { path: `/api/orgs/${ORG}/domains`, body: [] },
      {
        method: "POST",
        path: `/api/orgs/${ORG}/domains`,
        status: 201,
        body: {
          domain,
          record_type: "TXT",
          record_name: "_sentinelops-challenge.acme.example",
          record_value: "sentinelops-domain-verification=abc123",
        },
      },
    ]);
    render(<App />);
    await screen.findByRole("heading", { name: "Domains" });
    fireEvent.change(screen.getByLabelText("Domain (e.g. example.com)"), { target: { value: "acme.example" } });
    fireEvent.click(screen.getByRole("button", { name: "Add domain" }));
    const challenge = await screen.findByLabelText("DNS challenge");
    expect(challenge.textContent).toContain("_sentinelops-challenge.acme.example");
    expect(challenge.textContent).toContain("sentinelops-domain-verification=abc123");
  });

  it("hides domains from viewers", async () => {
    goTo("/o/acme/monitors");
    mockApi([ME, memberships("VIEWER"), { path: `/api/orgs/${ORG}/monitors`, body: [] }]);
    render(<App />);
    await screen.findByRole("heading", { name: "Monitors" });
    expect(screen.getByRole("navigation", { name: "Organization sections" }).textContent).not.toContain("Domains");
  });
});
