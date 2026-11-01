import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App.tsx";
import { navigate } from "./router.ts";
import { mockApi, type MockRoute } from "./test-utils.ts";

const ORG_A = "33333333-3333-4333-8333-333333333333";
const ORG_B = "55555555-5555-4555-8555-555555555555";
const ME = { path: "/api/auth/me", body: { id: "u", email: "a@acme.test", is_platform_admin: false } };

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  listeners: Record<string, (() => void)[]> = {};
  closed = false;
  onerror: (() => void) | null = null;
  constructor(public url: string) {
    FakeEventSource.instances.push(this);
  }
  addEventListener(name: string, handler: () => void) {
    (this.listeners[name] ??= []).push(handler);
  }
  close() {
    this.closed = true;
  }
  emit(name: string) {
    for (const handler of this.listeners[name] ?? []) handler();
  }
}

function memberships(role = "ORG_MEMBER"): MockRoute {
  return {
    path: "/api/me/organizations",
    body: {
      organizations: [
        { organization_id: ORG_A, slug: "acme", name: "Acme", organization_status: "ACTIVE", role },
        { organization_id: ORG_B, slug: "globex", name: "Globex", organization_status: "ACTIVE", role },
      ],
      selected_org_id: ORG_A,
    },
  };
}

const STATS = {
  conclusive_samples: 90,
  available_samples: 81,
  failed_samples: 9,
  blocked_samples: 2,
  inconclusive_samples: 1,
  expected_samples: 120,
  missed_samples: 27,
  uptime_pct: 90,
  coverage_pct: 75,
  latency_p50_ms: 120,
  latency_p95_ms: 480,
  downtime_estimate_seconds: 540,
  outage_incident_seconds: 600,
  incidents_opened: 1,
  outage_incidents_opened: 1,
  tls_incidents_opened: 0,
  incidents_resolved: 1,
  mean_resolution_seconds: 600,
  mean_acknowledge_seconds: null,
};

const WINDOW = {
  period: "24h",
  start: "2026-10-30T12:00:00Z",
  end: "2026-10-31T12:00:00Z",
  bucket: "hour",
  timezone: "UTC",
  latency_method: "exact",
};

function dashboard(overrides: object = {}) {
  return {
    generated_at: "2026-10-31T12:00:00Z",
    monitors_by_lifecycle: { ACTIVE: 3, PAUSED: 1, DRAFT: 0, ARCHIVED: 2 },
    health: { UP: 2, DEGRADED: 0, DOWN: 1, UNKNOWN: 0 },
    active_incidents_by_severity: { CRITICAL: 1, WARNING: 0 },
    recent_incidents: [
      {
        id: "i1",
        monitor_id: "m1",
        monitor_name: "Payments API",
        type: "OUTAGE",
        severity: "CRITICAL",
        status: "OPEN",
        title: "Outage detected",
        opened_at: "2026-10-31T11:00:00Z",
        resolved_at: null,
      },
    ],
    results_24h: { PASS: 80, SLOW: 1, FAIL: 9, BLOCKED: 2, INCONCLUSIVE: 1 },
    summary_24h: STATS,
    window_24h: WINDOW,
    series_24h: [
      { bucket_start: "2026-10-31T10:00:00Z", conclusive_samples: 60, available_samples: 60, uptime_pct: 100, latency_p50_ms: 110, latency_p95_ms: 300 },
      { bucket_start: "2026-10-31T11:00:00Z", conclusive_samples: 0, available_samples: 0, uptime_pct: null, latency_p50_ms: null, latency_p95_ms: null },
    ],
    tls_expiring: [
      { monitor_id: "m2", monitor_name: "Shop", hostname: "shop.acme.example", expires_at: "2026-11-05T00:00:00Z", days_remaining: 4, warn_days: 14 },
    ],
    recent_checks: [],
    ...overrides,
  };
}

function orgRoutes(org: string, body: object): MockRoute[] {
  return [
    {
      path: `/api/orgs/${org}`,
      body: { name: org === ORG_A ? "Acme" : "Globex", my_role: "ORG_MEMBER", timezone: "UTC", member_count: 3, project_count: 1, limits: { max_monitors: 20 } },
    },
    { path: `/api/orgs/${org}/dashboard`, body },
  ];
}

beforeEach(() => {
  FakeEventSource.instances = [];
  vi.stubGlobal("EventSource", FakeEventSource);
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

function goTo(path: string) {
  window.history.replaceState(null, "", path);
}

describe("organization dashboard", () => {
  it("shows real metrics, coverage gaps and accessible charts", async () => {
    goTo("/o/acme");
    mockApi([ME, memberships(), ...orgRoutes(ORG_A, dashboard())]);
    render(<App />);
    expect(await screen.findByText("90.000%")).toBeTruthy();
    expect(screen.getByText("480 ms")).toBeTruthy();
    expect(screen.getByText(/Coverage 75.00%/)).toBeTruthy();
    expect(screen.getByText(/coverage gaps, not uptime/)).toBeTruthy();
    expect(screen.getByRole("img", { name: /Health of active monitors: Up 2, Degraded 0, Down 1/ })).toBeTruthy();
    expect(screen.getByRole("img", { name: /Hourly uptime. 1 of 2 periods have data/ })).toBeTruthy();
    expect(screen.getAllByText("No data").length).toBeGreaterThan(0); // the empty hour in the table view
    expect(screen.getByText(/4 days left · below warning threshold/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Outage detected" })).toBeTruthy();
    expect(screen.getByText("No checks in the last 24 hours.")).toBeTruthy();
  });

  it("refreshes on live events and stops when access is revoked", async () => {
    goTo("/o/acme");
    const calls = mockApi([ME, memberships(), ...orgRoutes(ORG_A, dashboard())]);
    render(<App />);
    await screen.findByText("90.000%");
    const [source] = FakeEventSource.instances;
    expect(source?.url).toBe(`/api/orgs/${ORG_A}/events`);
    const before = calls.filter((c) => c.path.endsWith("/dashboard")).length;
    vi.useFakeTimers();
    act(() => {
      source?.emit("ready");
      source?.emit("incident.opened");
      source?.emit("check.recorded");
      vi.advanceTimersByTime(1100); // debounced into one refresh
    });
    vi.useRealTimers();
    await waitFor(() => {
      expect(calls.filter((c) => c.path.endsWith("/dashboard")).length).toBe(before + 1);
    });
    expect(screen.getByText("● Live")).toBeTruthy();
    act(() => {
      source?.emit("revoked");
    });
    expect(await screen.findByText(/Your access to this organization changed/)).toBeTruthy();
    expect(source?.closed).toBe(true);
  });

  it("shows empty states without inventing numbers", async () => {
    goTo("/o/acme");
    const empty = dashboard({
      health: { UP: 0, DEGRADED: 0, DOWN: 0, UNKNOWN: 0 },
      monitors_by_lifecycle: { ACTIVE: 0, PAUSED: 0, DRAFT: 0, ARCHIVED: 0 },
      active_incidents_by_severity: { CRITICAL: 0, WARNING: 0 },
      recent_incidents: [],
      tls_expiring: [],
      series_24h: [],
      summary_24h: { ...STATS, conclusive_samples: 0, available_samples: 0, uptime_pct: null, coverage_pct: null, latency_p50_ms: null, latency_p95_ms: null },
    });
    mockApi([ME, memberships(), ...orgRoutes(ORG_A, empty)]);
    render(<App />);
    expect(await screen.findByText("No active monitors.")).toBeTruthy();
    expect(screen.getAllByText("No data").length).toBeGreaterThan(0);
    expect(screen.queryByText("100.000%")).toBeNull();
    expect(screen.getByText("No checks in this period.")).toBeTruthy();
    expect(screen.getByText("No response-time data for this period.")).toBeTruthy();
    expect(screen.getByText("No incidents yet.")).toBeTruthy();
  });

  it("switching organizations closes the old stream and fetches only the new organization", async () => {
    goTo("/o/acme");
    const calls = mockApi([
      ME,
      memberships(),
      ...orgRoutes(ORG_A, dashboard()),
      ...orgRoutes(ORG_B, dashboard({ summary_24h: { ...STATS, uptime_pct: 50 } })),
    ]);
    render(<App />);
    await screen.findByText("90.000%");
    const first = FakeEventSource.instances[0];
    const mark = calls.length;
    act(() => {
      navigate("/o/globex");
    });
    expect(await screen.findByText("50.000%")).toBeTruthy();
    expect(screen.queryByText("90.000%")).toBeNull();
    expect(first?.closed).toBe(true);
    expect(FakeEventSource.instances.at(-1)?.url).toBe(`/api/orgs/${ORG_B}/events`);
    expect(calls.slice(mark).some((c) => c.path.includes(ORG_A))).toBe(false);
  });
});

describe("reports", () => {
  const REPORT = {
    window: { ...WINDOW, period: "7d", bucket: "day" },
    summary: STATS,
    median_resolution_seconds: 600,
    monitors: [
      { monitor_id: "m1", name: "Payments API", hostname: "api.acme.example", project_id: "p", project_name: "Main", lifecycle: "ACTIVE", interval_seconds: 60, stats: { ...STATS, uptime_pct: null } },
    ],
    total_monitors: 1,
    series: [],
  };

  it("loads periods, requires both custom dates and offers CSV export to members", async () => {
    goTo("/o/acme/reports");
    const calls = mockApi([
      ME,
      memberships(),
      { path: `/api/orgs/${ORG_A}/reports?period=7d`, body: REPORT },
      { path: `/api/orgs/${ORG_A}/reports?period=custom&from=2026-10-01&to=2026-10-07`, body: REPORT },
    ]);
    render(<App />);
    expect(await screen.findByText("Payments API")).toBeTruthy();
    expect(screen.getByText("10 min")).toBeTruthy(); // median time to resolve
    expect(screen.getByRole("link", { name: "Export CSV" }).getAttribute("href")).toBe(
      `/api/orgs/${ORG_A}/reports/export.csv?period=7d`,
    );
    const row = screen.getByText("Payments API").closest("tr") as HTMLElement;
    expect(row.textContent).toContain("No data");
    fireEvent.change(screen.getByLabelText("Period"), { target: { value: "custom" } });
    expect(screen.getByText("Choose both dates.")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("From"), { target: { value: "2026-10-01" } });
    fireEvent.change(screen.getByLabelText("To"), { target: { value: "2026-10-07" } });
    await waitFor(() => {
      expect(calls.some((c) => c.path.includes("period=custom&from=2026-10-01&to=2026-10-07"))).toBe(true);
    });
  });

  it("hides export from viewers", async () => {
    goTo("/o/acme/reports");
    mockApi([ME, memberships("VIEWER"), { path: `/api/orgs/${ORG_A}/reports?period=7d`, body: REPORT }]);
    render(<App />);
    await screen.findByText("Payments API");
    expect(screen.queryByRole("link", { name: "Export CSV" })).toBeNull();
  });
});
