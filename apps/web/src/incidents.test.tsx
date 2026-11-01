import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "./App.tsx";
import { formatDuration } from "./format.ts";
import { mockApi, type MockRoute } from "./test-utils.ts";

const ORG = "33333333-3333-4333-8333-333333333333";
const MON = "44444444-4444-4444-8444-444444444444";
const INC = "66666666-6666-4666-8666-666666666666";
const ME_ID = "77777777-7777-4777-8777-777777777777";
const OTHER = "88888888-8888-4888-8888-888888888888";
const ME = { path: "/api/auth/me", body: { id: ME_ID, email: "me@acme.test", is_platform_admin: false } };
const LIST = `/api/orgs/${ORG}/incidents?limit=100&active=true`;
const DETAIL = `/api/orgs/${ORG}/incidents/${INC}`;
const MEMBERS: MockRoute = {
  path: `/api/orgs/${ORG}/members`,
  body: [
    { user_id: ME_ID, email: "me@acme.test", role: "ORG_MEMBER", status: "ACTIVE", joined_at: "" },
    { user_id: OTHER, email: "ops@acme.test", role: "ORG_ADMIN", status: "ACTIVE", joined_at: "" },
    { user_id: "gone", email: "gone@acme.test", role: "VIEWER", status: "SUSPENDED", joined_at: "" },
  ],
};

function memberships(role: string): MockRoute {
  return {
    path: "/api/me/organizations",
    body: {
      organizations: [{ organization_id: ORG, slug: "acme", name: "Acme", organization_status: "ACTIVE", role }],
      selected_org_id: ORG,
    },
  };
}

function incident(overrides: object = {}) {
  return {
    id: INC,
    type: "OUTAGE",
    severity: "CRITICAL",
    status: "OPEN",
    source_kind: "HTTP_PROBE",
    title: "Outage detected",
    monitor: { id: MON, name: "Payments API", hostname: "api.acme.example" },
    opened_at: "2026-10-31T10:00:00Z",
    acknowledged_at: null,
    resolved_at: null,
    resolution: null,
    assigned_user_id: null,
    assignee_email: null,
    last_event_at: "2026-10-31T10:00:00Z",
    duration_seconds: null,
    duration_is_estimate: true,
    version: 1,
    ...overrides,
  };
}

const OPENED = {
  id: "e1",
  event_type: "OPENED",
  actor_kind: "SYSTEM",
  actor_user_id: null,
  actor_email: null,
  created_at: "2026-10-31T10:00:00Z",
  details: {
    health_from: "UP",
    health_to: "DOWN",
    consecutive_failures: 3,
    failure_threshold: 3,
    evidence: {
      result: "FAIL",
      failure_category: "HTTP_STATUS_MISMATCH",
      http_status: 503,
      elapsed_ms: 42,
      observed_at: "2026-10-31T10:00:00Z",
    },
  },
};

function detail(overrides: object = {}, events: object[] = [OPENED]) {
  return { ...incident(overrides), monitor_health: "DOWN", monitor_lifecycle: "ACTIVE", events };
}

function goTo(path: string) {
  window.history.replaceState(null, "", path);
}

afterEach(() => {
  cleanup();
});

describe("incidents", () => {
  it("lists active incidents and refetches when filters change", async () => {
    goTo("/o/acme/incidents");
    const calls = mockApi([
      ME,
      memberships("VIEWER"),
      { path: LIST, body: { items: [incident()], total: 1 } },
      {
        path: `/api/orgs/${ORG}/incidents?limit=100&active=false&type=TLS_EXPIRY`,
        body: { items: [], total: 0 },
      },
    ]);
    render(<App />);
    const link = await screen.findByRole("link", { name: "Outage detected" });
    expect(link.getAttribute("href")).toBe(`/o/acme/incidents/${INC}`);
    const row = link.closest("tr") as HTMLElement;
    expect(within(row).getByText("Critical")).toBeTruthy();
    expect(within(row).getByText("Ongoing")).toBeTruthy();
    expect(within(row).getByRole("link", { name: "Payments API" }).getAttribute("href")).toBe(
      `/o/acme/monitors/${MON}`,
    );
    fireEvent.change(screen.getByLabelText("Show"), { target: { value: "resolved" } });
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "TLS_EXPIRY" } });
    expect(await screen.findByText("No incidents match these filters.")).toBeTruthy();
    expect(calls.some((c) => c.path.includes("active=false&type=TLS_EXPIRY"))).toBe(true);
  });

  it("filters to incidents assigned to the current user", async () => {
    goTo("/o/acme/incidents");
    const calls = mockApi([
      ME,
      memberships("ORG_MEMBER"),
      { path: LIST, body: { items: [], total: 0 } },
      { path: `${LIST}&assigned_user_id=${ME_ID}`, body: { items: [], total: 0 } },
    ]);
    render(<App />);
    expect(await screen.findByText("No active incidents.")).toBeTruthy();
    fireEvent.click(screen.getByLabelText("Assigned to me"));
    await waitFor(() => {
      expect(calls.some((c) => c.path.endsWith(`assigned_user_id=${ME_ID}`))).toBe(true);
    });
  });

  it("lets a responder acknowledge, assign and add notes, but not resolve while down", async () => {
    goTo(`/o/acme/incidents/${INC}`);
    const calls = mockApi([
      ME,
      memberships("ORG_MEMBER"),
      MEMBERS,
      { path: DETAIL, body: detail() },
      { method: "POST", path: `${DETAIL}/acknowledge`, body: detail({ status: "ACKNOWLEDGED" }) },
      { method: "POST", path: `${DETAIL}/assign`, body: detail() },
      { method: "POST", path: `${DETAIL}/comments`, status: 201, body: detail() },
    ]);
    render(<App />);
    await screen.findByRole("heading", { name: "Outage detected" });
    expect(screen.getByText("HTTP_STATUS_MISMATCH", { exact: false })).toBeTruthy();
    expect(screen.getByText("Opened after 3 consecutive failed checks")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Resolve" })).toBeNull();
    expect(screen.getByText(/resolves automatically when the monitor recovers/)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Acknowledge" }));
    expect(await screen.findByText("Incident acknowledged.")).toBeTruthy();
    const ack = calls.find((c) => c.path.endsWith("/acknowledge"));
    expect(JSON.parse(String(ack?.init.body))).toEqual({ version: 1 });

    const select = screen.getByLabelText("Assign to");
    expect(within(select).queryByText("gone@acme.test")).toBeNull(); // suspended members hidden
    fireEvent.change(select, { target: { value: OTHER } });
    fireEvent.click(screen.getByRole("button", { name: "Assign" }));
    await screen.findByText("Incident assigned.");
    const assign = calls.find((c) => c.path.endsWith("/assign"));
    expect(JSON.parse(String(assign?.init.body))).toEqual({ user_id: OTHER, version: 1 });

    fireEvent.change(screen.getByLabelText("Add a note"), { target: { value: "  Rolled back deploy " } });
    fireEvent.click(screen.getByRole("button", { name: "Add note" }));
    await screen.findByText("Note added.");
    const note = calls.find((c) => c.path.endsWith("/comments"));
    expect(JSON.parse(String(note?.init.body))).toEqual({ text: "Rolled back deploy" });
  });

  it("allows manual resolution once the monitor is no longer down and shows server errors", async () => {
    goTo(`/o/acme/incidents/${INC}`);
    const calls = mockApi([
      ME,
      memberships("ORG_ADMIN"),
      MEMBERS,
      { path: DETAIL, body: { ...detail({ status: "ACKNOWLEDGED" }), monitor_lifecycle: "PAUSED" } },
      {
        method: "POST",
        path: `${DETAIL}/resolve`,
        status: 409,
        body: { error: { code: "VERSION_CONFLICT", message: "The incident changed; reload and try again" } },
      },
    ]);
    render(<App />);
    await screen.findByRole("heading", { name: "Outage detected" });
    expect(screen.queryByRole("button", { name: "Acknowledge" })).toBeNull();
    fireEvent.change(screen.getByLabelText("Resolution note (optional)"), { target: { value: "Migrated" } });
    fireEvent.click(screen.getByRole("button", { name: "Resolve" }));
    expect((await screen.findByRole("alert")).textContent).toContain("reload and try again");
    const resolve = calls.find((c) => c.path.endsWith("/resolve"));
    expect(JSON.parse(String(resolve?.init.body))).toEqual({ note: "Migrated", version: 1 });
  });

  it("shows viewers the timeline without any action controls", async () => {
    goTo(`/o/acme/incidents/${INC}`);
    const resolvedEvent = {
      id: "e2",
      event_type: "RESOLVED",
      actor_kind: "SYSTEM",
      actor_user_id: null,
      actor_email: null,
      created_at: "2026-10-31T10:02:00Z",
      details: { resolution: "AUTO", consecutive_successes: 2, duration_seconds_estimate: 120 },
    };
    const comment = {
      id: "e3",
      event_type: "COMMENTED",
      actor_kind: "USER",
      actor_user_id: OTHER,
      actor_email: "ops@acme.test",
      created_at: "2026-10-31T10:03:00Z",
      details: { text: "Postmortem scheduled" },
    };
    mockApi([
      ME,
      memberships("VIEWER"),
      MEMBERS,
      {
        path: DETAIL,
        body: detail(
          { status: "RESOLVED", resolution: "AUTO", resolved_at: "2026-10-31T10:02:00Z", duration_seconds: 120 },
          [OPENED, resolvedEvent, comment],
        ),
      },
    ]);
    render(<App />);
    await screen.findByRole("heading", { name: "Outage detected" });
    expect(screen.getByText("Resolved after 2 consecutive successful checks")).toBeTruthy();
    expect(screen.getByText("Postmortem scheduled")).toBeTruthy();
    expect(screen.getByText("2 min (estimated)")).toBeTruthy();
    expect(screen.getByText(/estimated from the failed and recovered checks/)).toBeTruthy();
    for (const name of ["Acknowledge", "Assign", "Resolve", "Add note"]) {
      expect(screen.queryByRole("button", { name })).toBeNull();
    }
  });

  it("reports a missing incident", async () => {
    goTo(`/o/acme/incidents/${INC}`);
    mockApi([ME, memberships("ORG_MEMBER"), MEMBERS]);
    render(<App />);
    expect((await screen.findByRole("alert")).textContent).toContain("Not Found");
  });

  it("links monitor detail to its incidents", async () => {
    goTo(`/o/acme/monitors/${MON}`);
    mockApi([
      ME,
      memberships("VIEWER"),
      {
        path: `/api/orgs/${ORG}/monitors/${MON}`,
        body: {
          id: MON,
          name: "Payments API",
          project_id: "p",
          hostname: "api.acme.example",
          lifecycle: "ACTIVE",
          paused_reason: null,
          attention_reason: null,
          health_state: "DOWN",
          latest: null,
          version: 1,
          config: null,
        },
      },
      { path: `/api/orgs/${ORG}/monitors/${MON}/measurements?limit=100`, body: [] },
      {
        path: `/api/orgs/${ORG}/incidents?monitor_id=${MON}&limit=20`,
        body: { items: [incident({ type: "TLS_EXPIRY", severity: "WARNING", title: "TLS certificate expiring" })], total: 1 },
      },
    ]);
    render(<App />);
    const link = await screen.findByRole("link", { name: "TLS certificate expiring" });
    expect(link.getAttribute("href")).toBe(`/o/acme/incidents/${INC}`);
  });

  it("formats durations", () => {
    expect(formatDuration(45)).toBe("45 s");
    expect(formatDuration(600)).toBe("10 min");
    expect(formatDuration(3 * 3600 + 120)).toBe("3 h 2 min");
    expect(formatDuration(3 * 86400 + 7200)).toBe("3 d 2 h");
  });
});
