import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "./App.tsx";
import { mockApi, type MockRoute } from "./test-utils.ts";

const ORG = "33333333-3333-4333-8333-333333333333";
const CH = "99999999-9999-4999-8999-999999999999";
const MON = "44444444-4444-4444-8444-444444444444";
const ADMIN = "77777777-7777-4777-8777-777777777777";
const ME = { path: "/api/auth/me", body: { id: ADMIN, email: "admin@acme.test", is_platform_admin: false } };
const BASE = `/api/orgs/${ORG}`;

function memberships(role: string): MockRoute {
  return {
    path: "/api/me/organizations",
    body: {
      organizations: [{ organization_id: ORG, slug: "acme", name: "Acme", organization_status: "ACTIVE", role }],
      selected_org_id: ORG,
    },
  };
}

const CHANNEL = {
  id: CH,
  type: "TELEGRAM",
  label: "On-call chat",
  enabled: true,
  credentials_set: true,
  recipients: [],
  created_at: "2026-10-31T10:00:00Z",
  version: 1,
};

const DELIVERY = {
  id: "d1",
  channel_id: CH,
  event_type: "INCIDENT_OPENED",
  incident_id: "i1",
  monitor_id: MON,
  state: "PENDING",
  cancel_reason: null,
  attempts: 1,
  last_result_code: "TELEGRAM_UNAVAILABLE",
  created_at: "2026-10-31T10:00:00Z",
  next_attempt_at: "2026-10-31T10:01:00Z",
  sent_at: null,
  history: [{ attempt: 1, result_code: "TELEGRAM_UNAVAILABLE", attempted_at: "2026-10-31T10:00:00Z" }],
};

function notificationRoutes(role: string, extra: MockRoute[] = []): MockRoute[] {
  return [
    ME,
    memberships(role),
    { path: `${BASE}/notification-channels`, body: [CHANNEL] },
    {
      path: `${BASE}/members`,
      body: [{ user_id: ADMIN, email: "admin@acme.test", role: "ORG_ADMIN", status: "ACTIVE", joined_at: "" }],
    },
    {
      path: `${BASE}/notification-routes`,
      body: [
        {
          id: "r1",
          channel_id: CH,
          project_id: null,
          monitor_id: null,
          event_types: ["INCIDENT_OPENED", "INCIDENT_RESOLVED"],
          enabled: true,
          version: 1,
        },
      ],
    },
    { path: `${BASE}/projects`, body: [] },
    { path: `${BASE}/monitors`, body: [] },
    { path: `${BASE}/notification-deliveries?limit=50`, body: [DELIVERY] },
    ...extra,
  ];
}

function goTo(path: string) {
  window.history.replaceState(null, "", path);
}

afterEach(() => {
  cleanup();
});

describe("notifications", () => {
  it("shows channels without credentials, routes and delivery history", async () => {
    goTo("/o/acme/notifications");
    mockApi(notificationRoutes("ORG_ADMIN"));
    render(<App />);
    expect((await screen.findAllByText("On-call chat")).length).toBeGreaterThan(0);
    expect(screen.getByText("Bot token and chat ID set")).toBeTruthy();
    expect(await screen.findByText("Outage opened, Incident resolved")).toBeTruthy();
    expect(await screen.findByText(/Queued · retry/)).toBeTruthy();
    expect(screen.getAllByText("TELEGRAM_UNAVAILABLE").length).toBeGreaterThan(0);
  });

  it("creates a Telegram channel with masked token input", async () => {
    goTo("/o/acme/notifications");
    const calls = mockApi(
      notificationRoutes("ORG_ADMIN", [
        { method: "POST", path: `${BASE}/notification-channels`, status: 201, body: CHANNEL },
      ]),
    );
    render(<App />);
    await screen.findByRole("heading", { name: "Add a channel" });
    fireEvent.change(screen.getByLabelText("Label"), { target: { value: "Ops" } });
    const token = screen.getByLabelText("Bot token");
    expect(token.getAttribute("type")).toBe("password");
    fireEvent.change(token, { target: { value: "123:abc" } });
    fireEvent.change(screen.getByLabelText("Chat ID"), { target: { value: "-100" } });
    fireEvent.click(screen.getByRole("button", { name: "Add channel" }));
    expect(await screen.findByText("Channel added.")).toBeTruthy();
    const post = calls.find((c) => c.method === "POST");
    expect(JSON.parse(String(post?.init.body))).toEqual({
      type: "TELEGRAM",
      label: "Ops",
      telegram: { bot_token: "123:abc", chat_id: "-100" },
      route_all_events: true,
    });
  });

  it("queues a test message", async () => {
    goTo("/o/acme/notifications");
    const calls = mockApi(
      notificationRoutes("ORG_ADMIN", [
        { method: "POST", path: `${BASE}/notification-channels/${CH}/test`, status: 202, body: { status: "queued" } },
      ]),
    );
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Send test" }));
    expect(await screen.findByText(/Test message queued/)).toBeTruthy();
    expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/test"))).toBe(true);
  });

  it("gives members a read-only view and hides the section from viewers", async () => {
    goTo("/o/acme/notifications");
    mockApi(notificationRoutes("ORG_MEMBER"));
    render(<App />);
    await screen.findAllByText("On-call chat");
    for (const name of ["Send test", "Disable", "Replace credentials", "Add channel", "Remove"]) {
      expect(screen.queryByRole("button", { name })).toBeNull();
    }
    cleanup();
    goTo("/o/acme/incidents");
    mockApi([ME, memberships("VIEWER"), { path: `${BASE}/incidents?limit=100&active=true`, body: { items: [], total: 0 } }]);
    render(<App />);
    await screen.findByText("No active incidents.");
    expect(screen.queryByRole("link", { name: "Notifications" })).toBeNull();
    expect(screen.getByRole("link", { name: "Status pages" })).toBeTruthy();
  });
});

describe("status pages", () => {
  const PAGE = {
    id: "p1",
    title: "Acme status",
    public_slug: "acme-status",
    published: false,
    monitors: [{ monitor_id: MON, monitor_name: "Payments API", public_display_name: "Checkout", sort_order: 0 }],
    created_at: "",
    version: 1,
  };

  it("publishes a page", async () => {
    goTo("/o/acme/status-pages");
    const calls = mockApi([
      ME,
      memberships("ORG_ADMIN"),
      { path: `${BASE}/status-pages`, body: [PAGE] },
      { path: `${BASE}/monitors`, body: [] },
      { method: "POST", path: `${BASE}/status-pages/p1/publish`, body: { ...PAGE, published: true } },
    ]);
    render(<App />);
    expect(await screen.findByText("Private")).toBeTruthy();
    expect(screen.getByText("Checkout")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Publish" }));
    expect(await screen.findByText("Page published.")).toBeTruthy();
    expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/publish"))).toBe(true);
  });

  it("lets viewers see pages without management controls", async () => {
    goTo("/o/acme/status-pages");
    mockApi([ME, memberships("VIEWER"), { path: `${BASE}/status-pages`, body: [PAGE] }]);
    render(<App />);
    await screen.findByText("Acme status");
    expect(screen.queryByRole("button", { name: "Publish" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "New status page" })).toBeNull();
  });

  it("renders the public page from the snapshot, escaping names", async () => {
    goTo("/status/acme-status");
    mockApi([
      { path: "/api/auth/me", status: 401, body: { error: { code: "UNAUTHENTICATED", message: "x" } } },
      {
        path: "/api/status/acme-status",
        body: {
          title: "Acme status",
          generated_at: "2026-10-31T10:00:00Z",
          overall: "OUTAGE",
          components: [{ name: "<img src=x onerror=alert(1)>", status: "OUTAGE", uptime_24h: 97.5, uptime_7d: null }],
          active_incidents: [
            { title: "Service disruption", component: "Checkout", status: "INVESTIGATING", started_at: "2026-10-31T09:00:00Z" },
          ],
          recent_incidents: [],
        },
      },
    ]);
    const { container } = render(<App />);
    expect(await screen.findByText("Some systems are experiencing an outage")).toBeTruthy();
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeTruthy();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("97.50%")).toBeTruthy();
    expect(screen.getByText(/Service disruption/)).toBeTruthy();
  });

  it("shows a neutral message for unavailable public pages", async () => {
    goTo("/status/missing-page");
    mockApi([{ path: "/api/auth/me", status: 401, body: { error: { code: "UNAUTHENTICATED", message: "x" } } }]);
    render(<App />);
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toContain("not available");
    });
  });
});
