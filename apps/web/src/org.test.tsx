import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "./App.tsx";
import { mockApi, type MockRoute } from "./test-utils.ts";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const ME = { path: "/api/auth/me", body: { id: "u", email: "dual@example.test", is_platform_admin: false } };

function memberships(selected: string | null = null): MockRoute {
  return {
    path: "/api/me/organizations",
    body: {
      organizations: [
        { organization_id: A, slug: "alpha", name: "Alpha", organization_status: "ACTIVE", role: "VIEWER" },
        { organization_id: B, slug: "beta", name: "Beta", organization_status: "ACTIVE", role: "ORG_OWNER" },
      ],
      selected_org_id: selected,
    },
  };
}

function profile(id: string, name: string, role: string): MockRoute {
  return {
    path: `/api/orgs/${id}`,
    body: {
      id,
      slug: name.toLowerCase(),
      name,
      timezone: "UTC",
      status: "ACTIVE",
      version: 1,
      my_role: role,
      limits: { max_monitors: 20, min_interval_seconds: 60, max_status_pages: 3, max_channels: 10 },
      member_count: 2,
      project_count: 1,
    },
  };
}

function goTo(path: string) {
  window.history.replaceState(null, "", path);
}

afterEach(() => {
  cleanup();
});

describe("organization app", () => {
  it("opens the selected organization from the home page", async () => {
    goTo("/");
    mockApi([ME, memberships(B), profile(B, "Beta", "ORG_OWNER")]);
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Beta" })).toBeTruthy();
    expect(window.location.pathname).toBe("/o/beta");
  });

  it("offers a picker when nothing is selected", async () => {
    goTo("/");
    mockApi([ME, memberships()]);
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Choose an organization" })).toBeTruthy();
  });

  it("hides management links for viewers and shows them for owners", async () => {
    goTo("/o/alpha");
    mockApi([ME, memberships(), profile(A, "Alpha", "VIEWER")]);
    render(<App />);
    await screen.findByRole("heading", { name: "Alpha" });
    const nav = screen.getByRole("navigation", { name: "Organization sections" });
    expect(nav.textContent).not.toContain("Settings");
    expect(nav.textContent).not.toContain("Audit");
    cleanup();

    goTo("/o/beta");
    mockApi([ME, memberships(), profile(B, "Beta", "ORG_OWNER")]);
    render(<App />);
    await screen.findByRole("heading", { name: "Beta" });
    const ownerNav = screen.getByRole("navigation", { name: "Organization sections" });
    expect(ownerNav.textContent).toContain("Settings");
    expect(ownerNav.textContent).toContain("Audit");
  });

  it("switches organization, saves the preference and never shows the old org", async () => {
    goTo("/o/alpha");
    const calls = mockApi([
      ME,
      memberships(),
      profile(A, "Alpha", "VIEWER"),
      profile(B, "Beta", "ORG_OWNER"),
      { method: "PUT", path: "/api/me/preferences", status: 204 },
    ]);
    render(<App />);
    await screen.findByRole("heading", { name: "Alpha" });
    fireEvent.change(await screen.findByLabelText("Organization"), { target: { value: "beta" } });
    expect(await screen.findByRole("heading", { name: "Beta" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Alpha" })).toBeNull();
    expect(window.location.pathname).toBe("/o/beta");
    const put = calls.find((c) => c.method === "PUT");
    expect(JSON.parse(String(put?.init.body))).toEqual({ selected_org_id: B });
  });

  it("treats an unknown organization slug as not found", async () => {
    goTo("/o/gamma");
    const calls = mockApi([ME, memberships()]);
    render(<App />);
    expect((await screen.findByRole("alert")).textContent).toBe("Organization not found.");
    expect(calls.some((c) => c.path.startsWith("/api/orgs/"))).toBe(false);
  });

  it("shows the invite form only to roles that may invite", async () => {
    goTo("/o/alpha/members");
    mockApi([
      ME,
      memberships(),
      {
        path: `/api/orgs/${A}/members`,
        body: [{ user_id: "x", email: "x@example.test", role: "ORG_OWNER", status: "ACTIVE", joined_at: "2026-10-31T00:00:00Z" }],
      },
    ]);
    render(<App />);
    await screen.findByRole("heading", { name: "Members" });
    expect(screen.queryByRole("button", { name: "Send invitation" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Remove" })).toBeNull();
  });
});

describe("invitation acceptance", () => {
  it("asks a new invitee for a password after previewing the invitation", async () => {
    goTo("/accept-invite#token=invite-token-value-123");
    const calls = mockApi([
      { path: "/api/auth/me", status: 401, body: { error: { code: "UNAUTHENTICATED", message: "x" } } },
      {
        method: "POST",
        path: "/api/auth/org-invitations/preview",
        body: { organization_name: "Beta", role: "VIEWER", email: "new@example.test", account_exists: false },
      },
      { method: "POST", path: "/api/auth/org-invitations/accept", body: { organization_id: B } },
    ]);
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Join Beta" })).toBeTruthy();
    expect(window.location.hash).toBe("");
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "a-long-passphrase-1" } });
    fireEvent.change(screen.getByLabelText("Confirm password"), { target: { value: "a-long-passphrase-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Create account and join" }));
    await waitFor(() => {
      expect(window.location.pathname).toBe("/login");
    });
    const accept = calls.find((c) => c.path === "/api/auth/org-invitations/accept");
    expect(JSON.parse(String(accept?.init.body))).toEqual({
      token: "invite-token-value-123",
      password: "a-long-passphrase-1",
    });
  });
});
