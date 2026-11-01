import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { App } from "./App.tsx";
import { mockApi } from "./test-utils.ts";

const ADMIN = { id: "u1", email: "root@example.test", is_platform_admin: true };
const MEMBER = { id: "u2", email: "member@example.test", is_platform_admin: false };
const UNAUTHENTICATED = {
  path: "/api/auth/me",
  status: 401,
  body: { error: { code: "UNAUTHENTICATED", message: "Authentication required" } },
};

function goTo(path: string) {
  window.history.replaceState(null, "", path);
}

beforeEach(() => {
  goTo("/");
});

afterEach(() => {
  cleanup();
});

describe("routing and guards", () => {
  it("sends anonymous users to sign in", async () => {
    mockApi([UNAUTHENTICATED]);
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeTruthy();
    expect(window.location.pathname).toBe("/login");
  });

  it("blocks platform pages for non-admins", async () => {
    goTo("/admin/admins");
    mockApi([{ path: "/api/auth/me", body: MEMBER }]);
    render(<App />);
    expect((await screen.findByRole("alert")).textContent).toContain(
      "Platform administrator access is required",
    );
  });

  it("shows the platform dashboard to SYSTEM_ADMIN", async () => {
    goTo("/admin");
    mockApi([
      { path: "/api/auth/me", body: ADMIN },
      {
        path: "/api/admin/dashboard",
        body: {
          organizations_by_status: { ACTIVE: 3, SUSPENDED: 1 },
          active_admins: 2,
          pending_invitations: 1,
          recent_audit: [],
          organizations_created_30d: 2,
          monitors_total: 7,
          monitors_active: 5,
          open_incidents_by_severity: { CRITICAL: 1, WARNING: 0 },
          queue: {
            checks_per_minute: 4.5,
            checks_last_24h: 6400,
            due_backlog: 0,
            claim_lag_seconds: null,
            checks_in_flight: 2,
            outbox_pending: 1,
            outbox_leased: 0,
            outbox_lag_seconds: null,
            outbox_failed_24h: 0,
          },
          workers: [{ worker_id: "w1", kind: "WORKER", last_seen_at: "2026-10-31T10:00:00Z", in_flight: 2, alive: true }],
          usage_daily: [],
          organizations: [
            {
              organization_id: "o1",
              slug: "acme",
              name: "Acme",
              status: "ACTIVE",
              active_members: 4,
              monitors_live: 7,
              monitors_active: 5,
              max_monitors: 20,
              status_pages: 1,
              max_status_pages: 3,
              channels: 2,
              max_channels: 10,
              open_incidents_critical: 1,
              open_incidents_warning: 0,
            },
          ],
        },
      },
    ]);
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Platform dashboard" })).toBeTruthy();
    expect(screen.getByText("Active platform administrators")).toBeTruthy();
    expect(screen.getByText("Suspended organizations")).toBeTruthy();
    expect(screen.getByText("5 / 7")).toBeTruthy();
    expect(screen.getByText("7 / 20")).toBeTruthy();
    expect(screen.getByText(/worker alive/)).toBeTruthy();
  });
});

describe("sign in", () => {
  it("shows the server's generic error and clears the password", async () => {
    goTo("/login");
    mockApi([
      UNAUTHENTICATED,
      {
        method: "POST",
        path: "/api/auth/login",
        status: 401,
        body: { error: { code: "INVALID_CREDENTIALS", message: "Invalid email or password" } },
      },
    ]);
    render(<App />);
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "a@example.test" } });
    const password = screen.getByLabelText("Password") as HTMLInputElement;
    fireEvent.change(password, { target: { value: "wrong-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Invalid email or password");
    expect(password.value).toBe("");
  });
});

describe("activation", () => {
  it("reads the token from the fragment, strips it from the URL and submits it", async () => {
    goTo("/activate#token=secret-token-value");
    const calls = mockApi([UNAUTHENTICATED, { method: "POST", path: "/api/auth/activate", status: 204 }]);
    render(<App />);
    await screen.findByRole("heading", { name: "Activate your account" });
    expect(window.location.hash).toBe("");
    fireEvent.change(screen.getByLabelText("New password"), {
      target: { value: "a-long-new-passphrase" },
    });
    fireEvent.change(screen.getByLabelText("Confirm password"), {
      target: { value: "a-long-new-passphrase" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Set password and activate" }));
    await waitFor(() => {
      expect(window.location.pathname).toBe("/login");
    });
    const post = calls.find((c) => c.method === "POST");
    expect(JSON.parse(String(post?.init.body))).toEqual({
      token: "secret-token-value",
      password: "a-long-new-passphrase",
    });
  });

  it("rejects mismatched confirmation without calling the API", async () => {
    goTo("/activate#token=secret-token-value");
    const calls = mockApi([UNAUTHENTICATED]);
    render(<App />);
    await screen.findByRole("heading", { name: "Activate your account" });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "first-value-123" } });
    fireEvent.change(screen.getByLabelText("Confirm password"), {
      target: { value: "second-value-456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Set password and activate" }));
    expect((await screen.findByRole("alert")).textContent).toBe("The passwords do not match.");
    expect(calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("explains a missing token", async () => {
    goTo("/activate");
    mockApi([UNAUTHENTICATED]);
    render(<App />);
    expect((await screen.findByRole("alert")).textContent).toContain("incomplete");
  });
});
