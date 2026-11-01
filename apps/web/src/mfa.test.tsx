import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "./App.tsx";
import { mockApi } from "./test-utils.ts";

function goTo(path: string) {
  window.history.replaceState(null, "", path);
}

afterEach(() => {
  cleanup();
});

const ADMIN = { id: "a", email: "root@platform.test", is_platform_admin: true };

describe("admin MFA", () => {
  it("asks a pending session for a code before anything else", async () => {
    goTo("/admin/organizations");
    const calls = mockApi([
      { path: "/api/auth/me", body: { ...ADMIN, mfa_pending: "VERIFY" } },
      { method: "POST", path: "/api/auth/mfa/verify", status: 401, body: { error: { code: "INVALID_MFA_CODE", message: "The code is not valid" } } },
    ]);
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Two-step verification" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Organizations" })).toBeNull();
    fireEvent.change(screen.getByLabelText("Authentication code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect((await screen.findByRole("alert")).textContent).toContain("not valid");
    expect(calls.some((c) => c.path === "/api/admin/organizations")).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Use a recovery code" }));
    expect(screen.getByLabelText("Recovery code")).toBeTruthy();
  });

  it("walks a required enrolment through password, key and recovery codes", async () => {
    goTo("/admin");
    const calls = mockApi([
      { path: "/api/auth/me", body: { ...ADMIN, mfa_pending: "ENROLL" } },
      { method: "POST", path: "/api/auth/mfa/enroll", body: { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/x" } },
      { method: "POST", path: "/api/auth/mfa/enroll/confirm", body: { recovery_codes: ["abcd-efgh-jkmn", "pqrs-tuvw-xyz2"] } },
    ]);
    render(<App />);
    expect(await screen.findByText(/must use multi-factor authentication/)).toBeTruthy();
    const password = screen.getByLabelText("Current password");
    expect(password.getAttribute("type")).toBe("password");
    fireEvent.change(password, { target: { value: "a-long-passphrase" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect((await screen.findByTestId("mfa-secret")).textContent).toBe("JBSWY3DPEHPK3PXP");
    fireEvent.change(screen.getByLabelText("Authentication code"), { target: { value: "654321" } });
    fireEvent.click(screen.getByRole("button", { name: "Turn on MFA" }));
    expect(await screen.findByText("abcd-efgh-jkmn")).toBeTruthy();
    const confirm = calls.find((c) => c.path.endsWith("/enroll/confirm"));
    expect(JSON.parse(String(confirm?.init.body))).toEqual({ code: "654321" });
  });
});
