import AxeBuilder from "@axe-core/playwright";
import { type Browser, type BrowserContext, expect, type Page, test } from "@playwright/test";
import {
  choosePassword,
  emailedLink,
  harness,
  noHorizontalScroll,
  PASSWORD,
  signIn,
  totp,
  waitForNextTotpStep,
} from "./helpers.ts";

/**
 * The main SentinelOps journeys in one serial story on a disposable database (AC-014):
 * platform admin with MFA → organizations → owner onboarding and org switching → projects and
 * members → domain verification and monitoring → notifications → outage, acknowledge, assign,
 * recovery → public status page → aggregate-only admin dashboard. All external effects are fakes.
 */
test.describe.configure({ mode: "serial" });

const ADMIN = "platform-admin@sentinelops.test";
const OWNER = "olivia.owner@acme.test";
const MEMBER = "maria.member@acme.test";
const SECRET_QUERY = "e2e-secret-query";

let adminSecret = "";
let recoveryCodes: string[] = [];
const contexts: Record<string, BrowserContext> = {};

async function pageFor(browser: Browser, who: string): Promise<Page> {
  contexts[who] ??= await browser.newContext();
  const pages = contexts[who].pages();
  return pages[0] ?? (await contexts[who].newPage());
}

test.afterAll(async () => {
  for (const context of Object.values(contexts)) await context.close();
});

test("A1 platform admin activates the bootstrap account and must enrol MFA", async ({ browser }) => {
  const { activation_url } = await harness<{ activation_url: string }>("POST", "/bootstrap", { email: ADMIN });
  const page = await pageFor(browser, "admin");
  await page.goto(activation_url);
  await choosePassword(page, "Set password and activate");
  await expect(page).toHaveURL(/\/login/);
  await signIn(page, ADMIN);
  await expect(page.getByText(/must use multi-factor authentication/)).toBeVisible();
  await expect(page.getByRole("link", { name: "Organizations" })).toHaveCount(0);
  await page.getByLabel("Current password").fill(PASSWORD);
  await page.getByRole("button", { name: "Continue" }).click();
  adminSecret = (await page.getByTestId("mfa-secret").textContent()) ?? "";
  expect(adminSecret).toMatch(/^[A-Z2-7]{32}$/);
  await page.getByLabel("Authentication code").fill(totp(adminSecret));
  await page.getByRole("button", { name: "Turn on MFA" }).click();
  const codes = page.getByRole("list", { name: "Recovery codes" }).getByRole("listitem");
  await expect(codes).toHaveCount(10);
  recoveryCodes = (await codes.allTextContents()).map((c) => c.trim());
  await page.getByRole("button", { name: "I have saved these codes" }).click();
  await expect(page.getByRole("heading", { name: "Platform dashboard" })).toBeVisible();
});

test("A2 sign-in requires a valid second factor; recovery codes work once", async ({ browser }) => {
  const page = await pageFor(browser, "admin");
  await page.getByRole("button", { name: "Sign out" }).click();
  await signIn(page, ADMIN);
  await expect(page.getByRole("heading", { name: "Two-step verification" })).toBeVisible();
  await page.getByLabel("Authentication code").fill("000000");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("alert")).toContainText("not valid");
  await page.getByRole("button", { name: "Use a recovery code" }).click();
  await page.getByLabel("Recovery code").fill(recoveryCodes[0] ?? "");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Platform dashboard" })).toBeVisible();
  // A fresh authenticator code (new 30 s step) also works; a replayed one would not.
  await page.getByRole("button", { name: "Sign out" }).click();
  await waitForNextTotpStep();
  await signIn(page, ADMIN);
  await page.getByLabel("Authentication code").fill(totp(adminSecret));
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Platform dashboard" })).toBeVisible();
});

test("A3 admin creates organizations, invites the owner, suspends and reactivates", async ({ browser }) => {
  const page = await pageFor(browser, "admin");
  page.on("dialog", (dialog) => void dialog.accept());
  await page.getByRole("link", { name: "Organizations" }).click();
  for (const [name, slug] of [
    ["Acme E2E", "acme-e2e"],
    ["Globex E2E", "globex-e2e"],
  ] as const) {
    await page.getByLabel("Name").fill(name);
    await page.getByLabel("Slug").fill(slug);
    await page.getByLabel("Owner email").fill(OWNER);
    await page.getByRole("button", { name: "Create organization" }).click();
    await expect(page.getByRole("link", { name })).toBeVisible();
  }
  await page.getByRole("link", { name: "Globex E2E" }).click();
  await page.getByLabel("Suspension reason").fill("E2E suspension check");
  await page.getByRole("button", { name: "Suspend" }).click();
  await expect(page.getByText("Suspended: E2E suspension check")).toBeVisible();
  await page.getByRole("button", { name: "Activate" }).click();
  await expect(page.getByText("Organization activated.")).toBeVisible();
});

test("B1 owner accepts both invitations and switches organizations", async ({ browser }) => {
  const messages = await harness<{ body: string }[]>("GET", `/mail?to=${OWNER}`);
  const links = messages.map((m) => /(https?:\/\/\S+#token=\S+)/.exec(m.body)?.[1] ?? "").filter(Boolean);
  expect(links).toHaveLength(2);
  const page = await pageFor(browser, "owner");
  await page.goto(links[0] ?? "");
  await choosePassword(page, "Create account and join");
  await signIn(page, OWNER);
  await page.goto(links[1] ?? "");
  await page.getByRole("button", { name: /Join as/ }).click();
  await page.getByRole("combobox", { name: "Organization", exact: true }).selectOption("acme-e2e");
  await expect(page).toHaveURL(/\/o\/acme-e2e/);
  await page.getByRole("combobox", { name: "Organization", exact: true }).selectOption("globex-e2e");
  await expect(page).toHaveURL(/\/o\/globex-e2e/);
  await expect(page.getByRole("heading", { name: "Globex E2E" })).toBeVisible();
  await page.getByRole("combobox", { name: "Organization", exact: true }).selectOption("acme-e2e");
  await expect(page.getByRole("heading", { name: "Acme E2E" })).toBeVisible();
});

test("B2 owner manages a project and memberships; roles are enforced", async ({ browser }) => {
  const page = await pageFor(browser, "owner");
  await page.getByRole("link", { name: "Projects" }).click();
  await page.getByLabel("New project name").fill("Checkout");
  await page.getByRole("button", { name: "Create project" }).click();
  await expect(page.getByRole("cell", { name: "Checkout" })).toBeVisible();
  await page.getByRole("link", { name: "Members" }).click();
  await page.getByLabel("Invite by email").fill(MEMBER);
  const invite = page.locator("form", { has: page.getByLabel("Invite by email") });
  await invite.getByRole("combobox").selectOption("ORG_MEMBER");
  await page.getByRole("button", { name: "Send invitation" }).click();
  const member = await pageFor(browser, "member");
  await member.goto(await emailedLink(MEMBER));
  await choosePassword(member, "Create account and join");
  await signIn(member, MEMBER);
  await expect(member).toHaveURL(/\/o\/acme-e2e/);
  await page.reload();
  await page.getByLabel(`Role for ${MEMBER}`).selectOption("VIEWER");
  await expect(page.getByText("Role updated.")).toBeVisible();
  await member.goto("/o/acme-e2e/monitors");
  await expect(member.getByRole("link", { name: "New monitor" })).toHaveCount(0);
  await page.getByLabel(`Role for ${MEMBER}`).selectOption("ORG_MEMBER");
  await expect(page.getByText("Role updated.")).toBeVisible();
});

test("B3 another organization's data is inaccessible", async ({ browser }) => {
  const owner = await pageFor(browser, "owner");
  const orgs = await owner.request.get("/api/me/organizations");
  const globex = ((await orgs.json()) as { organizations: { slug: string; organization_id: string }[] }).organizations.find(
    (o) => o.slug === "globex-e2e",
  );
  const member = await pageFor(browser, "member");
  await member.goto("/o/globex-e2e");
  await expect(member.getByText("Organization not found.")).toBeVisible();
  for (const path of ["", "/monitors", "/incidents", "/notification-channels", "/reports"]) {
    const response = await member.request.get(`/api/orgs/${globex?.organization_id ?? ""}${path}`);
    expect(response.status(), path).toBe(404);
  }
});

test("C owner verifies a domain with mocked DNS and monitors an endpoint", async ({ browser }) => {
  const page = await pageFor(browser, "owner");
  await page.goto("/o/acme-e2e/domains");
  await page.getByLabel("Domain (e.g. example.com)").fill("acme.example");
  await page.getByRole("button", { name: "Add domain" }).click();
  const challenge = page.getByLabel("DNS challenge");
  await expect(challenge.locator("code")).toHaveCount(2);
  const [name, value] = await challenge.locator("code").allTextContents();
  await harness("PUT", "/dns", { name, values: [value] });
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByText("acme.example verified.")).toBeVisible();
  await page.goto("/o/acme-e2e/monitors/new");
  await page.getByLabel("Name").fill("Payments API");
  await page.getByLabel("Project").selectOption({ label: "Checkout" });
  await page.getByLabel(/^URL/).fill(`https://api.acme.example/health?key=${SECRET_QUERY}`);
  await page.getByRole("button", { name: "Create monitor" }).click();
  await expect(page.getByRole("heading", { name: "Payments API" })).toBeVisible();
  await harness("POST", "/checks", { result: "PASS", rounds: 2 });
  await page.reload();
  await expect(page.getByRole("cell", { name: "Pass" }).first()).toBeVisible();
  await page.getByRole("button", { name: "Pause" }).click();
  await expect(page.getByText("Monitor paused.")).toBeVisible();
  await page.getByRole("button", { name: "Resume" }).click();
  await expect(page.getByText("Monitor resumed.")).toBeVisible();
  await page.goto("/o/acme-e2e");
  await expect(page.getByRole("heading", { name: "Last 24 hours" })).toBeVisible();
  await expect(page.getByText("100.000%")).toBeVisible();
});

test("E owner configures an email channel and route", async ({ browser }) => {
  const page = await pageFor(browser, "owner");
  await page.goto("/o/acme-e2e/notifications");
  const form = page.locator("form", { has: page.getByRole("heading", { name: "Add a channel" }) });
  await form.getByRole("combobox").first().selectOption("EMAIL");
  await form.getByLabel("Label").fill("Ops email");
  await form.getByLabel(OWNER).check();
  await page.getByRole("button", { name: "Add channel" }).click();
  await expect(page.getByText("Channel added.")).toBeVisible();
  await expect(page.getByRole("cell", { name: "All monitors" })).toBeVisible();
});

test("D failures open an incident; acknowledge, assign, recover", async ({ browser }) => {
  const page = await pageFor(browser, "owner");
  await harness("POST", "/checks", { result: "FAIL", rounds: 3 });
  await page.goto("/o/acme-e2e/incidents");
  await page.getByRole("link", { name: "Outage detected" }).click();
  await expect(page.getByText("Opened after 3 consecutive failed checks")).toBeVisible();
  await page.getByRole("button", { name: "Acknowledge" }).click();
  await expect(page.getByText("Incident acknowledged.")).toBeVisible();
  await page.getByLabel("Assign to").selectOption({ label: MEMBER });
  await page.getByRole("button", { name: "Assign" }).click();
  await expect(page.getByText("Incident assigned.")).toBeVisible();
  await expect(page.getByText(/resolves automatically when the monitor recovers/)).toBeVisible();
  await harness("POST", "/checks", { result: "PASS", rounds: 2 });
  await page.reload();
  await expect(page.getByText("Resolved after 2 consecutive successful checks")).toBeVisible();
  // Notifications go through the fake mailbox only.
  await harness("POST", "/notifier");
  await page.goto("/o/acme-e2e/notifications");
  await expect(page.getByRole("cell", { name: "Sent" }).first()).toBeVisible();
  const mail = await harness<{ subject: string; body: string }[]>("GET", `/mail?to=${OWNER}`);
  const alerts = mail.filter((m) => m.subject.includes("Payments API"));
  expect(alerts.length).toBeGreaterThan(0);
  for (const message of alerts) expect(message.body).not.toContain(SECRET_QUERY);
});

test("F published status pages are public and private data never appears", async ({ browser }) => {
  const page = await pageFor(browser, "owner");
  await page.goto("/o/acme-e2e/status-pages");
  await page.getByLabel("Title").fill("Acme status");
  await page.getByLabel("Public address").fill("acme-e2e");
  await page.getByLabel("Payments API", { exact: true }).check();
  await page.getByLabel("Public name for Payments API").fill("Public API");
  await page.getByRole("button", { name: "Create page" }).click();
  await page.getByRole("button", { name: "Publish" }).click();
  await expect(page.getByText("Page published.")).toBeVisible();
  const anonymous = await browser.newContext();
  const visitor = await anonymous.newPage();
  await visitor.goto("/status/acme-e2e");
  await expect(visitor.getByRole("heading", { name: "Acme status" })).toBeVisible();
  await expect(visitor.getByRole("cell", { name: "Public API" })).toBeVisible();
  const html = await visitor.content();
  for (const secret of ["Payments API", "api.acme.example", SECRET_QUERY, MEMBER, OWNER]) {
    expect(html).not.toContain(secret);
  }
  await page.getByRole("button", { name: "Unpublish" }).click();
  await expect(page.getByText(/Page unpublished/)).toBeVisible();
  await anonymous.close();
  // A new visitor (no browser cache; published responses may be cached for up to 30 s).
  const fresh = await browser.newContext();
  const later = await fresh.newPage();
  await later.goto("/status/acme-e2e");
  await expect(later.getByRole("alert")).toContainText("not available");
  expect((await later.request.get("/api/status/acme-e2e")).status()).toBe(404);
  await fresh.close();
});

test("A4 platform dashboard shows aggregates only", async ({ browser }) => {
  const page = await pageFor(browser, "admin");
  await page.getByRole("link", { name: "Dashboard" }).click();
  await expect(page.getByRole("heading", { name: "Usage against limits" })).toBeVisible();
  await expect(page.getByRole("cell", { name: /Acme E2E/ })).toBeVisible();
  const html = await page.content();
  for (const secret of ["Payments API", "api.acme.example", SECRET_QUERY, "Outage detected"]) {
    expect(html).not.toContain(secret);
  }
});

test("G dashboards work on a phone and pass automated accessibility checks", async ({ browser }) => {
  const owner = await pageFor(browser, "owner");
  await owner.setViewportSize({ width: 390, height: 844 });
  for (const path of ["/o/acme-e2e", "/o/acme-e2e/monitors", "/o/acme-e2e/incidents", "/o/acme-e2e/reports"]) {
    await owner.goto(path);
    await expect(owner.getByRole("navigation", { name: "Organization sections" })).toBeVisible();
    await noHorizontalScroll(owner);
  }
  await owner.goto("/o/acme-e2e");
  await expect(owner.getByRole("heading", { name: "Last 24 hours" })).toBeVisible();
  const results = await new AxeBuilder({ page: owner }).analyze();
  const serious = results.violations.filter((v) => v.impact === "critical" || v.impact === "serious");
  expect(serious.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
});
