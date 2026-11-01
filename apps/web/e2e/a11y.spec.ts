import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { noHorizontalScroll } from "./helpers.ts";

/** Public pages on desktop and mobile: keyboard use, labels, focus and automated a11y checks. */

test("sign-in form is labelled and fully keyboard operable", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByLabel("Email")).toBeVisible();
  await expect(page.getByLabel("Password", { exact: true })).toBeVisible();
  await page.keyboard.press("Tab");
  let reachedEmail = false;
  for (let i = 0; i < 10 && !reachedEmail; i += 1) {
    reachedEmail = await page.getByLabel("Email").evaluate((el) => el === document.activeElement);
    if (!reachedEmail) await page.keyboard.press("Tab");
  }
  expect(reachedEmail).toBe(true);
  const outline = await page.getByLabel("Email").evaluate((el) => getComputedStyle(el).outlineStyle);
  expect(outline).not.toBe("none"); // visible focus indicator
  await page.keyboard.type("nobody@example.test");
  await page.keyboard.press("Tab");
  await page.keyboard.type("wrong-password-123");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("alert")).toBeVisible();
  await noHorizontalScroll(page);
});

test("public pages have no serious accessibility violations", async ({ page }) => {
  for (const path of ["/login", "/forgot-password", "/status/does-not-exist"]) {
    await page.goto(path);
    await page.waitForLoadState("networkidle");
    await noHorizontalScroll(page);
    const results = await new AxeBuilder({ page }).analyze();
    const serious = results.violations.filter((v) => v.impact === "critical" || v.impact === "serious");
    expect(serious.map((v) => `${path} ${v.id}: ${v.help}`)).toEqual([]);
  }
});
