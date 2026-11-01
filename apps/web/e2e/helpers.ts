import { createHmac } from "node:crypto";
import { expect, type Page } from "@playwright/test";

export const API = "http://127.0.0.1:8001";
export const PASSWORD = "e2e-fictional-passphrase-2026"; // fictional, disposable test DB only

export async function harness<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(`${API}/__e2e${path}`, {
    method,
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? null : JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`harness ${path}: ${String(response.status)}`);
  return (await response.json()) as T;
}

/** The newest emailed single-use link for an address (fake mailbox). */
export async function emailedLink(to: string, contains = "#token="): Promise<string> {
  const messages = await harness<{ body: string }[]>("GET", `/mail?to=${encodeURIComponent(to)}`);
  for (const message of messages.reverse()) {
    const match = /(https?:\/\/\S+#token=\S+)/.exec(message.body);
    if (match?.[1]?.includes(contains)) return match[1];
  }
  throw new Error(`no link for ${to}`);
}

function base32(secret: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of secret.replace(/=+$/, "").toUpperCase()) {
    bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s), as an authenticator app would compute it. */
export function totp(secret: string, at = Date.now()): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const digest = createHmac("sha1", base32(secret)).update(counter).digest();
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f;
  const value = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(value % 1_000_000).padStart(6, "0");
}

export async function waitForNextTotpStep(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 30_500 - (Date.now() % 30_000)));
}

export async function signIn(page: Page, email: string, password = PASSWORD): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).not.toHaveURL(/\/login/); // the session cookie is set before moving on
}

export async function choosePassword(page: Page, button: string): Promise<void> {
  await page.getByLabel("New password").fill(PASSWORD);
  await page.getByLabel("Confirm password").fill(PASSWORD);
  await page.getByRole("button", { name: button }).click();
}

export async function noHorizontalScroll(page: Page): Promise<void> {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
}
