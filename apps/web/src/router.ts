import { useSyncExternalStore } from "react";

const listeners = new Set<() => void>();

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  window.addEventListener("popstate", listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("popstate", listener);
  };
}

export function navigate(path: string): void {
  window.history.pushState(null, "", path);
  for (const listener of listeners) {
    listener();
  }
}

export function usePath(): string {
  return useSyncExternalStore(subscribe, () => window.location.pathname);
}

/**
 * Reads a single-use token from the URL fragment (never sent to servers), then removes it from
 * the address bar and history so it cannot be copied or replayed from there.
 */
export function takeFragmentToken(): string | null {
  const match = /(?:^#|&)token=([^&]+)/.exec(window.location.hash);
  if (!match?.[1]) {
    return null;
  }
  window.history.replaceState(null, "", window.location.pathname);
  return decodeURIComponent(match[1]);
}

export const ORG_SECTIONS = [
  "",
  "monitors",
  "incidents",
  "notifications",
  "status-pages",
  "reports",
  "domains",
  "projects",
  "members",
  "settings",
  "audit",
] as const;
export type OrgSection = (typeof ORG_SECTIONS)[number];
