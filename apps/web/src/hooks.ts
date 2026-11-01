import { useCallback, useEffect, useState } from "react";
import { apiRequest } from "./api.ts";
import { errorMessage } from "./format.ts";

/** GET a resource; re-fetches when the path changes (e.g. switching organization). */
export function useLoad<T>(path: string | null): {
  data: T | null;
  error: string | null;
  reload: () => void;
} {
  const [state, setState] = useState<{ path: string | null; data: T | null; error: string | null }>(
    { path: null, data: null, error: null },
  );
  const [nonce, setNonce] = useState(0);
  useEffect(() => {
    if (!path) return;
    let active = true;
    apiRequest<T>("GET", path).then(
      (value) => {
        if (active) setState({ path, data: value, error: null });
      },
      (err: unknown) => {
        if (active) setState({ path, data: null, error: errorMessage(err) });
      },
    );
    return () => {
      active = false;
    };
  }, [path, nonce]);
  const reload = useCallback(() => {
    setNonce((n) => n + 1);
  }, []);
  // Never show data fetched for a different path (stale organization).
  const current = state.path === path;
  return { data: current ? state.data : null, error: current ? state.error : null, reload };
}

export type LiveState = "connecting" | "live" | "revoked";

/**
 * Organization dashboard events over SSE (FR-UI-005). The browser reconnects automatically;
 * every (re)connect and every event triggers a debounced snapshot refresh, because events
 * between connections are not replayed. A revoked stream is closed and not reopened.
 */
export function useOrgEvents(orgPath: string | null, onChange: () => void): LiveState {
  const [state, setState] = useState<LiveState>("connecting");
  useEffect(() => {
    if (!orgPath || typeof EventSource === "undefined") return;
    const source = new EventSource(`${orgPath}/events`);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const refresh = () => {
      clearTimeout(timer);
      timer = setTimeout(onChange, 1000);
    };
    const handlers: Record<string, () => void> = {
      ready: () => {
        setState("live");
        refresh();
      },
      revoked: () => {
        setState("revoked");
        source.close();
      },
    };
    for (const name of [
      "check.recorded",
      "monitor.health",
      "monitor.lifecycle",
      "incident.opened",
      "incident.acknowledged",
      "incident.assigned",
      "incident.unassigned",
      "incident.commented",
      "incident.resolved",
      "notification.delivery",
      "resync",
    ]) {
      handlers[name] = refresh;
    }
    for (const [name, handler] of Object.entries(handlers)) {
      source.addEventListener(name, handler);
    }
    source.onerror = () => {
      setState((current) => (current === "revoked" ? current : "connecting"));
    };
    return () => {
      clearTimeout(timer);
      source.close();
    };
  }, [orgPath, onChange]);
  return state;
}
