import { vi } from "vitest";

export interface MockRoute {
  method?: string;
  path: string;
  status?: number;
  body?: unknown;
}

/** Installs a fetch mock that answers by method+path and records every call. */
export function mockApi(routes: MockRoute[]) {
  const calls: { method: string; path: string; init: RequestInit }[] = [];
  const fetchMock = vi.fn((input: RequestInfo | URL, init: RequestInit = {}) => {
    const path = typeof input === "string" ? input : input.toString();
    const method = init.method ?? "GET";
    calls.push({ method, path, init });
    const route = routes.find((r) => r.path === path && (r.method ?? "GET") === method);
    const status = route?.status ?? (route ? 200 : 404);
    const body =
      route?.body ?? (route ? {} : { error: { code: "NOT_FOUND", message: "Not Found" } });
    return Promise.resolve(
      status === 204
        ? new Response(null, { status })
        : new Response(JSON.stringify(body), {
            status,
            headers: { "Content-Type": "application/json" },
          }),
    );
  });
  vi.stubGlobal("fetch", fetchMock);
  return calls;
}
