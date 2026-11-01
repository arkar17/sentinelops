import { afterEach, describe, expect, it } from "vitest";
import { ApiError, apiRequest, readCsrfToken } from "./api.ts";
import { mockApi } from "./test-utils.ts";

afterEach(() => {
  document.cookie = "sentinelops_csrf=; max-age=0";
});

describe("readCsrfToken", () => {
  it("reads the dev and __Host- cookie names", () => {
    expect(readCsrfToken("a=1; sentinelops_csrf=abc")).toBe("abc");
    expect(readCsrfToken("__Host-sentinelops_csrf=xyz")).toBe("xyz");
    expect(readCsrfToken("other=1")).toBeUndefined();
  });
});

describe("apiRequest", () => {
  it("sends the CSRF token on unsafe methods only", async () => {
    document.cookie = "sentinelops_csrf=token-123";
    const calls = mockApi([
      { method: "POST", path: "/api/auth/logout", status: 204 },
      { path: "/api/auth/me", body: { id: "1" } },
    ]);
    await apiRequest("POST", "/api/auth/logout");
    await apiRequest("GET", "/api/auth/me");
    const [post, get] = calls;
    expect((post?.init.headers as Record<string, string>)["X-CSRF-Token"]).toBe("token-123");
    expect((get?.init.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
    expect(post?.init.credentials).toBe("same-origin");
  });

  it("raises ApiError with the server's code and message", async () => {
    mockApi([
      {
        method: "POST",
        path: "/api/auth/login",
        status: 401,
        body: { error: { code: "INVALID_CREDENTIALS", message: "Invalid email or password" } },
      },
    ]);
    const error = await apiRequest("POST", "/api/auth/login", {}).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe("INVALID_CREDENTIALS");
    expect((error as ApiError).status).toBe(401);
  });
});
