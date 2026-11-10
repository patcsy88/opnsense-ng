import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";
import { server } from "@/test/server";
import { ADMIN, FW } from "@/test/utils";
import { api, ApiError, readCsrfToken, request, setUnauthorizedHandler } from "./api";

describe("api client", () => {
  it("reads the csrf cookie (plain and __Host- names)", () => {
    expect(readCsrfToken("a=1; csrf_token=abc%20d")).toBe("abc d");
    expect(readCsrfToken("__Host-csrf_token=zzz; x=y")).toBe("zzz");
    expect(readCsrfToken("session=1")).toBeNull();
  });

  it("sends X-CSRF-Token on mutating requests only", async () => {
    document.cookie = "csrf_token=tok123; path=/";
    const seen: Record<string, string | null> = {};
    server.use(
      http.post("/api/v1/auth/logout", ({ request: r }) => {
        seen.post = r.headers.get("x-csrf-token");
        return new HttpResponse(null, { status: 204 });
      }),
      http.patch("/api/v1/firewalls/:id", ({ request: r }) => {
        seen.patch = r.headers.get("x-csrf-token");
        return HttpResponse.json(FW);
      }),
      http.get("/api/v1/auth/me", ({ request: r }) => {
        seen.get = r.headers.get("x-csrf-token");
        return HttpResponse.json(ADMIN);
      }),
    );
    await api.logout();
    await api.updateFirewall(FW.id, { name: "x" });
    await api.me();
    expect(seen.post).toBe("tok123");
    expect(seen.patch).toBe("tok123");
    expect(seen.get).toBeNull();
  });

  it("sends login as JSON", async () => {
    let ct: string | null = null;
    let body: unknown;
    server.use(
      http.post("/api/v1/auth/login", async ({ request: r }) => {
        ct = r.headers.get("content-type");
        body = await r.json();
        return HttpResponse.json({ user: ADMIN, csrf_token: "t" });
      }),
    );
    const res = await api.login("alice", "pw");
    expect(ct).toBe("application/json");
    expect(body).toEqual({ username: "alice", password: "pw" });
    expect(res.user.role).toBe("admin");
  });

  it.each([
    [401, "unauthorized"],
    [403, "forbidden"],
    [415, "unsupported_media"],
    [404, "not_found"],
    [409, "conflict"],
    [422, "validation"],
    [500, "server"],
  ])("maps status %i to %s", async (status, kind) => {
    server.use(http.get("/api/v1/firewalls", () => HttpResponse.json({ detail: "nope" }, { status })));
    await expect(api.listFirewalls()).rejects.toMatchObject({ kind, status, message: "nope" });
  });

  it("maps 429 with Retry-After", async () => {
    server.use(
      http.post("/api/v1/auth/login", () =>
        HttpResponse.json({ detail: "slow" }, { status: 429, headers: { "Retry-After": "42" } }),
      ),
    );
    await expect(api.login("a", "b")).rejects.toMatchObject({ kind: "rate_limited", retryAfterSeconds: 42 });
  });

  it("maps network failure", async () => {
    server.use(http.get("/api/v1/auth/me", () => HttpResponse.error()));
    await expect(api.me()).rejects.toMatchObject({ kind: "network" });
  });

  it("rejects responses that do not match the schema", async () => {
    server.use(http.get("/api/v1/auth/me", () => HttpResponse.json({ nope: 1 })));
    await expect(api.me()).rejects.toMatchObject({ kind: "schema" });
  });

  it("extracts {status,message} detail objects", async () => {
    server.use(
      http.get("/api/v1/firewalls/:id/system/status", () =>
        HttpResponse.json({ detail: { status: "timeout", message: "timed out" } }, { status: 504 }),
      ),
    );
    await expect(api.systemStatus(FW.id)).rejects.toMatchObject({ message: "timed out" });
  });

  it("calls the unauthorized handler on 401 except for auth bootstrap", async () => {
    const fn = vi.fn();
    setUnauthorizedHandler(fn);
    server.use(
      http.get("/api/v1/firewalls", () => new HttpResponse(null, { status: 401 })),
      http.get("/api/v1/auth/me", () => new HttpResponse(null, { status: 401 })),
    );
    await expect(api.me()).rejects.toBeInstanceOf(ApiError);
    expect(fn).not.toHaveBeenCalled();
    await expect(api.listFirewalls()).rejects.toBeInstanceOf(ApiError);
    expect(fn).toHaveBeenCalledTimes(1);
    setUnauthorizedHandler(null);
  });

  it("refuses non-/api paths", async () => {
    await expect(request("GET", "https://evil.example/x")).rejects.toThrow();
  });
});
