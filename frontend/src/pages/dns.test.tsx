import { screen } from "@testing-library/react";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, FW, READER, renderApp } from "@/test/utils";

const body = (over: object = {}) => ({
  firewall_id: FW.id,
  stats_available: true,
  totals_available: true,
  queries: 2000,
  cache_hits: 1500,
  cache_misses: 500,
  hit_rate: 75,
  uptime_seconds: 90000,
  logged_queries: 1800,
  blocked: 100,
  blocked_percent: 5.6,
  blocklist_size: 5000,
  top_queried: [{ domain: "b.example", count: 90, blocklist: null }],
  top_blocked: [{ domain: "ads.example", count: 10, blocklist: "oisd" }],
  registry_verified: true,
  ...over,
});

function dns(user: object, data: JsonBodyType = body(), status = 200) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
    http.get(`/api/v1/firewalls/${FW.id}/dns`, () => HttpResponse.json(data, { status })),
  );
}

describe("DNS page", () => {
  it("shows counters and top domains without actions", async () => {
    dns(ADMIN);
    renderApp(<App />, "/dns");
    expect(await screen.findByText("b.example")).toBeInTheDocument();
    expect(screen.getByText("75%")).toBeInTheDocument();
    expect(screen.getByText("1d 1h")).toBeInTheDocument();
    expect(screen.getByText("ads.example")).toBeInTheDocument();
    expect(screen.getByText("oisd")).toBeInTheDocument();
    expect(screen.getByText(/Per-client queries are not shown/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /reset|restart|stop|start|edit|add/i })).not.toBeInTheDocument();
  });

  it("explains missing statistics instead of showing zeros", async () => {
    dns(
      ADMIN,
      body({
        totals_available: false,
        logged_queries: null,
        blocked: null,
        top_queried: [],
        top_blocked: [],
      }),
    );
    renderApp(<App />, "/dns");
    expect(await screen.findByText(/Extended Statistics/)).toBeInTheDocument();
    expect(screen.getByText("75%")).toBeInTheDocument();
    expect(screen.queryByText("Top queried domains")).not.toBeInTheDocument();
  });

  it("explains when resolver counters are unavailable", async () => {
    dns(ADMIN, body({ stats_available: false, queries: null, hit_rate: null, uptime_seconds: null }));
    renderApp(<App />, "/dns");
    expect(await screen.findByText(/Resolver counters are not available/)).toBeInTheDocument();
  });

  it("is not reachable for read-only users", async () => {
    dns(READER);
    renderApp(<App />, "/dns");
    expect(await screen.findByText("Not permitted")).toBeInTheDocument();
  });

  it("marks an unverified capability", async () => {
    dns(ADMIN, body({ registry_verified: false }));
    renderApp(<App />, "/dns");
    expect(await screen.findByText(/unverified/i)).toBeInTheDocument();
  });

  it("shows an error state when the call fails", async () => {
    dns(ADMIN, { detail: { status: "unreachable", message: "Firewall is unreachable" } }, 502);
    renderApp(<App />, "/dns");
    expect(await screen.findByText(/unreachable/i)).toBeInTheDocument();
  });
});
