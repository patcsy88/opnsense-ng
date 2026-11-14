import { fireEvent, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, FW, READER, renderApp } from "@/test/utils";

const DOWN_ID = "6f1c2a52-8a8f-4a39-9d0e-3b1f0c1d2e3f";

const entry = (over: object = {}) => ({
  id: FW.id,
  name: FW.name,
  reachable: true,
  status: "ok",
  message: "Connected",
  hostname: "alpha",
  version: "OPNsense 26.7",
  uptime: "3 days",
  cpu_used_percent: 12,
  memory_used_percent: 25,
  disk_used_percent: null,
  checked_at: 1,
  ...over,
});

function overview(user: object, firewalls: object[], truncated = false) {
  let calls = 0;
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/overview", () => {
      calls += 1;
      return HttpResponse.json({ firewalls, truncated });
    }),
  );
  return () => calls;
}

describe("Overview page", () => {
  it("shows reachable and unreachable firewalls with admin detail", async () => {
    overview(ADMIN, [
      entry(),
      entry({
        id: DOWN_ID,
        name: "backup",
        reachable: false,
        status: "timeout",
        message: "No answer within the time limit",
        hostname: null,
        version: null,
        uptime: null,
        cpu_used_percent: null,
        memory_used_percent: null,
      }),
    ]);
    renderApp(<App />, "/overview");
    expect(await screen.findByText("alpha")).toBeInTheDocument();
    expect(screen.getByText("25%")).toBeInTheDocument();
    expect(screen.getByText("Unreachable")).toBeInTheDocument();
    expect(screen.getByText(/timeout: No answer/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: FW.name })).toHaveAttribute(
      "href",
      `/?fw=${FW.id}`,
    );
  });

  it("is open to read-only users and shows no detail", async () => {
    overview(READER, [
      entry({
        id: DOWN_ID,
        name: "backup",
        reachable: false,
        status: "unreachable",
        message: "Firewall is unreachable",
      }),
    ]);
    renderApp(<App />, "/overview");
    expect(await screen.findByText("Unreachable")).toBeInTheDocument();
    expect(screen.queryByText(/unreachable: /)).not.toBeInTheDocument();
  });

  it("refreshes on demand and shows the truncated notice", async () => {
    const calls = overview(ADMIN, [entry()], true);
    renderApp(<App />, "/overview");
    await screen.findByText("alpha");
    expect(screen.getByText(/limited to 50/)).toBeInTheDocument();
    const before = calls();
    fireEvent.click(screen.getByRole("button", { name: "Refresh now" }));
    await screen.findByText("alpha");
    expect(calls()).toBeGreaterThan(before);
  });

  it("says so when there are no firewalls", async () => {
    overview(ADMIN, []);
    renderApp(<App />, "/overview");
    expect(
      await screen.findByText("No firewalls configured."),
    ).toBeInTheDocument();
  });
});
