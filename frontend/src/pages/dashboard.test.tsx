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

const down = (over: object = {}) =>
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
    ...over,
  });

function overview(user: object, firewalls: object[], truncated = false) {
  let calls = 0;
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () =>
      HttpResponse.json(firewalls.map((f) => ({ id: (f as { id: string }).id, name: (f as { name: string }).name }))),
    ),
    http.get("/api/v1/firewalls/overview", () => {
      calls += 1;
      return HttpResponse.json({ firewalls, truncated });
    }),
  );
  return () => calls;
}

describe("Dashboard", () => {
  it("shows one card per firewall, with admin detail for an unreachable one", async () => {
    overview(ADMIN, [entry(), down()]);
    renderApp(<App />, "/");
    expect(await screen.findByText("alpha")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: FW.name })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "backup" })).toBeInTheDocument();
    expect(screen.getByText("25%")).toBeInTheDocument();
    expect(screen.getByText("Reachable")).toBeInTheDocument();
    expect(screen.getByText("Unreachable")).toBeInTheDocument();
    expect(screen.getByText(/timeout: No answer/)).toBeInTheDocument();
  });

  it("is open to read-only users and shows no detail", async () => {
    overview(READER, [down({ status: "unreachable", message: "Firewall is unreachable" })]);
    renderApp(<App />, "/");
    expect(await screen.findByText("Unreachable")).toBeInTheDocument();
    expect(screen.queryByText(/unreachable: /)).not.toBeInTheDocument();
  });

  it("selects a firewall when its card is clicked and stays on the dashboard", async () => {
    overview(ADMIN, [entry(), down()]);
    renderApp(<App />, "/");
    const backup = await screen.findByRole("button", { name: "backup" });
    expect(backup).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(backup);
    expect(screen.getByRole("button", { name: "backup" })).toHaveAttribute("aria-pressed", "true");
    expect(sessionStorage.getItem("selected-firewall")).toBe(DOWN_ID);
    expect(screen.getByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
  });

  it("refreshes on demand and shows the truncated notice", async () => {
    const calls = overview(ADMIN, [entry()], true);
    renderApp(<App />, "/");
    await screen.findByText("alpha");
    expect(screen.getByText(/limited to 50/)).toBeInTheDocument();
    const before = calls();
    fireEvent.click(screen.getByRole("button", { name: "Refresh now" }));
    await screen.findByText("alpha");
    expect(calls()).toBeGreaterThan(before);
  });

  it("says so when there are no firewalls, with a link for admins", async () => {
    overview(ADMIN, []);
    renderApp(<App />, "/");
    expect(await screen.findByText(/No firewalls configured\./)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Add a firewall connection" })).toBeInTheDocument();
  });

  it("tells non-admins to ask an administrator when there are no firewalls", async () => {
    overview(READER, []);
    renderApp(<App />, "/");
    expect(await screen.findByText(/Ask an administrator/)).toBeInTheDocument();
  });

  it("redirects the old /overview address to the dashboard", async () => {
    overview(ADMIN, [entry()]);
    renderApp(<App />, "/overview");
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
  });
});
