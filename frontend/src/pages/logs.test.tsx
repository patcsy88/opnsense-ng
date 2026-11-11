import { fireEvent, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, FW, READER, renderApp } from "@/test/utils";

const entry = (over: Record<string, unknown> = {}) => ({
  time: "2026-11-12T10:00:00",
  action: "block",
  interface: "igb0",
  direction: "in",
  ip_version: 4,
  protocol: "tcp",
  source: "203.0.113.9",
  source_port: 51515,
  destination: "10.0.0.5",
  destination_port: 23,
  rule: "Default deny",
  reason: "match",
  ...over,
});

function logs(user: object, entries: unknown[]) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
    http.get(`/api/v1/firewalls/${FW.id}/firewall/logs`, () =>
      HttpResponse.json({ firewall_id: FW.id, entries, truncated: false, registry_verified: false }),
    ),
  );
}

describe("Logs page", () => {
  it("lists entries and filters by action and text", async () => {
    logs(ADMIN, [entry(), entry({ action: "pass", source: "10.0.0.9", destination_port: 443 })]);
    renderApp(<App />, "/logs");
    expect(await screen.findByText("203.0.113.9:51515")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.9:51515")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Blocked" }));
    expect(screen.queryByText("10.0.0.9:51515")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "All" }));
    fireEvent.change(screen.getByLabelText("Filter entries"), { target: { value: "443" } });
    expect(screen.queryByText("203.0.113.9:51515")).not.toBeInTheDocument();
    expect(screen.getByText("10.0.0.9:51515")).toBeInTheDocument();
  });

  it("shows an empty state", async () => {
    logs(ADMIN, []);
    renderApp(<App />, "/logs");
    expect(await screen.findByText(/no log entries/i)).toBeInTheDocument();
  });

  it("is not available to read_only: no nav link and the route refuses", async () => {
    logs(READER, [entry()]);
    renderApp(<App />, "/logs");
    expect(await screen.findByText("Not permitted")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Logs" })).not.toBeInTheDocument();
    expect(screen.queryByText("203.0.113.9:51515")).not.toBeInTheDocument();
  });

  it("shows the Logs link to admins", async () => {
    logs(ADMIN, []);
    renderApp(<App />, "/logs");
    expect((await screen.findAllByRole("link", { name: "Logs" })).length).toBeGreaterThan(0);
  });
});
