import { fireEvent, screen, waitFor } from "@testing-library/react";
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

const SUMMARY = {
  records: 40,
  blocked: 12,
  passed: 28,
  newest: "2026-11-12T10:00:00",
  oldest: "2026-11-12T09:00:00",
  top_blocked_sources: [{ label: "203.0.113.9", count: 7 }],
  top_blocked_destinations: [{ label: "10.0.0.5", count: 9 }],
  top_blocked_ports: [{ label: "23/tcp", count: 6 }],
  blocked_by_interface: [{ label: "igb0", count: 12 }],
  blocked_by_rule: [{ label: "Default deny", count: 12 }],
};

function logs(user: object, entries: unknown[], summary = SUMMARY) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
    http.get(`/api/v1/firewalls/${FW.id}/firewall/logs`, () =>
      HttpResponse.json({ firewall_id: FW.id, entries, summary, cursor: "a".repeat(32), truncated: false, registry_verified: false }),
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

  it("shows the blocked-traffic summary", async () => {
    logs(ADMIN, [entry()]);
    renderApp(<App />, "/logs");
    expect(await screen.findByText("Blocked traffic")).toBeInTheDocument();
    expect(screen.getByText(/12\s+blocked, 28 passed/)).toBeInTheDocument();
    expect(screen.getByText("Top blocked ports")).toBeInTheDocument();
    expect(screen.getByText("23/tcp")).toBeInTheDocument();
  });

  it("says so when nothing was blocked", async () => {
    logs(ADMIN, [entry({ action: "pass" })], { ...SUMMARY, blocked: 0, passed: 40 });
    renderApp(<App />, "/logs");
    expect(await screen.findByText(/no blocked traffic in these records/i)).toBeInTheDocument();
  });

  it("live mode merges new entries and sends the cursor", async () => {
    logs(ADMIN, [entry()]);
    let since = "";
    server.use(
      http.get(`/api/v1/firewalls/${FW.id}/firewall/logs/new`, ({ request }) => {
        since = new URL(request.url).searchParams.get("since") ?? "";
        return HttpResponse.json({
          firewall_id: FW.id,
          entries: [entry({ source: "198.51.100.77" })],
          cursor: "b".repeat(32),
          truncated: false,
        });
      }),
    );
    renderApp(<App />, "/logs");
    await screen.findByText("203.0.113.9:51515");
    const btn = await screen.findByRole("button", { name: "Live" });
    await waitFor(() => expect(btn).toBeEnabled());
    fireEvent.click(btn);
    expect(await screen.findByText("198.51.100.77:51515")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.9:51515")).toBeInTheDocument();
    expect(since).toBe("a".repeat(32));
  });
});
