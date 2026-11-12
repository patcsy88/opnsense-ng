import { fireEvent, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { FW, READER, renderApp } from "@/test/utils";

const rule = (over: Record<string, unknown> = {}) => ({
  uuid: "11111111-1111-1111-1111-111111111111",
  enabled: true,
  excluded: false,
  interface: "wan",
  ip_protocol: "inet",
  protocol: "TCP",
  source: "any",
  source_port: null,
  destination: "wanip",
  destination_port: "443",
  target: "10.0.0.5",
  target_port: "8443",
  description: "Web",
  log: false,
  sequence: 1,
  automatic: false,
  ...over,
});

function nat(forwards: unknown[], outbound: unknown[]) {
  const body = (rules: unknown[]) => ({
    firewall_id: FW.id,
    rules,
    truncated: false,
    registry_verified: false,
  });
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(READER)),
    http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
    http.get(`/api/v1/firewalls/${FW.id}/firewall/nat/port-forwards`, () => HttpResponse.json(body(forwards))),
    http.get(`/api/v1/firewalls/${FW.id}/firewall/nat/outbound`, () => HttpResponse.json(body(outbound))),
  );
}

describe("NAT page", () => {
  it("lists port forwards read-only, then switches to outbound", async () => {
    nat([rule()], [rule({ description: "LAN out", target: "wanip", target_port: null, automatic: true })]);
    renderApp(<App />, "/nat");
    expect(await screen.findByText("10.0.0.5:8443")).toBeInTheDocument();
    expect(screen.getByText("wanip:443")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /edit|delete|disable/i })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Outbound" }));
    expect(await screen.findByText("LAN out")).toBeInTheDocument();
    expect(screen.getByText("(automatic)")).toBeInTheDocument();
  });

  it("labels exception rules and handles an empty list", async () => {
    nat([rule({ excluded: true })], []);
    renderApp(<App />, "/nat");
    expect(await screen.findByText("No redirect")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Outbound" }));
    expect(await screen.findByText(/reported no outbound/i)).toBeInTheDocument();
  });

  it("is visible to read-only users in the navigation", async () => {
    nat([], []);
    renderApp(<App />, "/nat");
    expect((await screen.findAllByRole("link", { name: "NAT" })).length).toBeGreaterThan(0);
  });
});
