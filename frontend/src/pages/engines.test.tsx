import { fireEvent, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, FW, renderApp } from "@/test/utils";

const svc = (id: string, running: boolean) => ({
  id,
  name: id,
  description: null,
  running,
  locked: false,
});

function page(services: unknown[]) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(ADMIN)),
    http.get("/api/v1/firewalls/options", () =>
      HttpResponse.json([{ id: FW.id, name: FW.name }]),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/services`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        services,
        truncated: false,
        registry_verified: true,
      }),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/dhcp/leases`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        leases: [],
        truncated: false,
        registry_verified: true,
      }),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/dns`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        stats_available: false,
        totals_available: false,
        registry_verified: true,
      }),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/dnsmasq/domains`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        domains: [],
        registry_verified: true,
      }),
    ),
    http.get("/api/v1/changes", () => HttpResponse.json([])),
  );
}

describe("DHCP and DNS engine tabs", () => {
  it("opens DHCP on the running engine and says what the other is doing", async () => {
    page([svc("dnsmasq", false), svc("kea-dhcp4", true)]);
    renderApp(<App />, "/dhcp");
    expect(
      await screen.findByText("Dnsmasq: stopped · Kea: running"),
    ).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Kea" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(
      screen.getByText(/Viewing and managing Kea.*not available yet/),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Dnsmasq" }));
    expect(
      await screen.findByText(/Dnsmasq is stopped on this firewall/),
    ).toBeInTheDocument();
  });

  it("keeps an unlisted engine visible, since a disabled service is not listed", async () => {
    page([svc("dnsmasq", true)]);
    renderApp(<App />, "/dhcp");
    expect(
      await screen.findByText("Dnsmasq: running · Kea: not running"),
    ).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Kea" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Kea" }));
    expect(
      await screen.findByText(
        /Kea is not running on this firewall/,
      ),
    ).toBeInTheDocument();
  });

  it("offers Unbound and Dnsmasq on DNS, preferring a running Unbound", async () => {
    page([svc("unbound", true), svc("dnsmasq", true)]);
    renderApp(<App />, "/dns");
    expect(
      await screen.findByText("Unbound: running · Dnsmasq: running"),
    ).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Unbound" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    fireEvent.click(screen.getByRole("tab", { name: "Dnsmasq" }));
    expect(await screen.findByText("Domain overrides")).toBeInTheDocument();
  });

  it("warns that a stopped engine's changes have no effect", async () => {
    page([svc("unbound", false), svc("dnsmasq", true)]);
    renderApp(<App />, "/dns");
    expect(
      await screen.findByText("Unbound: stopped · Dnsmasq: running"),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Unbound" }));
    expect(
      await screen.findByText(/Unbound is stopped on this firewall/),
    ).toBeInTheDocument();
  });
});
