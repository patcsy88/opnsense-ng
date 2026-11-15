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
    http.get(`/api/v1/firewalls/${FW.id}/kea/leases`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        leases: [
          {
            address: "192.168.1.50",
            hostname: "laptop",
            interface: null,
            state: null,
            expires: null,
          },
        ],
        truncated: false,
        registry_verified: false,
      }),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/kea/reservations`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        reservations: [
          {
            uuid: "u1",
            subnet: null,
            ip_address: "192.168.1.10",
            hw_address: "aa:bb:cc:dd:ee:01",
            hostname: "printer",
            description: null,
          },
        ],
        truncated: false,
        registry_verified: false,
      }),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/kea/subnets`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        subnets: [
          {
            uuid: "s1",
            subnet: "192.168.1.0/24",
            pools: ["192.168.1.100-192.168.1.200"],
            description: null,
          },
        ],
        truncated: false,
        registry_verified: false,
      }),
    ),
  );
}

describe("DHCP and DNS engine tabs", () => {
  it("opens DHCP on the running engine and says what the other is doing", async () => {
    page([svc("dnsmasq", false), svc("kea-dhcp/v4", true)]);
    renderApp(<App />, "/dhcp");
    expect(
      await screen.findByText("Dnsmasq: stopped · Kea: running"),
    ).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Kea" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(
      await screen.findByRole("tab", { name: "Reservations" }),
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
    expect(await screen.findByText(/Kea is not running/)).toBeInTheDocument();
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

  it("shows Kea leases, reservations and subnets, flagged unverified", async () => {
    page([svc("kea-dhcp/v4", true)]);
    renderApp(<App />, "/dhcp");
    expect(await screen.findByText("192.168.1.50")).toBeInTheDocument();
    expect(screen.getByText(/unverified/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Reservations" }));
    expect(await screen.findByText("aa:bb:cc:dd:ee:01")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Subnets" }));
    expect(await screen.findByText("192.168.1.0/24")).toBeInTheDocument();
  });
});
