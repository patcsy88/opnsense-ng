import { fireEvent, screen } from "@testing-library/react";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, FW, READER, renderApp } from "@/test/utils";

const body = (verified = true) => ({
  firewall_id: FW.id,
  leases: [
    {
      address: "192.168.1.50",
      ip_version: 4,
      hostname: "laptop",
      interface: "LAN",
      lease_type: "dynamic",
      vendor: "Apple, Inc.",
      expires: "2026-11-12T10:00:00+00:00",
    },
    {
      address: "fd00::5",
      ip_version: 6,
      hostname: null,
      interface: "LAN",
      lease_type: "static",
      vendor: null,
      expires: null,
    },
  ],
  truncated: false,
  registry_verified: verified,
});

function dhcp(user: object, data: JsonBodyType = body(), status = 200) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
    http.get(`/api/v1/firewalls/${FW.id}/dhcp/leases`, () => HttpResponse.json(data, { status })),
  );
}

describe("DHCP page", () => {
  it("lists leases without MAC addresses or action buttons", async () => {
    dhcp(ADMIN);
    renderApp(<App />, "/dhcp");
    expect(await screen.findByText("192.168.1.50")).toBeInTheDocument();
    expect(screen.getByText("laptop")).toBeInTheDocument();
    expect(screen.getByText("Apple, Inc.")).toBeInTheDocument();
    expect(screen.getByText("No expiry")).toBeInTheDocument();
    expect(screen.getByText(/MAC addresses are not shown/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /delete|release|add|edit/i })).not.toBeInTheDocument();
  });

  it("filters by hostname, address or vendor", async () => {
    dhcp(ADMIN);
    renderApp(<App />, "/dhcp");
    await screen.findByText("192.168.1.50");
    fireEvent.change(screen.getByLabelText("Filter leases"), { target: { value: "apple" } });
    expect(screen.queryByText("fd00::5")).not.toBeInTheDocument();
    expect(screen.getByText("192.168.1.50")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Filter leases"), { target: { value: "zzz" } });
    expect(screen.getByText("No leases match.")).toBeInTheDocument();
  });

  it("is not reachable for read-only users", async () => {
    dhcp(READER);
    renderApp(<App />, "/dhcp");
    expect(await screen.findByText("Not permitted")).toBeInTheDocument();
    expect(screen.queryByText("DHCP leases")).not.toBeInTheDocument();
  });

  it("marks an unverified capability and shows an error state on failure", async () => {
    dhcp(ADMIN, body(false));
    renderApp(<App />, "/dhcp");
    expect(await screen.findByText(/unverified/i)).toBeInTheDocument();
  });

  it("shows an error state when the call fails", async () => {
    dhcp(ADMIN, { detail: { status: "unreachable", message: "Firewall is unreachable" } }, 502);
    renderApp(<App />, "/dhcp");
    expect(await screen.findByText(/unreachable/i)).toBeInTheDocument();
  });
});
