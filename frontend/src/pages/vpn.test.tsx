import { fireEvent, screen } from "@testing-library/react";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, FW, READER, renderApp } from "@/test/utils";

const base = {
  tunnel_name: "road-warrior",
  listen_port: null,
  allowed_ips: [] as string[],
  latest_handshake: null,
  rx_bytes: null,
  tx_bytes: null,
  keepalive: null,
  endpoint: null,
};

const body = (verified = true) => ({
  firewall_id: FW.id,
  records: [
    { ...base, interface: "wg0", type: "interface", name: "road-warrior", status: "up", listen_port: 51820 },
    {
      ...base,
      interface: "wg0",
      type: "peer",
      name: "phone",
      status: "online",
      endpoint: "203.0.113.7:40000",
      allowed_ips: ["10.10.0.2/32"],
      latest_handshake: "2026-11-13T10:00:00+00:00",
      rx_bytes: 2048,
      tx_bytes: 5,
    },
    { ...base, interface: "wg0", type: "peer", name: "laptop", status: "offline" },
  ],
  truncated: false,
  registry_verified: verified,
});

function vpn(user: object, data: JsonBodyType = body(), status = 200) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
    http.get(`/api/v1/firewalls/${FW.id}/vpn/wireguard`, () => HttpResponse.json(data, { status })),
  );
}

describe("VPN page", () => {
  it("shows tunnels with their peers and no action buttons", async () => {
    vpn(ADMIN);
    renderApp(<App />, "/vpn");
    expect(await screen.findByText("phone")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.7:40000")).toBeInTheDocument();
    expect(screen.getByText("2.0 KiB")).toBeInTheDocument();
    expect(screen.getByText("online")).toBeInTheDocument();
    expect(screen.getByText("port 51820")).toBeInTheDocument();
    expect(screen.getByText(/Keys are not shown/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /start|stop|restart|add|delete|edit/i })).not.toBeInTheDocument();
  });

  it("filters peers", async () => {
    vpn(ADMIN);
    renderApp(<App />, "/vpn");
    await screen.findByText("phone");
    fireEvent.change(screen.getByLabelText("Filter peers"), { target: { value: "laptop" } });
    expect(screen.queryByText("phone")).not.toBeInTheDocument();
    expect(screen.getByText("laptop")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Filter peers"), { target: { value: "zzz" } });
    expect(screen.getByText("No peers match.")).toBeInTheDocument();
  });

  it("is not reachable for read-only users", async () => {
    vpn(READER);
    renderApp(<App />, "/vpn");
    expect(await screen.findByText("Not permitted")).toBeInTheDocument();
  });

  it("marks an unverified capability", async () => {
    vpn(ADMIN, body(false));
    renderApp(<App />, "/vpn");
    expect(await screen.findByText(/unverified/i)).toBeInTheDocument();
  });

  it("shows an error state when the call fails", async () => {
    vpn(ADMIN, { detail: { status: "unreachable", message: "Firewall is unreachable" } }, 502);
    renderApp(<App />, "/vpn");
    expect(await screen.findByText(/unreachable/i)).toBeInTheDocument();
  });
});
