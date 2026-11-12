import { fireEvent, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "./App";
import { server } from "@/test/server";
import { ADMIN, FW, READER, renderApp } from "@/test/utils";

const okStatus = {
  firewall_id: FW.id,
  status: { hostname: "fw.lan", versions: ["OPNsense 26.1"], updates: null, server_time: null,
    uptime: "3 days",
    load_average: "0.10, 0.20, 0.30",
    memory_total_bytes: 8589934592,
    memory_used_bytes: 2147483648,
    memory_used_percent: 25,
    cpu_used_percent: 37.5,
    disk_total_bytes: 21474836480,
    disk_used_bytes: 5368709120,
    disk_used_percent: 25,
  },
  registry_verified: false,
};

function mockSession(user: typeof ADMIN | typeof READER | null) {
  server.use(
    http.get("/api/v1/auth/me", () =>
      user ? HttpResponse.json(user) : HttpResponse.json({ detail: "Not authenticated" }, { status: 401 }),
    ),
  );
}

describe("auth flow", () => {
  it("redirects to login on 401 bootstrap", async () => {
    mockSession(null);
    renderApp(<App />, "/administration");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("logs in then shows the dashboard", async () => {
    mockSession(null);
    server.use(
      http.post("/api/v1/auth/login", () => HttpResponse.json({ user: ADMIN, csrf_token: "t" })),
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([])),
    );
    renderApp(<App />, "/");
    fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
  });

  it("shows invalid credentials and clears the password field", async () => {
    mockSession(null);
    server.use(
      http.post("/api/v1/auth/login", () =>
        HttpResponse.json({ detail: "Invalid username or password" }, { status: 401 }),
      ),
    );
    renderApp(<App />, "/login");
    fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "bad" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid username or password");
    expect(screen.getByLabelText("Password")).toHaveValue("");
  });

  it("shows a Retry-After message on 429", async () => {
    mockSession(null);
    server.use(
      http.post("/api/v1/auth/login", () =>
        HttpResponse.json({ detail: "x" }, { status: 429, headers: { "Retry-After": "30" } }),
      ),
    );
    renderApp(<App />, "/login");
    fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "a" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "b" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Try again in 30 seconds");
  });

  it("shows a retry state when the server is unreachable at bootstrap", async () => {
    server.use(http.get("/api/v1/auth/me", () => HttpResponse.error()));
    renderApp(<App />, "/");
    expect(await screen.findByText("Server unreachable")).toBeInTheDocument();
    mockSession(ADMIN);
    server.use(http.get("/api/v1/firewalls/options", () => HttpResponse.json([])));
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
  });

  it("returns to login when a later request gets 401", async () => {
    mockSession(ADMIN);
    server.use(http.get("/api/v1/firewalls/options", () => new HttpResponse(null, { status: 401 })));
    renderApp(<App />, "/");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });
});

describe("role-based rendering", () => {
  it("admin sees the connections link and detailed connectivity", async () => {
    mockSession(ADMIN);
    server.use(
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
      http.get("/api/v1/firewalls/:id/connectivity", () =>
        HttpResponse.json({ firewall_id: FW.id, ok: false, status: "tls_error", message: "bad cert", registry_verified: true }),
      ),
      http.get("/api/v1/firewalls/:id/system/status", () => HttpResponse.json(okStatus)),
    );
    renderApp(<App />, "/");
    expect(await screen.findByText("tls_error")).toBeInTheDocument();
    expect(await screen.findByText("fw.lan")).toBeInTheDocument();
    expect(await screen.findByText("Unverified API mapping")).toBeInTheDocument();
    expect(await screen.findByText("2048 MB of 8192 MB (25%)")).toBeInTheDocument();
    expect(await screen.findByText("0.10, 0.20, 0.30")).toBeInTheDocument();
    expect(await screen.findByText("37.5%")).toBeInTheDocument();
    expect(await screen.findByText("5.0 GB of 20.0 GB (25%)")).toBeInTheDocument();
  });

  it("read-only user picks a firewall from the options list and never calls the detailed list", async () => {
    mockSession(READER);
    let detailedListCalled = false;
    server.use(
      http.get("/api/v1/firewalls", () => {
        detailedListCalled = true;
        return HttpResponse.json([]);
      }),
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: "edge-1" }])),
      http.get("/api/v1/firewalls/:id/connectivity", () =>
        HttpResponse.json({ firewall_id: FW.id, ok: false, status: "unreachable", message: "Firewall is unreachable", registry_verified: true }),
      ),
      http.get("/api/v1/firewalls/:id/system/status", () => HttpResponse.json(okStatus)),
    );
    renderApp(<App />, "/");
    expect(await screen.findByText("Firewall is unreachable")).toBeInTheDocument();
    expect(await screen.findByRole("option", { name: "edge-1" })).toBeInTheDocument();
    expect(screen.queryByText("tls_error")).not.toBeInTheDocument();
    expect(detailedListCalled).toBe(false);
  });

  it("read-only user is blocked from the connections page", async () => {
    mockSession(READER);
    renderApp(<App />, "/administration/firewalls");
    expect(await screen.findByText("Not permitted")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /add firewall/i })).not.toBeInTheDocument();
  });

  it("network page lists interfaces for a read-only user", async () => {
    mockSession(READER);
    server.use(
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: "edge-1" }])),
      http.get("/api/v1/firewalls/:id/interfaces", () =>
        HttpResponse.json({
          firewall_id: FW.id,
          registry_verified: false,
          interfaces: [
            { identifier: "wan", description: "WAN", device: "vtnet0", status: "up", enabled: true, link_type: "dhcp", ipv4: ["10.0.0.2/24"], ipv6: [], gateways: ["WAN_GW"], vlan_tag: null },
            { identifier: "opt1", description: "Guest", device: "vtnet2", status: "no carrier", enabled: true, link_type: "static", ipv4: [], ipv6: [], gateways: [], vlan_tag: 20 },
            { identifier: null, description: "Unassigned Interface", device: "enc0", status: "down", enabled: null, link_type: null, ipv4: [], ipv6: [], gateways: [], vlan_tag: null },
          ],
        }),
      ),
    );
    renderApp(<App />, "/network");
    expect(await screen.findByText("WAN")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.2/24")).toBeInTheDocument();
    expect(screen.getByText("Up")).toBeInTheDocument();
    expect(screen.getByText("no carrier")).toBeInTheDocument();
    // An enabled interface without carrier is an alarm; an unassigned one that is down is not.
    expect(screen.getByText("no carrier").closest("[class*=text-destructive]")).not.toBeNull();
    expect(screen.getByText("down").closest("[class*=text-destructive]")).toBeNull();
    expect(screen.getByText("Unverified API mapping")).toBeInTheDocument();
  });

  it("firewall page lists rules read-only", async () => {
    mockSession(READER);
    server.use(
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: "edge-1" }])),
      http.get("/api/v1/firewalls/:id/firewall/rules", () =>
        HttpResponse.json({
          firewall_id: FW.id,
          truncated: false,
          registry_verified: false,
          rules: [
            { uuid: "u1", enabled: true, action: "pass", interface: "lan", direction: "in", ip_protocol: "inet", protocol: "TCP", source: "any", source_port: null, destination: "10.0.0.0/8", destination_port: "443", description: "Allow HTTPS", log: false, sequence: 5 },
          ],
        }),
      ),
    );
    renderApp(<App />, "/firewall");
    expect(await screen.findByText("Allow HTTPS")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.0/8:443")).toBeInTheDocument();
    expect(screen.getByText("pass")).toBeInTheDocument();
    expect(screen.getByText("Unverified API mapping")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /delete|add|edit/i })).toBeNull();
  });

  it("firewall page lists aliases read-only", async () => {
    mockSession(READER);
    server.use(
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: "edge-1" }])),
      http.get("/api/v1/firewalls/:id/firewall/rules", () =>
        HttpResponse.json({ firewall_id: FW.id, truncated: false, registry_verified: true, rules: [] }),
      ),
      http.get("/api/v1/firewalls/:id/firewall/aliases", () =>
        HttpResponse.json({
          firewall_id: FW.id,
          truncated: false,
          registry_verified: false,
          aliases: [
            { uuid: "a1", name: "lan_hosts", type: "host", enabled: true, description: "LAN servers", content: ["10.0.0.1", "10.0.0.2"], content_truncated: false },
          ],
        }),
      ),
    );
    renderApp(<App />, "/firewall");
    expect(await screen.findByText("lan_hosts")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.1, 10.0.0.2")).toBeInTheDocument();
    expect(screen.getByText("Unverified API mapping")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /delete|add|edit/i })).toBeNull();
  });
});
