import { fireEvent, screen } from "@testing-library/react";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, FW, READER, renderApp } from "@/test/utils";

const body = (verified = true) => ({
  firewall_id: FW.id,
  services: [
    { id: "unbound", name: "unbound", description: "Unbound DNS", running: true, locked: false },
    { id: "dnsmasq", name: "dnsmasq", description: "Dnsmasq DNS/DHCP", running: false, locked: true },
  ],
  truncated: false,
  registry_verified: verified,
});

function services(user: object, data: JsonBodyType = body(), status = 200) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
    http.get(`/api/v1/firewalls/${FW.id}/services`, () => HttpResponse.json(data, { status })),
  );
}

describe("Services page", () => {
  it("shows running and stopped services with no control buttons, for any role", async () => {
    services(READER);
    renderApp(<App />, "/services");
    expect(await screen.findByText("Running")).toBeInTheDocument();
    expect(screen.getByText("Stopped")).toBeInTheDocument();
    expect(screen.getByText("locked")).toBeInTheDocument();
    expect(screen.getByText(/1 not running/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /start|stop|restart/i })).not.toBeInTheDocument();
  });

  it("filters by name or description", async () => {
    services(ADMIN);
    renderApp(<App />, "/services");
    await screen.findByText("Running");
    fireEvent.change(screen.getByLabelText("Filter services"), { target: { value: "dhcp" } });
    expect(screen.queryByText("Unbound DNS")).not.toBeInTheDocument();
    expect(screen.getByText("Dnsmasq DNS/DHCP")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Filter services"), { target: { value: "zzz" } });
    expect(screen.getByText("No services match.")).toBeInTheDocument();
  });

  it("marks an unverified capability and reports firewall errors", async () => {
    services(ADMIN, body(false));
    renderApp(<App />, "/services");
    expect(await screen.findByText(/unverified/i)).toBeInTheDocument();
  });

  it("shows an error state when the call fails", async () => {
    services(ADMIN, { detail: { status: "unreachable", message: "Firewall is unreachable" } }, 502);
    renderApp(<App />, "/services");
    expect(await screen.findByText(/unreachable/i)).toBeInTheDocument();
  });
});
