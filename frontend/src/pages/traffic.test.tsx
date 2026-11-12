import { screen } from "@testing-library/react";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, FW, READER, renderApp } from "@/test/utils";

const sample = (verified = true) => ({
  firewall_id: FW.id,
  time: 1762950000.5,
  interfaces: [
    { interface: "wan", name: "WAN", in_bytes: 1000, out_bytes: 2000, in_packets: 10, out_packets: 20 },
    { interface: "lan", name: null, in_bytes: 5, out_bytes: 6, in_packets: 1, out_packets: 1 },
  ],
  registry_verified: verified,
});

function traffic(user: object, body: JsonBodyType = sample(), status = 200) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
    http.get(`/api/v1/firewalls/${FW.id}/traffic`, () => HttpResponse.json(body, { status })),
  );
}

describe("Traffic page", () => {
  it("lists every interface and waits for a second sample before showing a rate", async () => {
    traffic(ADMIN);
    renderApp(<App />, "/traffic");
    expect(await screen.findByRole("heading", { name: "WAN" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "WAN" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "lan" })).toBeInTheDocument();
    expect(screen.getAllByText("…").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Collecting samples…")).toHaveLength(2);
  });

  it("marks an unverified capability", async () => {
    traffic(ADMIN, sample(false));
    renderApp(<App />, "/traffic");
    expect(await screen.findByRole("cell", { name: "WAN" })).toBeInTheDocument();
    expect(screen.getByText(/unverified/i)).toBeInTheDocument();
  });

  it("shows an error state when the firewall call fails", async () => {
    traffic(ADMIN, { detail: { status: "unreachable", message: "Firewall is unreachable" } }, 502);
    renderApp(<App />, "/traffic");
    expect(await screen.findByText(/unreachable/i)).toBeInTheDocument();
  });

  it("is not reachable for read-only users", async () => {
    traffic(READER);
    renderApp(<App />, "/traffic");
    expect(await screen.findByText("Not permitted")).toBeInTheDocument();
    expect(screen.queryByText("Interface traffic")).not.toBeInTheDocument();
  });
});
