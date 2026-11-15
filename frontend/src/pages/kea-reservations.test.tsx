import { fireEvent, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { App } from "@/App";
import {
  ipProblem,
  keaReservationDiff,
} from "@/features/changes/kea-reservation-form";
import { server } from "@/test/server";
import { ADMIN, FW, READER, renderApp } from "@/test/utils";

const NETADMIN = {
  id: "55555555-5555-4555-8555-555555555555",
  username: "carol",
  role: "network_admin",
} as const;
const CID = "66666666-6666-4666-8666-666666666666";
const SUB = "77777777-7777-4777-8777-777777777777";
const RES = "11111111-1111-4111-8111-111111111111";

const reservation = {
  uuid: RES,
  subnet: "192.168.1.0/24",
  subnet_id: SUB,
  ip_address: "192.168.1.10",
  hw_address: "02:00:00:00:00:01",
  hostname: "printer",
  description: null,
};

const change = (over: Record<string, unknown> = {}) => ({
  id: CID,
  firewall_id: FW.id,
  kind: "kea_reservation",
  action: "create",
  target_uuid: null,
  proposed: {
    label: "192.168.1.20",
    subnet: SUB,
    ip_address: "192.168.1.20",
    hw_address: "02:00:00:00:00:02",
    hostname: "bob",
    description: null,
    risk: [],
  },
  base_snapshot: null,
  status: "validated",
  high_risk: false,
  self_approved: false,
  requester_username: "carol",
  reviewer_username: null,
  applier_username: null,
  failure_message: null,
  created_at: "2026-11-15T10:00:00Z",
  updated_at: "2026-11-15T10:00:00Z",
  events: [],
  ...over,
});

const svc = (id: string, running: boolean) => ({
  id,
  name: id,
  description: null,
  running,
  locked: false,
});

function page(user: object, open: unknown[] = []) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () =>
      HttpResponse.json([{ id: FW.id, name: FW.name }]),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/services`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        services: [svc("kea-dhcp/v4", true)],
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
    http.get(`/api/v1/firewalls/${FW.id}/kea/leases`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        leases: [],
        truncated: false,
        registry_verified: false,
      }),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/kea/reservations`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        reservations: [reservation],
        truncated: false,
        registry_verified: true,
      }),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/kea/subnets`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        subnets: [
          {
            uuid: SUB,
            subnet: "192.168.1.0/24",
            pools: ["192.168.1.100-192.168.1.199"],
            description: null,
          },
        ],
        truncated: false,
        registry_verified: true,
      }),
    ),
    http.get("/api/v1/changes", () => HttpResponse.json(open)),
    http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(change())),
  );
}

async function openReservations() {
  await screen.findByText(/Kea: running/);
  fireEvent.click(await screen.findByRole("tab", { name: "Reservations" }));
}

beforeEach(() => {
  document.cookie = "csrf_token=tok; path=/";
});

describe("Kea reservation helpers", () => {
  const subnet = {
    uuid: SUB,
    subnet: "192.168.1.0/24",
    pools: ["192.168.1.100-192.168.1.199"],
    description: null,
  };

  it("accepts an address outside the pools and refuses the others", () => {
    expect(ipProblem("192.168.1.20", subnet)).toBeNull();
    expect(ipProblem("192.168.1.150", subnet)).toMatch(/dynamic pool/);
    expect(ipProblem("10.0.0.5", subnet)).toMatch(/outside the subnet/);
    expect(ipProblem("999.1.1.1", subnet)).toMatch(/valid IPv4/);
  });

  it("lists only the changed fields", () => {
    const before = {
      subnet: SUB,
      ip_address: "192.168.1.10",
      hw_address: "02:00:00:00:00:01",
      hostname: "printer",
      description: null,
    };
    expect(
      keaReservationDiff(before, {
        ...before,
        hw_address: "02:00:00:00:00:09",
      }),
    ).toEqual([["MAC address", "02:00:00:00:00:01", "02:00:00:00:00:09"]]);
    expect(keaReservationDiff(before, before)).toEqual([]);
  });
});

describe("Kea reservations", () => {
  it("lists reservations and open requests of this kind only", async () => {
    page(NETADMIN, [
      change(),
      change({
        id: "88888888-8888-4888-8888-888888888888",
        kind: "dnsmasq_host",
      }),
    ]);
    renderApp(<App />, "/dhcp");
    await openReservations();
    expect(await screen.findByText("printer")).toBeInTheDocument();
    expect(await screen.findAllByText(/create 192\.168\.1\.20/)).toHaveLength(
      1,
    );
  });

  it("creates a request with the entered fields and opens it", async () => {
    page(NETADMIN);
    let body: unknown = null;
    server.use(
      http.post("/api/v1/changes/kea-reservations", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(change(), { status: 201 });
      }),
    );
    renderApp(<App />, "/dhcp");
    await openReservations();
    const add = await screen.findByRole("button", { name: "New reservation" });
    await waitFor(() => expect(add).toBeEnabled());
    fireEvent.click(add);
    fireEvent.change(await screen.findByLabelText("IP address"), {
      target: { value: "192.168.1.20" },
    });
    fireEvent.change(screen.getByLabelText("MAC address"), {
      target: { value: "02-00-00-00-00-02" },
    });
    fireEvent.change(screen.getByLabelText("Hostname (optional)"), {
      target: { value: "Bob" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toEqual({
      firewall_id: FW.id,
      reservation: {
        subnet: SUB,
        ip_address: "192.168.1.20",
        hw_address: "02:00:00:00:00:02",
        hostname: "bob",
        description: null,
      },
    });
  });

  it("refuses an address inside a pool before sending", async () => {
    page(NETADMIN);
    let sent = false;
    server.use(
      http.post("/api/v1/changes/kea-reservations", () => {
        sent = true;
        return HttpResponse.json(change(), { status: 201 });
      }),
    );
    renderApp(<App />, "/dhcp");
    await openReservations();
    const add = await screen.findByRole("button", { name: "New reservation" });
    await waitFor(() => expect(add).toBeEnabled());
    fireEvent.click(add);
    fireEvent.change(await screen.findByLabelText("IP address"), {
      target: { value: "192.168.1.150" },
    });
    fireEvent.change(screen.getByLabelText("MAC address"), {
      target: { value: "02:00:00:00:00:02" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create change request" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(/dynamic pool/);
    expect(sent).toBe(false);
  });

  it("shows the diff when editing and posts to the update route", async () => {
    page(NETADMIN);
    let url = "";
    server.use(
      http.post(
        `/api/v1/changes/kea-reservations/${RES}/update`,
        ({ request }) => {
          url = request.url;
          return HttpResponse.json(change({ action: "update" }), {
            status: 201,
          });
        },
      ),
    );
    renderApp(<App />, "/dhcp");
    await openReservations();
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit 192.168.1.10" }),
    );
    fireEvent.change(await screen.findByLabelText("MAC address"), {
      target: { value: "02:00:00:00:00:09" },
    });
    expect(await screen.findByLabelText("Changes")).toHaveTextContent(
      "02:00:00:00:00:09",
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(url).toContain("/update"));
  });

  it("stages a delete after a confirmation that mentions the Kea restart", async () => {
    page(NETADMIN);
    let called = false;
    server.use(
      http.post(`/api/v1/changes/kea-reservations/${RES}/delete`, () => {
        called = true;
        return HttpResponse.json(change({ action: "delete" }), { status: 201 });
      }),
    );
    renderApp(<App />, "/dhcp");
    await openReservations();
    fireEvent.click(
      await screen.findByRole("button", { name: "Delete 192.168.1.10" }),
    );
    expect(
      await screen.findByText(/DHCP may pause briefly/),
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(called).toBe(true));
  });

  it("hides the Reservations tab from a security administrator", async () => {
    page({ ...READER, role: "security_admin" });
    renderApp(<App />, "/dhcp");
    fireEvent.click(await screen.findByRole("tab", { name: "Kea" }));
    await screen.findByRole("tab", { name: "Subnets" });
    expect(
      screen.queryByRole("tab", { name: "Reservations" }),
    ).not.toBeInTheDocument();
  });

  it("shows the proposal on the change page", async () => {
    page(ADMIN);
    server.use(
      http.get(`/api/v1/changes/${CID}`, () =>
        HttpResponse.json(change({ status: "approved" })),
      ),
    );
    renderApp(<App />, `/administration/changes/${CID}`);
    expect(await screen.findByText("Proposal")).toBeInTheDocument();
    expect(
      await screen.findByText("192.168.1.20", { selector: "dd" }),
    ).toBeInTheDocument();
  });
});
