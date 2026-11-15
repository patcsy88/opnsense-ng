import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { wireguardPeerDiff } from "@/features/changes/wireguard-peer-form";
import { server } from "@/test/server";
import { ADMIN, FW, renderApp } from "@/test/utils";

const NETADMIN = {
  id: "55555555-5555-4555-8555-555555555555",
  username: "carol",
  role: "network_admin",
} as const;
const SECADMIN = {
  id: "77777777-7777-4777-8777-777777777777",
  username: "sam",
  role: "security_admin",
} as const;
const CID = "66666666-6666-4666-8666-666666666666";
const UUID = "11111111-1111-4111-8111-111111111111";
const TUN = "22222222-2222-4222-8222-222222222222";
const KEY = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const KEY2 = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

const peer = (over: Record<string, unknown> = {}) => ({
  uuid: UUID,
  enabled: true,
  name: "road-laptop",
  pubkey: KEY,
  tunneladdress: ["10.10.0.2/32"],
  serveraddress: null,
  serverport: null,
  keepalive: null,
  servers: [TUN],
  has_psk: true,
  ...over,
});

const tunnel = () => ({
  uuid: TUN,
  enabled: true,
  name: "wg0",
  pubkey: KEY2,
  port: "51820",
  tunneladdress: ["10.10.0.1/24"],
  mtu: null,
  disableroutes: false,
  peers: [UUID],
});

const change = (over: Record<string, unknown> = {}) => ({
  id: CID,
  firewall_id: FW.id,
  kind: "wireguard_peer",
  action: "create",
  target_uuid: null,
  proposed: { label: "bob", name: "bob", risk: [] },
  base_snapshot: null,
  status: "validated",
  high_risk: false,
  self_approved: false,
  requester_username: "carol",
  reviewer_username: null,
  applier_username: null,
  failure_message: null,
  created_at: "2026-11-14T10:00:00Z",
  updated_at: "2026-11-14T10:00:00Z",
  events: [
    {
      timestamp: "2026-11-14T10:00:00Z",
      actor_username: "carol",
      from_status: null,
      to_status: "draft",
      note: null,
    },
  ],
  ...over,
});

function page(user: object, peers: unknown[] = [peer()], open: unknown[] = []) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () =>
      HttpResponse.json([{ id: FW.id, name: FW.name }]),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/vpn/wireguard`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        records: [],
        truncated: false,
        registry_verified: true,
      }),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/wireguard/peers`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        peers,
        registry_verified: false,
      }),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/wireguard/tunnels`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        tunnels: [tunnel()],
        registry_verified: false,
      }),
    ),
    http.get("/api/v1/changes", () => HttpResponse.json(open)),
    http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(change())),
  );
}

async function openTab(name = "Peers") {
  fireEvent.click(await screen.findByRole("tab", { name }));
}

describe("VPN peers", () => {
  it("lists peers with the unverified badge and no private key field", async () => {
    page(ADMIN);
    renderApp(<App />, "/vpn");
    await openTab();
    expect(await screen.findByText("road-laptop")).toBeInTheDocument();
    expect(screen.getByText(KEY, { exact: false })).toBeInTheDocument();
    expect(screen.getByText("wg0")).toBeInTheDocument();
    expect(screen.getByText(/preshared key set/)).toBeInTheDocument();
    expect(screen.getByText(/unverified/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "New peer" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).queryByLabelText(/private/i)).not.toBeInTheDocument();
    expect(
      within(dialog).queryByLabelText(/preshared/i),
    ).not.toBeInTheDocument();
  });

  it("hides the tabs from roles that cannot manage", async () => {
    page(SECADMIN);
    renderApp(<App />, "/vpn");
    await screen.findByRole("heading", { name: "VPN" });
    expect(
      screen.queryByRole("tab", { name: "Peers" }),
    ).not.toBeInTheDocument();
  });

  it("lists open requests for this kind only", async () => {
    page(
      NETADMIN,
      [peer()],
      [
        change(),
        change({
          id: "88888888-8888-4888-8888-888888888888",
          kind: "unbound_host",
        }),
      ],
    );
    renderApp(<App />, "/vpn");
    await openTab();
    expect(await screen.findAllByText(/create bob/)).toHaveLength(1);
  });

  it("creates a request with the entered fields", async () => {
    page(ADMIN);
    let body: unknown = null;
    server.use(
      http.post("/api/v1/changes/wireguard-peers", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(change(), { status: 201 });
      }),
    );
    renderApp(<App />, "/vpn");
    await openTab();
    fireEvent.click(await screen.findByRole("button", { name: "New peer" }));
    const set = (label: string, value: string) =>
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    set("Name", "bob");
    set("Tunnel address", "10.10.0.3/32");
    set("Public key", KEY2);
    set("Keepalive (optional)", "25");
    fireEvent.click(screen.getByLabelText(/wg0/));
    fireEvent.click(
      screen.getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toEqual({
      firewall_id: FW.id,
      peer: {
        name: "bob",
        pubkey: KEY2,
        tunneladdress: ["10.10.0.3/32"],
        servers: [TUN],
        serveraddress: null,
        serverport: null,
        keepalive: 25,
        enabled: true,
      },
    });
    expect(await screen.findByText("create VPN peer bob")).toBeInTheDocument();
  });

  it("checks the fields before sending anything", async () => {
    page(ADMIN);
    let called = false;
    server.use(
      http.post("/api/v1/changes/wireguard-peers", () => {
        called = true;
        return HttpResponse.json(change(), { status: 201 });
      }),
    );
    renderApp(<App />, "/vpn");
    await openTab();
    fireEvent.click(await screen.findByRole("button", { name: "New peer" }));
    const submit = () =>
      fireEvent.click(
        screen.getByRole("button", { name: "Create change request" }),
      );
    const set = (label: string, value: string) =>
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "A name is required",
    );
    set("Name", "bob");
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Never paste a private key",
    );
    set("Public key", KEY2);
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "tunnel address is required",
    );
    set("Tunnel address", "10.10.0.3/32");
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Choose at least one tunnel",
    );
    expect(called).toBe(false);
  });

  it("shows the diff while editing and sends an update", async () => {
    page(NETADMIN);
    let body: unknown = null;
    server.use(
      http.post(
        `/api/v1/changes/wireguard-peers/${UUID}/update`,
        async ({ request }) => {
          body = await request.json();
          return HttpResponse.json(change({ action: "update" }), {
            status: 201,
          });
        },
      ),
    );
    renderApp(<App />, "/vpn");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit peer road-laptop" }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("No changes yet.")).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText("Tunnel address"), {
      target: { value: "10.10.0.9/32" },
    });
    expect(await within(dialog).findByText("10.10.0.9/32")).toBeInTheDocument();
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toMatchObject({
      firewall_id: FW.id,
      peer: {
        name: "road-laptop",
        pubkey: KEY,
        tunneladdress: ["10.10.0.9/32"],
        servers: [TUN],
      },
    });
  });

  it("stages a toggle with the opposite state", async () => {
    page(NETADMIN);
    let body: unknown = null;
    server.use(
      http.post(
        `/api/v1/changes/wireguard-peers/${UUID}/toggle`,
        async ({ request }) => {
          body = await request.json();
          return HttpResponse.json(change({ action: "toggle" }), {
            status: 201,
          });
        },
      ),
    );
    renderApp(<App />, "/vpn");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", { name: "Disable peer road-laptop" }),
    );
    const dialog = await screen.findByRole("alertdialog");
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() =>
      expect(body).toEqual({ firewall_id: FW.id, enabled: false }),
    );
  });

  it("stages a delete", async () => {
    page(NETADMIN);
    let called = false;
    server.use(
      http.post(`/api/v1/changes/wireguard-peers/${UUID}/delete`, () => {
        called = true;
        return HttpResponse.json(change({ action: "delete" }), { status: 201 });
      }),
    );
    renderApp(<App />, "/vpn");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", { name: "Delete peer road-laptop" }),
    );
    const dialog = await screen.findByRole("alertdialog");
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(called).toBe(true));
  });

  it("shows the refusal from the backend in the form", async () => {
    page(NETADMIN);
    server.use(
      http.post("/api/v1/changes/wireguard-peers", () =>
        HttpResponse.json(
          { detail: "A peer with this public key already exists" },
          { status: 400 },
        ),
      ),
    );
    renderApp(<App />, "/vpn");
    await openTab();
    fireEvent.click(await screen.findByRole("button", { name: "New peer" }));
    const set = (label: string, value: string) =>
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    set("Name", "dup");
    set("Public key", KEY);
    set("Tunnel address", "10.10.0.9/32");
    fireEvent.click(screen.getByLabelText(/wg0/));
    fireEvent.click(
      screen.getByRole("button", { name: "Create change request" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "already exists",
    );
  });

  it("wireguardPeerDiff lists only the changed fields", () => {
    const a = {
      name: "x",
      pubkey: KEY,
      tunneladdress: ["10.10.0.2/32"],
      servers: [TUN],
      serveraddress: null,
      serverport: null,
      keepalive: null,
      enabled: true,
    };
    expect(wireguardPeerDiff(a, a)).toEqual([]);
    expect(wireguardPeerDiff(a, { ...a, keepalive: 25 })).toEqual([
      ["Keepalive", "—", "25"],
    ]);
  });
});
