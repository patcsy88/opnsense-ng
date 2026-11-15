import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { wireguardTunnelDiff } from "@/features/changes/wireguard-tunnel-form";
import { server } from "@/test/server";
import { ADMIN, FW, renderApp } from "@/test/utils";

const NETADMIN = {
  id: "55555555-5555-4555-8555-555555555555",
  username: "carol",
  role: "network_admin",
} as const;
const CID = "66666666-6666-4666-8666-666666666666";
const TUN = "22222222-2222-4222-8222-222222222222";
const PEER = "11111111-1111-4111-8111-111111111111";

const tunnel = (over: Record<string, unknown> = {}) => ({
  uuid: TUN,
  enabled: true,
  name: "road-wg",
  pubkey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
  port: "51820",
  tunneladdress: ["10.10.0.1/24"],
  mtu: null,
  disableroutes: false,
  peers: [PEER],
  ...over,
});

const change = (over: Record<string, unknown> = {}) => ({
  id: CID,
  firewall_id: FW.id,
  kind: "wireguard_tunnel",
  action: "create",
  target_uuid: null,
  proposed: { label: "wg9", name: "wg9", risk: ["creates a tunnel"] },
  base_snapshot: null,
  status: "validated",
  high_risk: true,
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

function page(user: object, tunnels: unknown[] = [tunnel()]) {
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
    http.get(`/api/v1/firewalls/${FW.id}/wireguard/tunnels`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        tunnels,
        registry_verified: false,
      }),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/wireguard/peers`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        peers: [
          {
            uuid: PEER,
            enabled: true,
            name: "road-laptop",
            pubkey: null,
            tunneladdress: [],
            serveraddress: null,
            serverport: null,
            keepalive: null,
            servers: [],
            has_psk: false,
          },
        ],
        registry_verified: false,
      }),
    ),
    http.get("/api/v1/changes", () => HttpResponse.json([change()])),
    http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(change())),
  );
}

async function openTab() {
  fireEvent.click(await screen.findByRole("tab", { name: "Tunnels" }));
}

describe("VPN tunnels", () => {
  it("lists tunnels, unverified, and shows no private key field", async () => {
    page(ADMIN);
    renderApp(<App />, "/vpn");
    await openTab();
    expect(await screen.findByText("road-wg")).toBeInTheDocument();
    expect(screen.getByText("10.10.0.1/24")).toBeInTheDocument();
    expect(screen.getByText(/unverified/i)).toBeInTheDocument();
    expect(await screen.findAllByText(/create wg9/)).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "New tunnel" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).queryByLabelText(/private|key/i)).toBeNull();
    expect(
      within(dialog).getByText(/generates this tunnel/),
    ).toBeInTheDocument();
  });

  it("creates a request with the entered fields and no key", async () => {
    page(NETADMIN);
    let body: unknown = null;
    server.use(
      http.post("/api/v1/changes/wireguard-tunnels", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(change(), { status: 201 });
      }),
    );
    renderApp(<App />, "/vpn");
    await openTab();
    fireEvent.click(await screen.findByRole("button", { name: "New tunnel" }));
    const set = (label: string, value: string) =>
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    set("Name", "wg9");
    set("Listen port", "51899");
    set("Tunnel address", "10.99.0.1/24");
    fireEvent.click(
      screen.getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toEqual({
      firewall_id: FW.id,
      tunnel: {
        name: "wg9",
        port: 51899,
        tunneladdress: ["10.99.0.1/24"],
        mtu: null,
        disableroutes: false,
        peers: [],
        enabled: true,
      },
    });
    expect(
      await screen.findByText("create VPN tunnel wg9"),
    ).toBeInTheDocument();
  });

  it("checks the fields before sending anything", async () => {
    page(ADMIN);
    let called = false;
    server.use(
      http.post("/api/v1/changes/wireguard-tunnels", () => {
        called = true;
        return HttpResponse.json(change(), { status: 201 });
      }),
    );
    renderApp(<App />, "/vpn");
    await openTab();
    fireEvent.click(await screen.findByRole("button", { name: "New tunnel" }));
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
    set("Name", "wg9");
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent("listen port");
    set("Listen port", "51899");
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "tunnel address is required",
    );
    set("Tunnel address", "10.99.0.1");
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent("prefix");
    expect(called).toBe(false);
  });

  it("shows the diff while editing and sends an update", async () => {
    page(NETADMIN);
    let body: unknown = null;
    server.use(
      http.post(
        `/api/v1/changes/wireguard-tunnels/${TUN}/update`,
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
      await screen.findByRole("button", { name: "Edit tunnel road-wg" }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("No changes yet.")).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText("MTU (optional)"), {
      target: { value: "1380" },
    });
    expect(await within(dialog).findByText("1380")).toBeInTheDocument();
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toMatchObject({
      firewall_id: FW.id,
      tunnel: { name: "road-wg", port: 51820, mtu: 1380, peers: [PEER] },
    });
  });

  it("stages a toggle and a delete", async () => {
    page(NETADMIN);
    let toggle: unknown = null;
    let deleted = false;
    server.use(
      http.post(
        `/api/v1/changes/wireguard-tunnels/${TUN}/toggle`,
        async ({ request }) => {
          toggle = await request.json();
          return HttpResponse.json(change({ action: "toggle" }), {
            status: 201,
          });
        },
      ),
      http.post(`/api/v1/changes/wireguard-tunnels/${TUN}/delete`, () => {
        deleted = true;
        return HttpResponse.json(change({ action: "delete" }), { status: 201 });
      }),
    );
    renderApp(<App />, "/vpn");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", { name: "Disable tunnel road-wg" }),
    );
    fireEvent.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: "Create change request",
      }),
    );
    await waitFor(() =>
      expect(toggle).toEqual({ firewall_id: FW.id, enabled: false }),
    );
    renderApp(<App />, "/vpn");
    await openTab();
    fireEvent.click(
      (
        await screen.findAllByRole("button", { name: "Delete tunnel road-wg" })
      )[0]!,
    );
    fireEvent.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: "Create change request",
      }),
    );
    await waitFor(() => expect(deleted).toBe(true));
  });

  it("shows the refusal from the backend in the form", async () => {
    page(NETADMIN);
    server.use(
      http.post("/api/v1/changes/wireguard-tunnels", () =>
        HttpResponse.json(
          { detail: "Another tunnel already listens on this port" },
          { status: 400 },
        ),
      ),
    );
    renderApp(<App />, "/vpn");
    await openTab();
    fireEvent.click(await screen.findByRole("button", { name: "New tunnel" }));
    const set = (label: string, value: string) =>
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    set("Name", "dup");
    set("Listen port", "51820");
    set("Tunnel address", "10.77.0.1/24");
    fireEvent.click(
      screen.getByRole("button", { name: "Create change request" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "already listens",
    );
  });

  it("wireguardTunnelDiff lists only the changed fields", () => {
    const a = {
      name: "x",
      port: 51820,
      tunneladdress: ["10.0.0.1/24"],
      mtu: null,
      disableroutes: false,
      peers: [PEER],
      enabled: true,
    };
    expect(wireguardTunnelDiff(a, a)).toEqual([]);
    expect(wireguardTunnelDiff(a, { ...a, port: 51821 })).toEqual([
      ["Port", "51820", "51821"],
    ]);
  });
});
