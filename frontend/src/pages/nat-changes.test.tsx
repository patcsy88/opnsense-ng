import { fireEvent, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, FW, READER, renderApp } from "@/test/utils";

const NETADMIN = { id: "55555555-5555-4555-8555-555555555555", username: "carol", role: "network_admin" } as const;
const CID = "66666666-6666-4666-8666-666666666666";
const UUID = "11111111-1111-4111-8111-111111111111";

const forward = (over: Record<string, unknown> = {}) => ({
  uuid: UUID,
  enabled: true,
  excluded: false,
  interface: "lan",
  ip_protocol: "inet",
  protocol: "TCP",
  source: "10.0.0.0/24",
  source_port: null,
  destination: "lanip",
  destination_port: "8443",
  target: "10.0.0.5",
  target_port: "443",
  description: "Web",
  log: false,
  sequence: 3,
  automatic: false,
  ...over,
});

const change = (over: Record<string, unknown> = {}) => ({
  id: CID,
  firewall_id: FW.id,
  kind: "nat_forward",
  action: "create",
  target_uuid: null,
  proposed: {
    label: "Web",
    description: "Web",
    interface: "wan",
    ip_protocol: "inet",
    protocol: "TCP",
    source: "any",
    source_port: "",
    destination: "wanip",
    destination_port: "443",
    target: "10.0.0.5",
    target_port: "8443",
    log: false,
    enabled: true,
    risk: ["exposes a host on the WAN interface"],
  },
  base_snapshot: null,
  status: "validated",
  high_risk: true,
  self_approved: false,
  requester_username: "carol",
  reviewer_username: null,
  applier_username: null,
  failure_message: null,
  created_at: "2026-11-12T10:00:00Z",
  updated_at: "2026-11-12T10:00:00Z",
  events: [{ timestamp: "2026-11-12T10:00:00Z", actor_username: "carol", from_status: null, to_status: "draft", note: null }],
  ...over,
});

function natPage(user: object, rules: unknown[] = [forward()]) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
    http.get(`/api/v1/firewalls/${FW.id}/firewall/nat/port-forwards`, () =>
      HttpResponse.json({ firewall_id: FW.id, rules, truncated: false, registry_verified: true }),
    ),
    http.get("/api/v1/changes", () => HttpResponse.json([])),
    http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(change())),
  );
}

beforeEach(() => {
  document.cookie = "csrf_token=tok; path=/";
});

describe("NAT port forward changes", () => {
  it("shows change buttons only to managers, and not for outbound", async () => {
    natPage(NETADMIN, [forward(), forward({ uuid: null, description: "auto", automatic: true }), forward({ excluded: true, uuid: "22222222-2222-4222-8222-222222222222" })]);
    renderApp(<App />, "/nat");
    expect(await screen.findByRole("button", { name: "New port forward" })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Disable" })).toBeInTheDocument();
    expect(screen.getAllByText("Not editable here")).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "Outbound" }));
    expect(screen.queryByRole("button", { name: "New port forward" })).not.toBeInTheDocument();
  });

  it("hides every change control from view-only roles", async () => {
    natPage(READER);
    renderApp(<App />, "/nat");
    await screen.findByText("10.0.0.5:443");
    expect(screen.queryByRole("button", { name: /new port forward|disable|edit|delete/i })).not.toBeInTheDocument();
  });

  it("creates a request with the entered fields and opens it", async () => {
    natPage(NETADMIN);
    let body: unknown = null;
    server.use(
      http.post("/api/v1/changes/forwards", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(change(), { status: 201 });
      }),
    );
    renderApp(<App />, "/nat");
    fireEvent.click(await screen.findByRole("button", { name: "New port forward" }));
    fireEvent.change(await screen.findByLabelText("Description"), { target: { value: "Public web" } });
    fireEvent.change(screen.getByLabelText("Interface"), { target: { value: "wan" } });
    fireEvent.change(screen.getByLabelText("Destination"), { target: { value: "wanip" } });
    fireEvent.change(screen.getByLabelText("Destination port"), { target: { value: "443" } });
    fireEvent.change(screen.getByLabelText("Redirect target IP"), { target: { value: "10.0.0.5" } });
    fireEvent.change(screen.getByLabelText("Redirect target port"), { target: { value: "8443" } });
    fireEvent.click(screen.getByRole("button", { name: "Create change request" }));
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toEqual({
      firewall_id: FW.id,
      forward: {
        enabled: true,
        interface: "wan",
        ip_protocol: "inet",
        protocol: "TCP",
        source: "any",
        source_port: "",
        destination: "wanip",
        destination_port: "443",
        target: "10.0.0.5",
        target_port: "8443",
        log: false,
        description: "Public web",
      },
    });
    expect(await screen.findByText("create port forward Web")).toBeInTheDocument();
    expect(screen.getByText("exposes a host on the WAN interface")).toBeInTheDocument();
    expect(screen.getByText("Redirect to")).toBeInTheDocument();
  });

  it("requires a description, destination and target", async () => {
    natPage(NETADMIN);
    renderApp(<App />, "/nat");
    fireEvent.click(await screen.findByRole("button", { name: "New port forward" }));
    fireEvent.click(await screen.findByRole("button", { name: "Create change request" }));
    expect(await screen.findByText(/description is required/i)).toBeInTheDocument();
  });

  it("edits a forward with interface and description fixed", async () => {
    natPage(NETADMIN);
    let call: { uuid: unknown; body: unknown } | null = null;
    server.use(
      http.post("/api/v1/changes/forwards/:uuid/update", async ({ request, params }) => {
        call = { uuid: params.uuid, body: await request.json() };
        return HttpResponse.json(change({ action: "update", high_risk: false }), { status: 201 });
      }),
    );
    renderApp(<App />, "/nat");
    fireEvent.click(await screen.findByRole("button", { name: /edit/i }));
    expect(await screen.findByLabelText("Description")).toHaveAttribute("readonly");
    expect(screen.getByLabelText("Interface")).toHaveAttribute("readonly");
    fireEvent.change(screen.getByLabelText("Redirect target IP"), { target: { value: "10.0.0.9" } });
    fireEvent.click(screen.getByRole("button", { name: "Create change request" }));
    await waitFor(() => expect(call).not.toBeNull());
    expect(call).toMatchObject({ uuid: UUID, body: { firewall_id: FW.id, forward: { target: "10.0.0.9", description: "Web" } } });
  });

  it("stages a toggle and a delete", async () => {
    natPage(NETADMIN);
    const calls: string[] = [];
    server.use(
      http.post("/api/v1/changes/forwards/:uuid/toggle", async ({ request }) => {
        calls.push(JSON.stringify(await request.json()));
        return HttpResponse.json(change({ action: "toggle", high_risk: false, proposed: { label: "Web", enabled: false, risk: [] } }), { status: 201 });
      }),
      http.post("/api/v1/changes/forwards/:uuid/delete", async ({ request }) => {
        calls.push(JSON.stringify(await request.json()));
        return HttpResponse.json(change({ action: "delete", proposed: { label: "Web", description: "Web", risk: ["deletes a port forward"] } }), { status: 201 });
      }),
    );
    renderApp(<App />, "/nat");
    fireEvent.click(await screen.findByRole("button", { name: "Disable" }));
    fireEvent.click(await screen.findByRole("button", { name: "Create change request" }));
    await waitFor(() => expect(calls).toHaveLength(1));
    expect(JSON.parse(calls[0] as string)).toEqual({ firewall_id: FW.id, enabled: false });

    renderApp(<App />, "/nat");
    fireEvent.click((await screen.findAllByRole("button", { name: /delete/i }))[0] as HTMLElement);
    fireEvent.click(await screen.findByRole("button", { name: "Create change request" }));
    await waitFor(() => expect(calls).toHaveLength(2));
    expect(JSON.parse(calls[1] as string)).toEqual({ firewall_id: FW.id });
  });

  it("shows a refusal from the backend in the form", async () => {
    natPage(NETADMIN);
    server.use(
      http.post("/api/v1/changes/forwards", () =>
        HttpResponse.json({ detail: "A port forward with this description already exists on the firewall" }, { status: 400 }),
      ),
    );
    renderApp(<App />, "/nat");
    fireEvent.click(await screen.findByRole("button", { name: "New port forward" }));
    fireEvent.change(await screen.findByLabelText("Description"), { target: { value: "Web" } });
    fireEvent.change(screen.getByLabelText("Interface"), { target: { value: "lan" } });
    fireEvent.change(screen.getByLabelText("Destination"), { target: { value: "lanip" } });
    fireEvent.change(screen.getByLabelText("Redirect target IP"), { target: { value: "10.0.0.5" } });
    fireEvent.click(screen.getByRole("button", { name: "Create change request" }));
    expect(await screen.findByText(/already exists/i)).toBeInTheDocument();
  });
});

describe("Port forward change detail", () => {
  it("describes the effect and needs the typed description for a high-risk apply", async () => {
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(ADMIN)),
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
      http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(change({ status: "approved" }))),
    );
    renderApp(<App />, `/changes/${CID}`);
    fireEvent.click(await screen.findByRole("button", { name: /apply to firewall/i }));
    expect(await screen.findByText(/creates the port forward "Web"/i)).toBeInTheDocument();
    expect(screen.getByText(/does not add a pass rule/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Apply now" })).toBeDisabled();
  });

  it("shows the current forward for a delete", async () => {
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(ADMIN)),
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
      http.get(`/api/v1/changes/${CID}`, () =>
        HttpResponse.json(
          change({
            action: "delete",
            proposed: { label: "Web", description: "Web", risk: ["deletes a port forward"] },
            base_snapshot: forward(),
          }),
        ),
      ),
    );
    renderApp(<App />, `/changes/${CID}`);
    expect(await screen.findByText("Port forward to delete")).toBeInTheDocument();
    expect(screen.getByText("Current port forward")).toBeInTheDocument();
  });
});
