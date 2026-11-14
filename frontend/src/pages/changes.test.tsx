import { fireEvent, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, FW, READER, renderApp } from "@/test/utils";

const NETADMIN = { id: "55555555-5555-4555-8555-555555555555", username: "carol", role: "network_admin" } as const;
const CID = "66666666-6666-4666-8666-666666666666";

function change(over: Record<string, unknown> = {}) {
  return {
    id: CID,
    firewall_id: FW.id,
    kind: "alias",
    action: "create",
    target_uuid: null,
    proposed: { name: "web_hosts", type: "host", content: ["10.0.0.1", "10.0.0.2"], description: "Web", enabled: true },
    base_snapshot: null,
    status: "validated",
    high_risk: false,
    self_approved: false,
    requester_username: "carol",
    reviewer_username: null,
    applier_username: null,
    failure_message: null,
    created_at: "2026-11-11T10:00:00Z",
    updated_at: "2026-11-11T10:00:00Z",
    events: [
      { timestamp: "2026-11-11T10:00:00Z", actor_username: "carol", from_status: null, to_status: "draft", note: null },
    ],
    ...over,
  };
}

let current: ReturnType<typeof change>;

function base(user: object, detail: Record<string, unknown> = {}) {
  current = change(detail);
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
    http.get("/api/v1/changes", () => HttpResponse.json([current])),
    http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(current)),
  );
}

describe("Changes", () => {
  it("lists requests and shows the no-rollback notice", async () => {
    base(ADMIN);
    renderApp(<App />, "/administration/changes");
    expect(await screen.findByText("create alias web_hosts")).toBeInTheDocument();
    expect(screen.getByText(/no automatic rollback/i)).toBeInTheDocument();
  });

  it("hides the create button from view-only roles", async () => {
    base(READER);
    renderApp(<App />, "/administration/changes");
    await screen.findByText("create alias web_hosts");
    expect(screen.queryByRole("button", { name: /new alias/i })).not.toBeInTheDocument();
  });

  it("stages an alias with CSRF and opens the new request", async () => {
    let body: Record<string, unknown> | null = null;
    document.cookie = "csrf_token=tok; path=/";
    base(NETADMIN);
    server.use(
      http.post("/api/v1/changes/aliases", async ({ request }) => {
        expect(request.headers.get("x-csrf-token")).toBe("tok");
        body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(change(), { status: 201 });
      }),
    );
    renderApp(<App />, "/administration/changes");
    const open = await screen.findByRole("button", { name: /new alias/i });
    await waitFor(() => expect(open).toBeEnabled());
    fireEvent.click(open);
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "web_hosts" } });
    fireEvent.change(screen.getByLabelText("Content"), { target: { value: " 10.0.0.1 \n\n10.0.0.2\n" } });
    fireEvent.click(screen.getByRole("button", { name: "Create request" }));
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toEqual({
      firewall_id: FW.id,
      alias: { name: "web_hosts", type: "host", content: ["10.0.0.1", "10.0.0.2"], description: "" },
    });
    expect(await screen.findByRole("heading", { name: "create alias web_hosts" })).toBeInTheDocument();
  });

  it("shows server validation errors in the form", async () => {
    base(NETADMIN);
    server.use(
      http.post("/api/v1/changes/aliases", () =>
        HttpResponse.json({ detail: "An open request already creates an alias with this name" }, { status: 400 }),
      ),
    );
    renderApp(<App />, "/administration/changes");
    const open = await screen.findByRole("button", { name: /new alias/i });
    await waitFor(() => expect(open).toBeEnabled());
    fireEvent.click(open);
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "web_hosts" } });
    fireEvent.change(screen.getByLabelText("Content"), { target: { value: "10.0.0.1" } });
    fireEvent.click(screen.getByRole("button", { name: "Create request" }));
    expect(await screen.findByText(/already creates an alias/i)).toBeInTheDocument();
  });

  it("lets the requester submit, but not approve their own request", async () => {
    base(NETADMIN, { status: "in_review" });
    renderApp(<App />, `/administration/changes/${CID}`);
    expect(await screen.findByText(/cannot approve your own request/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /apply/i })).not.toBeInTheDocument();
  });

  it("offers submit for a validated request and sends it", async () => {
    const called: string[] = [];
    document.cookie = "csrf_token=tok; path=/";
    base(NETADMIN);
    server.use(
      http.post(`/api/v1/changes/${CID}/submit`, () => {
        called.push("submit");
        current = change({ status: "in_review" });
        return HttpResponse.json(current);
      }),
    );
    renderApp(<App />, `/administration/changes/${CID}`);
    fireEvent.click(await screen.findByRole("button", { name: "Submit for review" }));
    await waitFor(() => expect(called).toEqual(["submit"]));
    expect(await screen.findByText("In review", { selector: "span" })).toBeInTheDocument();
  });

  it("lets another network admin approve", async () => {
    base({ ...NETADMIN, username: "dave" }, { status: "in_review" });
    renderApp(<App />, `/administration/changes/${CID}`);
    expect(await screen.findByRole("button", { name: "Approve" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reject" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /apply/i })).not.toBeInTheDocument();
  });

  it("applies only after the warning dialog, and only for admins", async () => {
    const applied: unknown[] = [];
    document.cookie = "csrf_token=tok; path=/";
    base(ADMIN, { status: "approved", requester_username: "carol", reviewer_username: "dave" });
    server.use(
      http.post(`/api/v1/changes/${CID}/apply`, async ({ request }) => {
        applied.push(await request.json());
        current = change({ status: "applied", applier_username: "alice" });
        return HttpResponse.json(current);
      }),
    );
    renderApp(<App />, `/administration/changes/${CID}`);
    fireEvent.click(await screen.findByRole("button", { name: /apply to firewall/i }));
    expect(await screen.findByText(/no automatic rollback/i)).toBeInTheDocument();
    expect(applied).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Apply now" }));
    await waitFor(() => expect(applied).toEqual([{}]));
    expect(await screen.findByText(/Applied to the firewall/i)).toBeInTheDocument();
  });

  it("requires the alias name to be typed for a high-risk apply", async () => {
    const applied: unknown[] = [];
    base(ADMIN, { status: "approved", high_risk: true });
    server.use(
      http.post(`/api/v1/changes/${CID}/apply`, async ({ request }) => {
        applied.push(await request.json());
        current = change({ status: "applied" });
        return HttpResponse.json(current);
      }),
    );
    renderApp(<App />, `/administration/changes/${CID}`);
    fireEvent.click(await screen.findByRole("button", { name: /apply to firewall/i }));
    const confirm = await screen.findByRole("button", { name: "Apply now" });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/type/i), { target: { value: "web_hosts" } });
    fireEvent.click(confirm);
    await waitFor(() => expect(applied).toEqual([{ confirm_name: "web_hosts" }]));
  });

  it("does not show Apply to a network admin", async () => {
    base(NETADMIN, { status: "approved", requester_username: "dave" });
    renderApp(<App />, `/administration/changes/${CID}`);
    await screen.findByRole("heading", { name: "create alias web_hosts" });
    expect(screen.queryByRole("button", { name: /apply/i })).not.toBeInTheDocument();
  });

  it("shows why a failed apply failed", async () => {
    base(ADMIN, {
      status: "failed",
      failure_message: "The alias is saved on the firewall but NOT active: timeout",
    });
    renderApp(<App />, `/administration/changes/${CID}`);
    expect(await screen.findByRole("alert")).toHaveTextContent("saved on the firewall but NOT active");
  });

  it("turns writes on only after typing the firewall name", async () => {
    const patches: unknown[] = [];
    base(ADMIN);
    server.use(
      http.get("/api/v1/firewalls", () => HttpResponse.json([FW])),
      http.patch("/api/v1/firewalls/:id", async ({ request }) => {
        patches.push(await request.json());
        return HttpResponse.json({ ...FW, allow_writes: true });
      }),
    );
    renderApp(<App />, "/administration/firewalls");
    fireEvent.click(await screen.findByRole("button", { name: "Enable writes" }));
    const confirm = await screen.findByRole("button", { name: "Enable writes", description: "" });
    expect(patches).toEqual([]);
    fireEvent.change(screen.getByLabelText(/type/i), { target: { value: FW.name } });
    fireEvent.click(screen.getAllByRole("button", { name: "Enable writes" }).at(-1) ?? confirm);
    await waitFor(() => expect(patches).toEqual([{ allow_writes: true }]));
  });
});

describe("Alias update and delete", () => {
  const ALIAS_UUID = "ec691b46-6d4c-4fa5-88cc-54589859a1c9";
  const alias = {
    uuid: ALIAS_UUID,
    name: "web",
    type: "host",
    enabled: true,
    description: "Web",
    content: ["10.0.0.1"],
    content_truncated: false,
  };

  function firewallPage(user: object) {
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
      http.get(`/api/v1/firewalls/${FW.id}/firewall/rules`, () =>
        HttpResponse.json({ firewall_id: FW.id, rules: [], truncated: false, registry_verified: true }),
      ),
      http.get(`/api/v1/firewalls/${FW.id}/firewall/aliases`, () =>
        HttpResponse.json({
          firewall_id: FW.id,
          aliases: [alias, { ...alias, uuid: null, name: "geo", type: "geoip" }],
          truncated: false,
          registry_verified: true,
        }),
      ),
    );
  }

  it("shows Edit and Delete only to managers, and only for editable aliases", async () => {
    firewallPage(NETADMIN);
    renderApp(<App />, "/firewall");
    expect(await screen.findByRole("button", { name: /^edit$/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^delete$/i })).toBeInTheDocument();
    expect(screen.getAllByText("Not editable here")).toHaveLength(1);
  });

  it("hides Edit and Delete from view-only roles", async () => {
    firewallPage(READER);
    renderApp(<App />, "/firewall");
    await screen.findByText("web");
    expect(screen.queryByRole("button", { name: /^edit$/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^delete$/i })).not.toBeInTheDocument();
  });

  it("stages an update with the alias uuid, fixed name and type, and the changed content", async () => {
    let body: Record<string, unknown> | null = null;
    let path = "";
    document.cookie = "csrf_token=tok; path=/";
    firewallPage(NETADMIN);
    server.use(
      http.post("/api/v1/changes/aliases/:uuid/update", async ({ request, params }) => {
        path = String(params.uuid);
        body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(change({ action: "update", target_uuid: ALIAS_UUID }), { status: 201 });
      }),
      http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(change({ action: "update" }))),
    );
    renderApp(<App />, "/firewall");
    fireEvent.click(await screen.findByRole("button", { name: /^edit$/i }));
    expect(await screen.findByLabelText("Name")).toHaveAttribute("readonly");
    expect(screen.getByLabelText("Type")).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Content"), { target: { value: "10.0.0.1\n10.0.0.9" } });
    fireEvent.click(screen.getByRole("button", { name: "Create change request" }));
    await waitFor(() => expect(body).not.toBeNull());
    expect(path).toBe(ALIAS_UUID);
    expect(body).toEqual({
      firewall_id: FW.id,
      alias: { name: "web", type: "host", content: ["10.0.0.1", "10.0.0.9"], description: "Web", enabled: true },
    });
  });

  it("stages a delete only after confirmation and explains it is high risk", async () => {
    const calls: string[] = [];
    document.cookie = "csrf_token=tok; path=/";
    firewallPage(NETADMIN);
    server.use(
      http.post("/api/v1/changes/aliases/:uuid/delete", ({ params }) => {
        calls.push(String(params.uuid));
        return HttpResponse.json(change({ action: "delete", high_risk: true }), { status: 201 });
      }),
      http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(change({ action: "delete", high_risk: true }))),
    );
    renderApp(<App />, "/firewall");
    fireEvent.click(await screen.findByRole("button", { name: /^delete$/i }));
    expect(await screen.findByText(/high-risk change request/i)).toBeInTheDocument();
    expect(calls).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Create delete request" }));
    await waitFor(() => expect(calls).toEqual([ALIAS_UUID]));
    expect(await screen.findByText("High risk")).toBeInTheDocument();
  });

  it("shows the before-state of an update and warns clearly on a delete apply", async () => {
    base(ADMIN, {
      action: "update",
      status: "validated",
      base_snapshot: { name: "web", type: "host", content: ["10.0.0.1"], description: "Web", enabled: true },
    });
    renderApp(<App />, `/administration/changes/${CID}`);
    expect(await screen.findByText("Before this change")).toBeInTheDocument();
  });

  it("describes the deletion in the apply dialog and requires the typed name", async () => {
    base(ADMIN, { action: "delete", status: "approved", high_risk: true });
    renderApp(<App />, `/administration/changes/${CID}`);
    fireEvent.click(await screen.findByRole("button", { name: /apply to firewall/i }));
    expect(await screen.findByText(/deletes the alias web_hosts/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Apply now" })).toBeDisabled();
  });
});

describe("Rule enable/disable", () => {
  const RULE_UUID = "0b3a6c1e-1d2f-4a5b-8c7d-9e0f1a2b3c4d";
  const rule = {
    uuid: RULE_UUID,
    enabled: true,
    action: "pass",
    interface: "lan",
    direction: "in",
    ip_protocol: "inet",
    protocol: "TCP",
    source: "10.0.0.0/24",
    source_port: null,
    destination: "10.0.1.5",
    destination_port: "443",
    description: "Web out",
    log: false,
    sequence: 10,
  };
  const ruleChange = (over: Record<string, unknown> = {}) =>
    change({
      kind: "rule",
      action: "toggle",
      target_uuid: RULE_UUID,
      proposed: { label: "Web out", enabled: false, description: "Web out" },
      base_snapshot: rule,
      ...over,
    });

  function rulesPage(user: object) {
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
      http.get(`/api/v1/firewalls/${FW.id}/firewall/rules`, () =>
        HttpResponse.json({
          firewall_id: FW.id,
          rules: [rule, { ...rule, uuid: null, description: "system" }],
          truncated: false,
          registry_verified: true,
        }),
      ),
      http.get(`/api/v1/firewalls/${FW.id}/firewall/aliases`, () =>
        HttpResponse.json({ firewall_id: FW.id, aliases: [], truncated: false, registry_verified: true }),
      ),
    );
  }

  it("offers Disable only to managers and only for rules with an id", async () => {
    rulesPage(NETADMIN);
    renderApp(<App />, "/firewall");
    expect(await screen.findByRole("button", { name: "Disable" })).toBeInTheDocument();
    expect(screen.getAllByText("Not editable here")).toHaveLength(1);
  });

  it("hides the button from view-only roles", async () => {
    rulesPage(READER);
    renderApp(<App />, "/firewall");
    await screen.findByText("Web out");
    expect(screen.queryByRole("button", { name: "Disable" })).not.toBeInTheDocument();
  });

  it("stages a disable only after confirmation and opens the request", async () => {
    const calls: { uuid: string; body: unknown }[] = [];
    document.cookie = "csrf_token=tok; path=/";
    rulesPage(NETADMIN);
    server.use(
      http.post("/api/v1/changes/rules/:uuid/toggle", async ({ request, params }) => {
        calls.push({ uuid: String(params.uuid), body: await request.json() });
        return HttpResponse.json(ruleChange(), { status: 201 });
      }),
      http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(ruleChange())),
    );
    renderApp(<App />, "/firewall");
    fireEvent.click(await screen.findByRole("button", { name: "Disable" }));
    expect(calls).toEqual([]);
    fireEvent.click(await screen.findByRole("button", { name: "Create change request" }));
    await waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]).toEqual({ uuid: RULE_UUID, body: { firewall_id: FW.id, enabled: false } });
    expect(await screen.findByText("Current rule")).toBeInTheDocument();
  });

  it("describes the rule in the apply dialog and needs the typed label when high risk", async () => {
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(ADMIN)),
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
      http.get(`/api/v1/changes/${CID}`, () =>
        HttpResponse.json(ruleChange({ status: "approved", high_risk: true })),
      ),
    );
    renderApp(<App />, `/administration/changes/${CID}`);
    fireEvent.click(await screen.findByRole("button", { name: /apply to firewall/i }));
    expect(await screen.findByText(/disables the rule "Web out"/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Apply now" })).toBeDisabled();
  });

  it("edits a rule with the interface and description fixed", async () => {
    const calls: { uuid: string; body: Record<string, unknown> }[] = [];
    document.cookie = "csrf_token=tok; path=/";
    rulesPage(NETADMIN);
    server.use(
      http.post("/api/v1/changes/rules/:uuid/update", async ({ request, params }) => {
        calls.push({ uuid: String(params.uuid), body: (await request.json()) as Record<string, unknown> });
        return HttpResponse.json(ruleChange({ action: "update" }), { status: 201 });
      }),
      http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(ruleChange({ action: "update" }))),
    );
    renderApp(<App />, "/firewall");
    fireEvent.click(await screen.findByRole("button", { name: /^Edit/ }));
    expect(await screen.findByLabelText("Description")).toHaveAttribute("readonly");
    expect(screen.getByLabelText("Interface")).toHaveAttribute("readonly");
    fireEvent.change(screen.getByLabelText("Destination port"), { target: { value: "8443" } });
    fireEvent.click(screen.getByRole("button", { name: "Create change request" }));
    await waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]?.uuid).toBe(RULE_UUID);
    expect(calls[0]?.body).toEqual({
      firewall_id: FW.id,
      rule: {
        action: "pass",
        interface: "lan",
        direction: "in",
        ip_protocol: "inet",
        protocol: "TCP",
        source: "10.0.0.0/24",
        source_port: "",
        destination: "10.0.1.5",
        destination_port: "8443",
        log: false,
        enabled: true,
        description: "Web out",
      },
    });
  });

  it("stages a delete only after confirmation", async () => {
    const calls: unknown[] = [];
    document.cookie = "csrf_token=tok; path=/";
    rulesPage(NETADMIN);
    server.use(
      http.post("/api/v1/changes/rules/:uuid/delete", async ({ request }) => {
        calls.push(await request.json());
        return HttpResponse.json(ruleChange({ action: "delete", high_risk: true }), { status: 201 });
      }),
      http.get(`/api/v1/changes/${CID}`, () =>
        HttpResponse.json(ruleChange({ action: "delete", high_risk: true })),
      ),
    );
    renderApp(<App />, "/firewall");
    fireEvent.click(await screen.findByRole("button", { name: /^Delete/ }));
    expect(calls).toEqual([]);
    fireEvent.click(await screen.findByRole("button", { name: "Create change request" }));
    await waitFor(() => expect(calls).toEqual([{ firewall_id: FW.id }]));
    expect(await screen.findByText("Rule to delete")).toBeInTheDocument();
  });

  it("offers neither Edit nor Delete to view-only roles", async () => {
    rulesPage(READER);
    renderApp(<App />, "/firewall");
    await screen.findByText("Web out");
    expect(screen.queryByRole("button", { name: /^Edit/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Delete/ })).not.toBeInTheDocument();
  });

  it("describes a delete in the apply dialog and needs the typed description", async () => {
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(ADMIN)),
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
      http.get(`/api/v1/changes/${CID}`, () =>
        HttpResponse.json(ruleChange({ action: "delete", status: "approved", high_risk: true })),
      ),
    );
    renderApp(<App />, `/administration/changes/${CID}`);
    fireEvent.click(await screen.findByRole("button", { name: /apply to firewall/i }));
    expect(await screen.findByText(/permanently deletes the rule "Web out"/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Apply now" })).toBeDisabled();
  });
});

describe("New rule", () => {
  it("creates a rule request with the entered fields and opens it", async () => {
    let body: Record<string, unknown> | null = null;
    document.cookie = "csrf_token=tok; path=/";
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(NETADMIN)),
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
      http.get("/api/v1/changes", () => HttpResponse.json([])),
      http.post("/api/v1/changes/rules", async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(
          change({
            kind: "rule",
            action: "create",
            target_uuid: null,
            proposed: {
              label: "Block telnet",
              description: "Block telnet",
              action: "block",
              interface: "lan",
              direction: "in",
              ip_protocol: "inet",
              protocol: "TCP",
              source: "any",
              source_port: "",
              destination: "any",
              destination_port: "23",
              log: true,
              enabled: true,
              risk: [],
            },
          }),
          { status: 201 },
        );
      }),
      http.get(`/api/v1/changes/${CID}`, () =>
        HttpResponse.json(
          change({
            kind: "rule",
            action: "create",
            proposed: { label: "Block telnet", description: "Block telnet", action: "block", interface: "lan", direction: "in", ip_protocol: "inet", protocol: "TCP", source: "any", source_port: "", destination: "any", destination_port: "23", log: true, enabled: true, risk: [] },
          }),
        ),
      ),
    );
    renderApp(<App />, "/administration/changes");
    const newRule = await screen.findByRole("button", { name: /new rule/i });
    await waitFor(() => expect(newRule).toBeEnabled());
    fireEvent.click(newRule);
    fireEvent.change(await screen.findByLabelText("Description"), { target: { value: "Block telnet" } });
    fireEvent.change(screen.getByLabelText("Interface"), { target: { value: "lan" } });
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "TCP" } });
    fireEvent.change(await screen.findByLabelText("Destination port"), { target: { value: "23" } });
    fireEvent.click(screen.getByLabelText(/log matching/i));
    fireEvent.click(screen.getByRole("button", { name: "Create request" }));
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toEqual({
      firewall_id: FW.id,
      rule: {
        action: "block",
        interface: "lan",
        direction: "in",
        ip_protocol: "inet",
        protocol: "TCP",
        source: "any",
        source_port: "",
        destination: "any",
        destination_port: "23",
        log: true,
        enabled: true,
        description: "Block telnet",
      },
    });
    expect(await screen.findByText("Block telnet")).toBeInTheDocument();
  });

  it("requires a description and hides ports unless the protocol has them", async () => {
    document.cookie = "csrf_token=tok; path=/";
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(NETADMIN)),
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
      http.get("/api/v1/changes", () => HttpResponse.json([])),
    );
    renderApp(<App />, "/administration/changes");
    const newRule = await screen.findByRole("button", { name: /new rule/i });
    await waitFor(() => expect(newRule).toBeEnabled());
    fireEvent.click(newRule);
    await screen.findByLabelText("Description");
    expect(screen.queryByLabelText("Destination port")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Create request" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("description is required");
  });

  it("hides New rule from view-only roles", async () => {
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(READER)),
      http.get("/api/v1/firewalls/options", () => HttpResponse.json([{ id: FW.id, name: FW.name }])),
      http.get("/api/v1/changes", () => HttpResponse.json([])),
    );
    renderApp(<App />, "/administration/changes");
    await screen.findByRole("heading", { name: "Changes" });
    await screen.findByRole("combobox", { name: /firewall/i });
    expect(screen.queryByRole("button", { name: /new rule/i })).not.toBeInTheDocument();
  });
});
