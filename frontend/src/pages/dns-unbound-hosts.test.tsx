import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { App } from "@/App";
import { unboundHostDiff } from "@/features/changes/unbound-host-form";
import { server } from "@/test/server";
import { ADMIN, FW, renderApp } from "@/test/utils";

const NETADMIN = {
  id: "55555555-5555-4555-8555-555555555555",
  username: "carol",
  role: "network_admin",
} as const;
const SECADMIN = {
  id: "77777777-7777-4777-8777-777777777777",
  username: "dave",
  role: "security_admin",
} as const;
const CID = "66666666-6666-4666-8666-666666666666";
const UUID = "11111111-1111-4111-8111-111111111111";
const MX_UUID = "22222222-2222-4222-8222-222222222222";

const host = (over: Record<string, unknown> = {}) => ({
  uuid: UUID,
  enabled: true,
  hostname: "nas",
  domain: "home.test",
  rr: "A",
  server: "10.0.0.20",
  ttl: null,
  description: "NAS",
  editable: true,
  ...over,
});

const change = (over: Record<string, unknown> = {}) => ({
  id: CID,
  firewall_id: FW.id,
  kind: "unbound_host",
  action: "create",
  target_uuid: null,
  proposed: {
    label: "Printer",
    hostname: "printer",
    domain: "home.test",
    rr: "A",
    server: "10.0.0.30",
    ttl: null,
    description: "Printer",
    enabled: true,
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

function page(user: object, hosts: unknown[] = [host()], open: unknown[] = []) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () =>
      HttpResponse.json([{ id: FW.id, name: FW.name }]),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/dns`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        stats_available: false,
        totals_available: false,
        queries: null,
        cache_hits: null,
        cache_misses: null,
        hit_rate: null,
        uptime_seconds: null,
        logged_queries: null,
        blocked: null,
        blocked_percent: null,
        blocklist_size: null,
        top_queried: [],
        top_blocked: [],
        registry_verified: true,
      }),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/unbound/hosts`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        hosts,
        registry_verified: false,
      }),
    ),
    http.get("/api/v1/changes", () => HttpResponse.json(open)),
    http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(change())),
  );
}

async function openTab() {
  fireEvent.click(await screen.findByRole("tab", { name: "Host overrides" }));
}

beforeEach(() => {
  document.cookie = "csrf_token=tok; path=/";
});

describe("Unbound host overrides", () => {
  it("shows the tab to admins and network admins only", async () => {
    page(SECADMIN);
    renderApp(<App />, "/dns");
    await screen.findByRole("heading", { name: "DNS" });
    expect(screen.queryByRole("tab")).not.toBeInTheDocument();
  });

  it("lists hosts, flags the unverified capability and MX rows as read-only", async () => {
    page(NETADMIN, [
      host(),
      host({
        uuid: MX_UUID,
        rr: "MX",
        hostname: "mail",
        description: "Mail",
        editable: false,
      }),
    ]);
    renderApp(<App />, "/dns");
    await openTab();
    expect(await screen.findByText("nas.home.test")).toBeInTheDocument();
    expect(screen.getByText("A 10.0.0.20")).toBeInTheDocument();
    expect(screen.getByText(/unverified/i)).toBeInTheDocument();
    expect(screen.getByText("Not editable here")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Edit host override Mail" }),
    ).not.toBeInTheDocument();
  });

  it("creates a request with the entered fields", async () => {
    page(ADMIN);
    let body: unknown = null;
    server.use(
      http.post("/api/v1/changes/unbound-hosts", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(change(), { status: 201 });
      }),
    );
    renderApp(<App />, "/dns");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", { name: "New host override" }),
    );
    const set = (label: string, value: string) =>
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    set("Host name", "Printer");
    set("Domain", "Home.Test");
    set("IP address", "10.0.0.30");
    set("TTL seconds (optional)", "300");
    set("Description", "Printer");
    fireEvent.click(
      screen.getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toEqual({
      firewall_id: FW.id,
      host: {
        hostname: "printer",
        domain: "home.test",
        rr: "A",
        server: "10.0.0.30",
        ttl: 300,
        description: "Printer",
        enabled: true,
      },
    });
    expect(
      await screen.findByText("create DNS host override Printer"),
    ).toBeInTheDocument();
  });

  it("checks the fields before sending anything", async () => {
    page(ADMIN);
    let called = false;
    server.use(
      http.post("/api/v1/changes/unbound-hosts", () => {
        called = true;
        return HttpResponse.json(change(), { status: 201 });
      }),
    );
    renderApp(<App />, "/dns");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", { name: "New host override" }),
    );
    const submit = () =>
      fireEvent.click(
        screen.getByRole("button", { name: "Create change request" }),
      );
    const set = (label: string, value: string) =>
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "A host name is required",
    );
    set("Host name", "a.b");
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent("single label");
    set("Host name", "nas");
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "A domain is required",
    );
    set("Domain", "home.test");
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "An IP address is required",
    );
    set("IP address", "10.0.0.1");
    set("TTL seconds (optional)", "abc");
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent("TTL");
    set("TTL seconds (optional)", "");
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "A description is required",
    );
    expect(called).toBe(false);
  });

  it("shows the diff while editing and sends an update", async () => {
    page(NETADMIN);
    let body: unknown = null;
    server.use(
      http.post(
        `/api/v1/changes/unbound-hosts/${UUID}/update`,
        async ({ request }) => {
          body = await request.json();
          return HttpResponse.json(change({ action: "update" }), {
            status: 201,
          });
        },
      ),
    );
    renderApp(<App />, "/dns");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit host override NAS" }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("No changes yet.")).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText("IP address"), {
      target: { value: "10.0.0.99" },
    });
    expect(await within(dialog).findByText("10.0.0.99")).toBeInTheDocument();
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toMatchObject({
      firewall_id: FW.id,
      host: { hostname: "nas", server: "10.0.0.99", enabled: true },
    });
  });

  it("stages a toggle with the opposite state", async () => {
    page(NETADMIN);
    let body: unknown = null;
    server.use(
      http.post(
        `/api/v1/changes/unbound-hosts/${UUID}/toggle`,
        async ({ request }) => {
          body = await request.json();
          return HttpResponse.json(change({ action: "toggle" }), {
            status: 201,
          });
        },
      ),
    );
    renderApp(<App />, "/dns");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", { name: "Disable host override NAS" }),
    );
    const dialog = await screen.findByRole("alertdialog");
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() =>
      expect(body).toEqual({ firewall_id: FW.id, enabled: false }),
    );
  });

  it("stages a delete as a high-risk request", async () => {
    page(NETADMIN);
    let called = false;
    server.use(
      http.post(`/api/v1/changes/unbound-hosts/${UUID}/delete`, () => {
        called = true;
        return HttpResponse.json(change({ action: "delete" }), { status: 201 });
      }),
    );
    renderApp(<App />, "/dns");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", { name: "Delete host override NAS" }),
    );
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("high-risk");
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(called).toBe(true));
  });

  it("shows the refusal from the backend in the form", async () => {
    page(NETADMIN);
    server.use(
      http.post("/api/v1/changes/unbound-hosts", () =>
        HttpResponse.json(
          {
            detail:
              "A host override with this name, domain and record type already exists",
          },
          { status: 400 },
        ),
      ),
    );
    renderApp(<App />, "/dns");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", { name: "New host override" }),
    );
    const set = (label: string, value: string) =>
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    set("Host name", "nas");
    set("Domain", "home.test");
    set("IP address", "10.0.0.9");
    set("Description", "Dup");
    fireEvent.click(
      screen.getByRole("button", { name: "Create change request" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "already exists",
    );
  });

  it("unboundHostDiff lists only the changed fields", () => {
    const a = {
      hostname: "nas",
      domain: "home.test",
      rr: "A" as const,
      server: "10.0.0.20",
      ttl: null,
      description: "NAS",
      enabled: true,
    };
    expect(unboundHostDiff(a, a)).toEqual([]);
    expect(unboundHostDiff(a, { ...a, server: "10.0.0.21", ttl: 60 })).toEqual([
      ["IP address", "10.0.0.20", "10.0.0.21"],
      ["TTL", "—", "60"],
    ]);
  });
});

describe("host override change review", () => {
  it("shows the Unbound restart notice and needs the description to apply", async () => {
    const approved = change({ status: "approved" });
    page(ADMIN);
    server.use(
      http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(approved)),
    );
    renderApp(<App />, `/administration/changes/${CID}`);
    expect(await screen.findByText("printer.home.test")).toBeInTheDocument();
    expect(screen.getByText("A 10.0.0.30")).toBeInTheDocument();
    expect(
      await screen.findByRole("button", { name: "Apply to firewall…" }),
    ).toBeInTheDocument();
  });

  it("requires the typed description for a high-risk delete", async () => {
    const approved = change({
      status: "approved",
      action: "delete",
      target_uuid: UUID,
      high_risk: true,
      base_snapshot: host(),
      proposed: {
        label: "NAS",
        hostname: "nas",
        domain: "home.test",
        description: "NAS",
        risk: ["deletes a host override"],
      },
    });
    page(ADMIN);
    server.use(
      http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(approved)),
    );
    let sent: unknown = null;
    server.use(
      http.post(`/api/v1/changes/${CID}/apply`, async ({ request }) => {
        sent = await request.json();
        return HttpResponse.json({ ...approved, status: "applied" });
      }),
    );
    renderApp(<App />, `/administration/changes/${CID}`);
    expect(
      await screen.findByText("Current host override"),
    ).toBeInTheDocument();
    fireEvent.click(
      await screen.findByRole("button", { name: "Apply to firewall…" }),
    );
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent(/restarts Unbound/);
    expect(dialog).toHaveTextContent(/every client/);
    const confirm = within(dialog).getByRole("button", { name: "Apply now" });
    expect(confirm).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText(/Type/), {
      target: { value: "NAS" },
    });
    fireEvent.click(confirm);
    await waitFor(() => expect(sent).toEqual({ confirm_name: "NAS" }));
  });
});
