import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { App } from "@/App";
import { domainDiff } from "@/features/changes/domain-form";
import { server } from "@/test/server";
import { ADMIN, FW, renderApp } from "@/test/utils";

const NETADMIN = {
  id: "55555555-5555-4555-8555-555555555555",
  username: "carol",
  role: "network_admin",
} as const;
const CID = "66666666-6666-4666-8666-666666666666";
const UUID = "11111111-1111-4111-8111-111111111111";

const domain = (over: Record<string, unknown> = {}) => ({
  uuid: UUID,
  domain: "corp.example",
  server: "10.0.0.53",
  port: null,
  description: "Corporate DNS",
  ...over,
});

const change = (over: Record<string, unknown> = {}) => ({
  id: CID,
  firewall_id: FW.id,
  kind: "dnsmasq_domain",
  action: "create",
  target_uuid: null,
  proposed: {
    label: "Lab DNS",
    domain: "lab.example",
    server: "10.0.0.54",
    port: 5353,
    description: "Lab DNS",
    risk: [
      "sends all lookups for lab.example to the DNS server 10.0.0.54:5353",
    ],
  },
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

function page(
  user: object,
  domains: unknown[] = [domain()],
  open: unknown[] = [],
) {
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/firewalls/options", () =>
      HttpResponse.json([{ id: FW.id, name: FW.name }]),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/dnsmasq/hosts`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        hosts: [],
        registry_verified: true,
      }),
    ),
    http.get(`/api/v1/firewalls/${FW.id}/dnsmasq/domains`, () =>
      HttpResponse.json({
        firewall_id: FW.id,
        domains,
        registry_verified: false,
      }),
    ),
    http.get("/api/v1/changes", () => HttpResponse.json(open)),
    http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(change())),
  );
}

async function openTab() {
  fireEvent.click(await screen.findByRole("tab", { name: "Domain overrides" }));
}

beforeEach(() => {
  document.cookie = "csrf_token=tok; path=/";
});

describe("Dnsmasq domain overrides", () => {
  it("lists overrides on their own tab and flags the unverified capability", async () => {
    page(NETADMIN, [domain({ port: "5353" })]);
    renderApp(<App />, "/dhcp/entries");
    await openTab();
    expect(await screen.findByText("corp.example")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.53:5353")).toBeInTheDocument();
    expect(screen.getByText(/unverified/i)).toBeInTheDocument();
  });

  it("lists open requests for this kind only", async () => {
    page(
      NETADMIN,
      [domain()],
      [
        change(),
        change({
          id: "88888888-8888-4888-8888-888888888888",
          kind: "dnsmasq_host",
        }),
      ],
    );
    renderApp(<App />, "/dhcp/entries");
    await openTab();
    expect(await screen.findAllByText(/create Lab DNS/)).toHaveLength(1);
  });

  it("creates a request with the entered fields and opens it", async () => {
    page(NETADMIN);
    let body: unknown = null;
    server.use(
      http.post("/api/v1/changes/dnsmasq-domains", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(change(), { status: 201 });
      }),
    );
    renderApp(<App />, "/dhcp/entries");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", { name: "New override" }),
    );
    fireEvent.change(await screen.findByLabelText("Domain"), {
      target: { value: "Lab.Example" },
    });
    fireEvent.change(screen.getByLabelText("DNS server IP"), {
      target: { value: "10.0.0.54" },
    });
    fireEvent.change(screen.getByLabelText("Port (optional)"), {
      target: { value: "5353" },
    });
    fireEvent.change(screen.getByLabelText("Description"), {
      target: { value: "Lab DNS" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toEqual({
      firewall_id: FW.id,
      override: {
        domain: "lab.example",
        server: "10.0.0.54",
        port: 5353,
        description: "Lab DNS",
      },
    });
    expect(
      await screen.findByText("create DNS domain override Lab DNS"),
    ).toBeInTheDocument();
    expect(screen.getByText("DNS server")).toBeInTheDocument();
  });

  it("checks the fields before sending anything", async () => {
    page(NETADMIN);
    let called = false;
    server.use(
      http.post("/api/v1/changes/dnsmasq-domains", () => {
        called = true;
        return HttpResponse.json(change(), { status: 201 });
      }),
    );
    renderApp(<App />, "/dhcp/entries");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", { name: "New override" }),
    );
    const submit = () =>
      fireEvent.click(
        screen.getByRole("button", { name: "Create change request" }),
      );
    const set = (label: string, value: string) =>
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "A domain is required",
    );
    set("Domain", "*.example.com");
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Wildcards are not allowed",
    );
    set("Domain", "lab.example");
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "DNS server IP address is required",
    );
    set("DNS server IP", "10.0.0.54");
    set("Port (optional)", "99999");
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent("port must be");
    expect(called).toBe(false);
  });

  it("shows the diff while editing and sends an update", async () => {
    page(NETADMIN);
    let url = "";
    server.use(
      http.post(
        `/api/v1/changes/dnsmasq-domains/${UUID}/update`,
        ({ request }) => {
          url = request.url;
          return HttpResponse.json(change({ action: "update" }), {
            status: 201,
          });
        },
      ),
    );
    renderApp(<App />, "/dhcp/entries");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Edit override Corporate DNS",
      }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("No changes yet.")).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText("DNS server IP"), {
      target: { value: "10.0.0.99" },
    });
    expect(await within(dialog).findByText("10.0.0.99")).toBeInTheDocument();
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(url).not.toBe(""));
  });

  it("stages a delete as a high-risk request", async () => {
    page(NETADMIN);
    let called = false;
    server.use(
      http.post(`/api/v1/changes/dnsmasq-domains/${UUID}/delete`, () => {
        called = true;
        return HttpResponse.json(change({ action: "delete" }), { status: 201 });
      }),
    );
    renderApp(<App />, "/dhcp/entries");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Delete override Corporate DNS",
      }),
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
      http.post("/api/v1/changes/dnsmasq-domains", () =>
        HttpResponse.json(
          {
            detail:
              "An override for this domain already exists on the firewall",
          },
          { status: 400 },
        ),
      ),
    );
    renderApp(<App />, "/dhcp/entries");
    await openTab();
    fireEvent.click(
      await screen.findByRole("button", { name: "New override" }),
    );
    fireEvent.change(await screen.findByLabelText("Domain"), {
      target: { value: "corp.example" },
    });
    fireEvent.change(screen.getByLabelText("DNS server IP"), {
      target: { value: "10.0.0.9" },
    });
    fireEvent.change(screen.getByLabelText("Description"), {
      target: { value: "Dup" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create change request" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "already exists",
    );
  });

  it("domainDiff lists only the changed fields", () => {
    const a = {
      domain: "x.example",
      server: "1.1.1.1",
      port: null,
      description: "d",
    };
    expect(domainDiff(a, a)).toEqual([]);
    expect(domainDiff(a, { ...a, server: "2.2.2.2", port: 53 })).toEqual([
      ["DNS server", "1.1.1.1", "2.2.2.2"],
      ["Port", "—", "53"],
    ]);
  });
});

describe("domain override change review", () => {
  it("shows the Dnsmasq restart notice and needs the description to apply", async () => {
    const approved = change({ status: "approved" });
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
    renderApp(<App />, `/changes/${CID}`);
    expect(await screen.findByText("lab.example")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.54:5353")).toBeInTheDocument();
    fireEvent.click(
      await screen.findByRole("button", { name: "Apply to firewall…" }),
    );
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent(/restarts Dnsmasq/);
    expect(dialog).toHaveTextContent(/which DNS server answers/);
    const confirm = within(dialog).getByRole("button", { name: "Apply now" });
    expect(confirm).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText(/Type/), {
      target: { value: "Lab DNS" },
    });
    fireEvent.click(confirm);
    await waitFor(() => expect(sent).toEqual({ confirm_name: "Lab DNS" }));
  });
});
