import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { App } from "@/App";
import { hostDiff } from "@/features/changes/host-form";
import { server } from "@/test/server";
import { ADMIN, FW, READER, renderApp } from "@/test/utils";

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

const host = (over: Record<string, unknown> = {}) => ({
  uuid: UUID,
  host: "printer",
  domain: "lan.test",
  ips: ["10.0.0.20"],
  hwaddrs: ["aa:bb:cc:dd:ee:01"],
  cnames: [],
  ignore: false,
  description: "Office printer",
  ...over,
});

const change = (over: Record<string, unknown> = {}) => ({
  id: CID,
  firewall_id: FW.id,
  kind: "dnsmasq_host",
  action: "create",
  target_uuid: null,
  proposed: {
    label: "Office scanner",
    host: "scanner",
    domain: "lan.test",
    ips: ["10.0.0.21"],
    hwaddrs: ["aa:bb:cc:dd:ee:02"],
    cnames: [],
    ignore: false,
    description: "Office scanner",
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

function entriesPage(
  user: object,
  hosts: unknown[] = [host()],
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
        hosts,
        registry_verified: false,
      }),
    ),
    http.get("/api/v1/changes", () => HttpResponse.json(open)),
    http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(change())),
  );
}

beforeEach(() => {
  document.cookie = "csrf_token=tok; path=/";
});

describe("DNS and DHCP static hosts", () => {
  it("lists hosts with MAC addresses and flags the unverified capability", async () => {
    entriesPage(NETADMIN, [
      host(),
      host({
        uuid: "22222222-2222-4222-8222-222222222222",
        host: "tv",
        ignore: true,
        hwaddrs: ["aa:bb:cc:dd:ee:09"],
      }),
    ]);
    renderApp(<App />, "/dhcp/entries");
    expect(await screen.findByText("aa:bb:cc:dd:ee:01")).toBeInTheDocument();
    expect(screen.getByText("ignored")).toBeInTheDocument();
    expect(screen.getByText(/unverified/i)).toBeInTheDocument();
  });

  it("is closed to view-only roles and the DHCP page links to it only for managers", async () => {
    for (const user of [READER, SECADMIN]) {
      entriesPage(user);
      const { unmount } = renderApp(<App />, "/dhcp/entries");
      expect(await screen.findByText(/not permitted/i)).toBeInTheDocument();
      unmount();
    }
    server.use(
      http.get(`/api/v1/firewalls/${FW.id}/dhcp/leases`, () =>
        HttpResponse.json({
          firewall_id: FW.id,
          leases: [],
          truncated: false,
          registry_verified: true,
        }),
      ),
    );
    entriesPage(SECADMIN);
    renderApp(<App />, "/dhcp");
    await screen.findByRole("heading", { name: "DHCP" });
    expect(
      screen.queryByRole("link", { name: "Manage static hosts" }),
    ).not.toBeInTheDocument();
  });

  it("lists open requests for this kind", async () => {
    entriesPage(
      NETADMIN,
      [host()],
      [
        change(),
        change({ id: "88888888-8888-4888-8888-888888888888", kind: "alias" }),
      ],
    );
    renderApp(<App />, "/dhcp/entries");
    expect(
      await screen.findByText(/create Office scanner/),
    ).toBeInTheDocument();
  });

  it("creates a request with the entered fields and opens it", async () => {
    entriesPage(NETADMIN);
    let body: unknown = null;
    server.use(
      http.post("/api/v1/changes/dnsmasq-hosts", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(change(), { status: 201 });
      }),
    );
    renderApp(<App />, "/dhcp/entries");
    fireEvent.click(await screen.findByRole("button", { name: "New host" }));
    fireEvent.change(await screen.findByLabelText("Host name"), {
      target: { value: "Scanner" },
    });
    fireEvent.change(screen.getByLabelText("Domain"), {
      target: { value: "lan.test" },
    });
    fireEvent.change(screen.getByLabelText("IP addresses"), {
      target: { value: "10.0.0.21" },
    });
    fireEvent.change(screen.getByLabelText("MAC addresses"), {
      target: { value: "AA:BB:CC:DD:EE:02" },
    });
    fireEvent.change(screen.getByLabelText("Description"), {
      target: { value: "Office scanner" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toEqual({
      firewall_id: FW.id,
      host: {
        host: "scanner",
        domain: "lan.test",
        ips: ["10.0.0.21"],
        hwaddrs: ["aa:bb:cc:dd:ee:02"],
        cnames: [],
        ignore: false,
        description: "Office scanner",
      },
    });
    expect(
      await screen.findByText("create DNS/DHCP host Office scanner"),
    ).toBeInTheDocument();
    expect(screen.getByText("MAC addresses")).toBeInTheDocument();
  });

  it("checks required fields before sending anything", async () => {
    entriesPage(NETADMIN);
    let called = false;
    server.use(
      http.post("/api/v1/changes/dnsmasq-hosts", () => {
        called = true;
        return HttpResponse.json(change(), { status: 201 });
      }),
    );
    renderApp(<App />, "/dhcp/entries");
    fireEvent.click(await screen.findByRole("button", { name: "New host" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Create change request" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "A host name is required",
    );
    fireEvent.change(screen.getByLabelText("Host name"), {
      target: { value: "x" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create change request" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "At least one IP address",
    );
    expect(called).toBe(false);
  });

  it("shows the diff while editing and sends an update", async () => {
    entriesPage(NETADMIN);
    let url = "";
    server.use(
      http.post(
        `/api/v1/changes/dnsmasq-hosts/${UUID}/update`,
        ({ request }) => {
          url = request.url;
          return HttpResponse.json(change({ action: "update" }), {
            status: 201,
          });
        },
      ),
    );
    renderApp(<App />, "/dhcp/entries");
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit Office printer" }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("No changes yet.")).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText("IP addresses"), {
      target: { value: "10.0.0.22" },
    });
    expect(await within(dialog).findByText("10.0.0.22")).toBeInTheDocument();
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(url).not.toBe(""));
  });

  it("stages a delete as a high-risk request", async () => {
    entriesPage(NETADMIN);
    let called = false;
    server.use(
      http.post(`/api/v1/changes/dnsmasq-hosts/${UUID}/delete`, () => {
        called = true;
        return HttpResponse.json(
          change({ action: "delete", high_risk: true }),
          { status: 201 },
        );
      }),
    );
    renderApp(<App />, "/dhcp/entries");
    fireEvent.click(
      await screen.findByRole("button", { name: "Delete Office printer" }),
    );
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("high-risk");
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Create change request" }),
    );
    await waitFor(() => expect(called).toBe(true));
  });

  it("shows the refusal from the backend in the form", async () => {
    entriesPage(NETADMIN);
    server.use(
      http.post("/api/v1/changes/dnsmasq-hosts", () =>
        HttpResponse.json(
          {
            detail:
              "A host entry with this name and domain already exists on the firewall",
          },
          { status: 400 },
        ),
      ),
    );
    renderApp(<App />, "/dhcp/entries");
    fireEvent.click(await screen.findByRole("button", { name: "New host" }));
    fireEvent.change(await screen.findByLabelText("Host name"), {
      target: { value: "printer" },
    });
    fireEvent.change(screen.getByLabelText("IP addresses"), {
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

  it("hostDiff lists only the changed fields", () => {
    const a = {
      host: "x",
      domain: "",
      ips: ["1.1.1.1"],
      hwaddrs: [],
      cnames: [],
      ignore: false,
      description: "d",
    };
    expect(hostDiff(a, a)).toEqual([]);
    expect(hostDiff(a, { ...a, ips: ["2.2.2.2"], ignore: true })).toEqual([
      ["IP addresses", "1.1.1.1", "2.2.2.2"],
      ["Ignore", "No", "Yes"],
    ]);
  });
});

describe("DNS/DHCP host change review", () => {
  it("shows the Dnsmasq restart notice and needs the description for a high-risk apply", async () => {
    const high = change({
      status: "approved",
      high_risk: true,
      proposed: {
        ...change().proposed,
        risk: ["blocks this device from DHCP (ignore)"],
        ignore: true,
      },
    });
    entriesPage(ADMIN);
    server.use(
      http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(high)),
    );
    let sent: unknown = null;
    server.use(
      http.post(`/api/v1/changes/${CID}/apply`, async ({ request }) => {
        sent = await request.json();
        return HttpResponse.json({ ...high, status: "applied" });
      }),
    );
    renderApp(<App />, `/changes/${CID}`);
    fireEvent.click(
      await screen.findByRole("button", { name: "Apply to firewall…" }),
    );
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent(/restarts Dnsmasq/);
    expect(dialog).toHaveTextContent(/DNS and DHCP pause/);
    const confirm = within(dialog).getByRole("button", { name: "Apply now" });
    expect(confirm).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText(/Type/), {
      target: { value: "Office scanner" },
    });
    fireEvent.click(confirm);
    await waitFor(() =>
      expect(sent).toEqual({ confirm_name: "Office scanner" }),
    );
  });

  it("hides MAC rows when the backend leaves them out", async () => {
    const hidden = change();
    delete (hidden.proposed as Record<string, unknown>).hwaddrs;
    entriesPage(READER);
    server.use(
      http.get(`/api/v1/changes/${CID}`, () => HttpResponse.json(hidden)),
    );
    renderApp(<App />, `/changes/${CID}`);
    expect(await screen.findByText("IP addresses")).toBeInTheDocument();
    expect(screen.queryByText("MAC addresses")).not.toBeInTheDocument();
  });
});
