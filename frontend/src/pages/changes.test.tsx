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
    renderApp(<App />, "/changes");
    expect(await screen.findByText("create alias web_hosts")).toBeInTheDocument();
    expect(screen.getByText(/no automatic rollback/i)).toBeInTheDocument();
  });

  it("hides the create button from view-only roles", async () => {
    base(READER);
    renderApp(<App />, "/changes");
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
    renderApp(<App />, "/changes");
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
    renderApp(<App />, "/changes");
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
    renderApp(<App />, `/changes/${CID}`);
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
    renderApp(<App />, `/changes/${CID}`);
    fireEvent.click(await screen.findByRole("button", { name: "Submit for review" }));
    await waitFor(() => expect(called).toEqual(["submit"]));
    expect(await screen.findByText("In review", { selector: "span" })).toBeInTheDocument();
  });

  it("lets another network admin approve", async () => {
    base({ ...NETADMIN, username: "dave" }, { status: "in_review" });
    renderApp(<App />, `/changes/${CID}`);
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
    renderApp(<App />, `/changes/${CID}`);
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
    renderApp(<App />, `/changes/${CID}`);
    fireEvent.click(await screen.findByRole("button", { name: /apply to firewall/i }));
    const confirm = await screen.findByRole("button", { name: "Apply now" });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/type/i), { target: { value: "web_hosts" } });
    fireEvent.click(confirm);
    await waitFor(() => expect(applied).toEqual([{ confirm_name: "web_hosts" }]));
  });

  it("does not show Apply to a network admin", async () => {
    base(NETADMIN, { status: "approved", requester_username: "dave" });
    renderApp(<App />, `/changes/${CID}`);
    await screen.findByRole("heading", { name: "create alias web_hosts" });
    expect(screen.queryByRole("button", { name: /apply/i })).not.toBeInTheDocument();
  });

  it("shows why a failed apply failed", async () => {
    base(ADMIN, {
      status: "failed",
      failure_message: "The alias is saved on the firewall but NOT active: timeout",
    });
    renderApp(<App />, `/changes/${CID}`);
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
