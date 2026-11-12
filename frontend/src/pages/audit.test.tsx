import { fireEvent, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, READER, renderApp } from "@/test/utils";

const SECURITY = { ...ADMIN, id: "9b2a9a40-6f5d-4f1c-8d55-4b2f2b9f4d11", username: "sec", role: "security_admin" };

const entry = (over: object = {}) => ({
  id: "6f0f1c1e-1a3b-4c5d-8e9f-0a1b2c3d4e5f",
  timestamp: "2026-11-13T10:00:00+00:00",
  username: "alice",
  action: "firewall.dns.stats",
  firewall_id: null,
  outcome: "success",
  source_ip: "192.168.1.9",
  user_agent: "Mozilla/5.0",
  detail: { reason: "ok", count: 3 },
  ...over,
});

const page = (over: object = {}) => ({
  items: [entry(), entry({ id: "7f0f1c1e-1a3b-4c5d-8e9f-0a1b2c3d4e5f", action: "rbac.denied", outcome: "denied", username: null })],
  total: 2,
  page: 1,
  page_size: 50,
  retention_days: 365,
  purgeable: 7,
  ...over,
});

function audit(user: object, data: object = page()) {
  const seen: string[] = [];
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(user)),
    http.get("/api/v1/audit", ({ request }) => {
      seen.push(new URL(request.url).search);
      return HttpResponse.json(data);
    }),
  );
  return seen;
}

describe("Audit log page", () => {
  it("lists records and shows the flat detail", async () => {
    audit(ADMIN);
    renderApp(<App />, "/administration/audit");
    expect(await screen.findByText("firewall.dns.stats")).toBeInTheDocument();
    expect(screen.getByText("rbac.denied")).toBeInTheDocument();
    expect(screen.getByText(/2 records. Retention is 365 days/)).toBeInTheDocument();
    const [first] = screen.getAllByRole("button", { name: "Details" });
    if (!first) throw new Error("no details button");
    fireEvent.click(first);
    expect(await screen.findByText("reason")).toBeInTheDocument();
    expect(screen.getByText("Mozilla/5.0")).toBeInTheDocument();
  });

  it("sends the filters to the backend", async () => {
    const seen = audit(ADMIN);
    renderApp(<App />, "/administration/audit");
    await screen.findByText("firewall.dns.stats");
    fireEvent.change(screen.getByLabelText("User"), { target: { value: "bob" } });
    fireEvent.change(screen.getByLabelText("Outcome"), { target: { value: "failure" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => expect(seen.some((s) => s.includes("username=bob") && s.includes("outcome=failure"))).toBe(true));
  });

  it("lets a security admin view but not purge", async () => {
    audit(SECURITY);
    renderApp(<App />, "/administration/audit");
    expect(await screen.findByText("firewall.dns.stats")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Purge old records" })).not.toBeInTheDocument();
  });

  it("blocks other roles", async () => {
    audit(READER);
    renderApp(<App />, "/administration/audit");
    expect(await screen.findByText("Not permitted")).toBeInTheDocument();
  });

  it("requires typing PURGE before an admin can purge", async () => {
    audit(ADMIN);
    let purged = false;
    server.use(
      http.post("/api/v1/audit/purge", () => {
        purged = true;
        return HttpResponse.json({ removed: 7, cutoff: "2025-11-13T00:00:00+00:00" });
      }),
    );
    document.cookie = "csrf_token=tok; path=/";
    renderApp(<App />, "/administration/audit");
    await screen.findByText("firewall.dns.stats");
    expect(screen.getByText(/7 records can be purged/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Purge old records" }));
    const confirm = await screen.findByRole("button", { name: "Purge" });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Type/), { target: { value: "PURGE" } });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);
    await waitFor(() => expect(purged).toBe(true));
  });

  it("disables the purge when nothing is old enough", async () => {
    audit(ADMIN, page({ purgeable: 0 }));
    renderApp(<App />, "/administration/audit");
    await screen.findByText("firewall.dns.stats");
    expect(screen.getByRole("button", { name: "Purge old records" })).toBeDisabled();
  });
});
