import { fireEvent, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, FW, renderApp } from "@/test/utils";

describe("Firewall Connections page", () => {
  it("creates a firewall, sends secrets once and clears them from state and DOM", async () => {
    let created: Record<string, unknown> | null = null;
    document.cookie = "csrf_token=tok; path=/";
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(ADMIN)),
      http.get("/api/v1/firewalls", () => HttpResponse.json([FW])),
      http.post("/api/v1/firewalls", async ({ request }) => {
        expect(request.headers.get("x-csrf-token")).toBe("tok");
        created = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ ...FW, id: "44444444-4444-4444-8444-444444444444", name: "new" }, { status: 201 });
      }),
    );
    const { qc } = renderApp(<App />, "/administration/firewalls");
    fireEvent.click(await screen.findByRole("button", { name: /add firewall/i }));
    const key = await screen.findByLabelText("API key");
    const secret = screen.getByLabelText("API secret");
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "new" } });
    fireEvent.change(screen.getByLabelText("Base URL"), { target: { value: "https://192.0.2.9" } });
    fireEvent.change(key, { target: { value: "KEY-SECRET-1" } });
    fireEvent.change(secret, { target: { value: "SECRET-SECRET-2" } });
    fireEvent.click(screen.getByRole("button", { name: "Add firewall", hidden: false, description: "" }).closest("form")!.querySelector("button[type=submit]")!);

    await waitFor(() => expect(created).not.toBeNull());
    expect(created).toMatchObject({ api_key: "KEY-SECRET-1", api_secret: "SECRET-SECRET-2", verify_tls: true });
    await waitFor(() => expect(screen.queryByLabelText("API key")).not.toBeInTheDocument());

    // Secrets must be nowhere in the query/mutation caches or storage.
    const dump = JSON.stringify([
      qc.getQueryCache().getAll().map((q) => q.state.data),
      qc.getMutationCache().getAll().map((m) => [m.state.variables, m.state.data]),
      { ...localStorage },
      { ...sessionStorage },
    ]);
    expect(dump).not.toContain("KEY-SECRET-1");
    expect(dump).not.toContain("SECRET-SECRET-2");
    expect(document.body.innerHTML).not.toContain("KEY-SECRET-1");
  });

  it("clears secrets even when the submit fails", async () => {
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(ADMIN)),
      http.get("/api/v1/firewalls", () => HttpResponse.json([])),
      http.post("/api/v1/firewalls", () => HttpResponse.json({ detail: "A firewall with this name exists" }, { status: 409 })),
    );
    renderApp(<App />, "/administration/firewalls");
    fireEvent.click(await screen.findByRole("button", { name: /add firewall/i }));
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "dup" } });
    fireEvent.change(screen.getByLabelText("Base URL"), { target: { value: "https://192.0.2.9" } });
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "K" } });
    fireEvent.change(screen.getByLabelText("API secret"), { target: { value: "S" } });
    fireEvent.click(document.querySelector("form button[type=submit]")!);
    expect(await screen.findByText("A firewall with this name exists")).toBeInTheDocument();
    expect(screen.getByLabelText("API key")).toHaveValue("");
    expect(screen.getByLabelText("API secret")).toHaveValue("");
  });

  it("warns when TLS verification is turned off", async () => {
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(ADMIN)),
      http.get("/api/v1/firewalls", () => HttpResponse.json([])),
    );
    renderApp(<App />, "/administration/firewalls");
    fireEvent.click(await screen.findByRole("button", { name: /add firewall/i }));
    fireEvent.click(await screen.findByLabelText("Verify TLS certificate"));
    expect(screen.getByText(/certificate verification off/i)).toBeInTheDocument();
  });

  it("edits via PATCH sending only changed fields and requires confirmation to disable TLS", async () => {
    const patches: Record<string, unknown>[] = [];
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(ADMIN)),
      http.get("/api/v1/firewalls", () => HttpResponse.json([{ ...FW, has_ca_bundle: true }])),
      http.patch("/api/v1/firewalls/:id", async ({ request }) => {
        patches.push((await request.json()) as Record<string, unknown>);
        return HttpResponse.json(FW);
      }),
    );
    renderApp(<App />, "/administration/firewalls");
    expect(await screen.findByText("edge-1")).toBeInTheDocument();
    expect(screen.getByText("Yes")).toBeInTheDocument(); // has_ca_bundle

    fireEvent.click(screen.getByRole("button", { name: /edit/i }));
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "edge-2" } });
    fireEvent.click(document.querySelector("form button[type=submit]")!);
    await waitFor(() => expect(patches).toEqual([{ name: "edge-2" }]));

    fireEvent.click(await screen.findByRole("button", { name: /disable tls check/i }));
    const confirm = await screen.findByRole("button", { name: "Disable verification" });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/type/i), { target: { value: "edge-1" } });
    fireEvent.click(confirm);
    await waitFor(() => expect(patches).toContainEqual({ verify_tls: false }));
  });
});
