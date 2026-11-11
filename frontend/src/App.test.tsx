import { fireEvent, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "./App";
import { server } from "@/test/server";
import { ADMIN, FW, READER, renderApp } from "@/test/utils";

const okStatus = {
  firewall_id: FW.id,
  status: { hostname: "fw.lan", versions: ["OPNsense 26.1"], updates: null, server_time: null,
    uptime: "3 days",
    load_average: "0.10, 0.20, 0.30",
    memory_total_bytes: 8589934592,
    memory_used_bytes: 2147483648,
    memory_used_percent: 25,
    cpu_used_percent: 37.5,
    disk_total_bytes: 21474836480,
    disk_used_bytes: 5368709120,
    disk_used_percent: 25,
  },
  registry_verified: false,
};

function mockSession(user: typeof ADMIN | typeof READER | null) {
  server.use(
    http.get("/api/v1/auth/me", () =>
      user ? HttpResponse.json(user) : HttpResponse.json({ detail: "Not authenticated" }, { status: 401 }),
    ),
  );
}

describe("auth flow", () => {
  it("redirects to login on 401 bootstrap", async () => {
    mockSession(null);
    renderApp(<App />, "/administration");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("logs in then shows the dashboard", async () => {
    mockSession(null);
    server.use(
      http.post("/api/v1/auth/login", () => HttpResponse.json({ user: ADMIN, csrf_token: "t" })),
      http.get("/api/v1/firewalls", () => HttpResponse.json([])),
    );
    renderApp(<App />, "/");
    fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
  });

  it("shows invalid credentials and clears the password field", async () => {
    mockSession(null);
    server.use(
      http.post("/api/v1/auth/login", () =>
        HttpResponse.json({ detail: "Invalid username or password" }, { status: 401 }),
      ),
    );
    renderApp(<App />, "/login");
    fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "bad" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid username or password");
    expect(screen.getByLabelText("Password")).toHaveValue("");
  });

  it("shows a Retry-After message on 429", async () => {
    mockSession(null);
    server.use(
      http.post("/api/v1/auth/login", () =>
        HttpResponse.json({ detail: "x" }, { status: 429, headers: { "Retry-After": "30" } }),
      ),
    );
    renderApp(<App />, "/login");
    fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "a" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "b" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Try again in 30 seconds");
  });

  it("shows a retry state when the server is unreachable at bootstrap", async () => {
    server.use(http.get("/api/v1/auth/me", () => HttpResponse.error()));
    renderApp(<App />, "/");
    expect(await screen.findByText("Server unreachable")).toBeInTheDocument();
    mockSession(ADMIN);
    server.use(http.get("/api/v1/firewalls", () => HttpResponse.json([])));
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
  });

  it("returns to login when a later request gets 401", async () => {
    mockSession(ADMIN);
    server.use(http.get("/api/v1/firewalls", () => new HttpResponse(null, { status: 401 })));
    renderApp(<App />, "/");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });
});

describe("role-based rendering", () => {
  it("admin sees the connections link and detailed connectivity", async () => {
    mockSession(ADMIN);
    server.use(
      http.get("/api/v1/firewalls", () => HttpResponse.json([FW])),
      http.get("/api/v1/firewalls/:id/connectivity", () =>
        HttpResponse.json({ firewall_id: FW.id, ok: false, status: "tls_error", message: "bad cert", registry_verified: true }),
      ),
      http.get("/api/v1/firewalls/:id/system/status", () => HttpResponse.json(okStatus)),
    );
    renderApp(<App />, "/");
    expect(await screen.findByText("tls_error")).toBeInTheDocument();
    expect(await screen.findByText("fw.lan")).toBeInTheDocument();
    expect(await screen.findByText("Unverified API mapping")).toBeInTheDocument();
    expect(await screen.findByText("2048 MB of 8192 MB (25%)")).toBeInTheDocument();
    expect(await screen.findByText("0.10, 0.20, 0.30")).toBeInTheDocument();
    expect(await screen.findByText("37.5%")).toBeInTheDocument();
    expect(await screen.findByText("5.0 GB of 20.0 GB (25%)")).toBeInTheDocument();
  });

  it("read-only user gets the collapsed status and no firewall list call", async () => {
    mockSession(READER);
    let listed = false;
    server.use(
      http.get("/api/v1/firewalls", () => {
        listed = true;
        return HttpResponse.json([]);
      }),
      http.get("/api/v1/firewalls/:id/connectivity", () =>
        HttpResponse.json({ firewall_id: FW.id, ok: false, status: "unreachable", message: "Firewall is unreachable", registry_verified: true }),
      ),
      http.get("/api/v1/firewalls/:id/system/status", () => HttpResponse.json(okStatus)),
    );
    renderApp(<App />, `/?fw=${FW.id}`);
    expect(await screen.findByText("Firewall is unreachable")).toBeInTheDocument();
    expect(screen.queryByText("tls_error")).not.toBeInTheDocument();
    expect(listed).toBe(false);
  });

  it("read-only user is blocked from the connections page", async () => {
    mockSession(READER);
    renderApp(<App />, "/administration/firewalls");
    expect(await screen.findByText("Not permitted")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /add firewall/i })).not.toBeInTheDocument();
  });

  it("unimplemented sections render the Planned placeholder", async () => {
    mockSession(ADMIN);
    renderApp(<App />, "/vpn");
    expect(await screen.findByRole("heading", { name: "VPN" })).toBeInTheDocument();
    expect(screen.getByText("This section is not implemented yet.")).toBeInTheDocument();
  });
});
