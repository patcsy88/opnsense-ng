import { expect, test } from "@playwright/test";

const USER = { id: "11111111-1111-4111-8111-111111111111", username: "alice", role: "admin" };
const FW = {
  id: "33333333-3333-4333-8333-333333333333",
  name: "edge-1",
  base_url: "https://192.0.2.1",
  verify_tls: true,
  has_ca_bundle: false,
  created_at: "2026-11-10T00:00:00Z",
};

test("login with a mocked API and see the dashboard", async ({ page }) => {
  let loggedIn = false;
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const json = (body: unknown, status = 200) => route.fulfill({ status, json: body });
    switch (url.pathname) {
      case "/api/v1/auth/me":
        return loggedIn ? json(USER) : json({ detail: "Not authenticated" }, 401);
      case "/api/v1/auth/login":
        loggedIn = true;
        return json({ user: USER, csrf_token: "t" });
      case "/api/v1/firewalls":
        return json([FW]);
      case `/api/v1/firewalls/${FW.id}/connectivity`:
        return json({ firewall_id: FW.id, ok: true, status: "ok", message: "Connected", registry_verified: false });
      case `/api/v1/firewalls/${FW.id}/system/status`:
        return json({
          firewall_id: FW.id,
          status: { hostname: "fw.lan", versions: ["OPNsense 26.1"], updates: null, server_time: null, uptime: "3 days", load_average: null, memory_total_bytes: null, memory_used_bytes: null, memory_used_percent: null, cpu_used_percent: null },
          registry_verified: false,
        });
      default:
        return json({ detail: "unmocked" }, 404);
    }
  });

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Username").fill("alice");
  await page.getByLabel("Password").fill("correct horse");
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Reachable")).toBeVisible();
  await expect(page.getByText("fw.lan")).toBeVisible();
  await expect(page.getByText("Unverified API mapping").first()).toBeVisible();

  // Nothing but the theme preference may be persisted client-side.
  const keys = await page.evaluate(() => Object.keys(localStorage));
  expect(keys.every((k) => k === "theme")).toBe(true);
});
