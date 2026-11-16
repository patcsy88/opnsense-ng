import { expect, test } from "@playwright/test";

const USER = { id: "11111111-1111-4111-8111-111111111111", username: "alice", role: "admin" };
const FW = {
  id: "33333333-3333-4333-8333-333333333333",
  name: "edge-1",
  base_url: "https://192.0.2.1",
  verify_tls: true,
  has_ca_bundle: false,
  allow_writes: false,
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
      case "/api/v1/firewalls/options":
        return json([{ id: FW.id, name: FW.name }]);
      case "/api/v1/firewalls":
        return json([FW]);
      case "/api/v1/firewalls/overview":
        return json({
          firewalls: [
            { id: FW.id, name: FW.name, reachable: true, status: "ok", message: "Connected", hostname: "fw.lan", version: "OPNsense 26.1", uptime: "3 days", cpu_used_percent: 10, memory_used_percent: 20, disk_used_percent: 30, checked_at: 1 },
          ],
          truncated: false,
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

  // Nothing but the theme preference may be persisted client-side.
  const keys = await page.evaluate(() => Object.keys(localStorage));
  expect(keys.every((k) => k === "theme")).toBe(true);
});
