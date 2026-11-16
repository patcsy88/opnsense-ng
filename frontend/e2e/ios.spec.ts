import { devices, expect, test } from "@playwright/test";

// iPhone profile on WebKit: the closest check available without a device (ADR-free PWA polish).
test.use({ ...devices["iPhone 14"] });

const USER = { id: "11111111-1111-4111-8111-111111111111", username: "alice", role: "admin" };
const FW = { id: "33333333-3333-4333-8333-333333333333", name: "edge-1" };

test("the installed-app metadata is present", async ({ page, request }) => {
  await page.route("**/api/v1/**", (route) => route.fulfill({ status: 401, json: { detail: "Not authenticated" } }));
  await page.goto("/login");
  const meta = (name: string) => page.locator(`meta[name="${name}"]`).getAttribute("content");
  expect(await meta("apple-mobile-web-app-capable")).toBe("yes");
  expect(await meta("apple-mobile-web-app-title")).toBe("FW Manager");
  expect(await meta("viewport")).toContain("viewport-fit=cover");
  await expect(page.locator('link[rel="apple-touch-icon"]')).toHaveCount(1);
  const manifest = await (await request.get("/manifest.webmanifest")).json();
  expect(manifest.display).toBe("standalone");
  expect(manifest.start_url).toBe("/");
});

test("the signed-in app fits a phone screen with its quick navigation", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const json = (body: unknown, status = 200) => route.fulfill({ status, json: body });
    switch (new URL(route.request().url()).pathname) {
      case "/api/v1/auth/me":
        return json(USER);
      case "/api/v1/firewalls/options":
        return json([FW]);
      case "/api/v1/firewalls/overview":
        return json({
          firewalls: [
            { ...FW, reachable: true, status: "ok", message: "Connected", hostname: "fw.lan", version: "OPNsense 26.1", uptime: "3 days", cpu_used_percent: 10, memory_used_percent: 20, disk_used_percent: 30, checked_at: 1 },
          ],
          truncated: false,
        });
      default:
        return json({ detail: "unmocked" }, 404);
    }
  });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("fw.lan")).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Quick" })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});

test("form fields are at least 16px so iOS does not zoom on focus", async ({ page }) => {
  await page.route("**/api/v1/**", (route) => route.fulfill({ status: 401, json: { detail: "Not authenticated" } }));
  await page.goto("/login");
  for (const label of ["Username", "Password"]) {
    const size = await page.getByLabel(label).evaluate((el) => parseFloat(getComputedStyle(el).fontSize));
    expect(size, label).toBeGreaterThanOrEqual(16);
  }
});
