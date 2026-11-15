import { expect, test, type Page } from "@playwright/test";
import { Totp } from "./totp";

// Lab-only and read-only: fetches the Kea views (ADR-0020) and prints what the app returns.
// Run through scripts/e2e-lab-hosts.sh with LAB_SPEC=lab-kea. Skipped otherwise.
const USER = process.env.E2E_LAB_USER ?? "";
const PASSWORD = process.env.E2E_LAB_PASSWORD ?? "";
const FIREWALL = process.env.E2E_LAB_FIREWALL ?? "OPNsense.test";

async function signInAndEnrol(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username", { exact: true }).fill(USER);
  await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/account/);
  await page.getByLabel("Confirm your password").fill(PASSWORD);
  await page.getByRole("button", { name: "Continue" }).click();
  const secret = (await page.getByLabel("Setup key").innerText()).trim();
  await page
    .getByLabel("Code from your app", { exact: true })
    .fill(await new Totp(secret).next());
  await page
    .getByRole("button", { name: "Turn on two-factor authentication" })
    .click();
  await expect(page.getByLabel("Recovery codes")).toBeVisible();
  await page.getByRole("button", { name: "I have saved these codes" }).click();
}

test("Kea views read from the lab firewall", async ({ browser }) => {
  test.skip(!USER || !PASSWORD, "run through scripts/e2e-lab-hosts.sh");
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    serviceWorkers: "block",
  });
  const page = await context.newPage();
  await signInAndEnrol(page);
  const list = await (await page.request.get("/api/v1/firewalls")).json();
  const fw = list.find((f: { name: string }) => f.name === FIREWALL);
  expect(fw, `firewall ${FIREWALL} exists`).toBeTruthy();
  for (const view of [
    "services",
    "kea/subnets",
    "kea/reservations",
    "kea/leases",
  ]) {
    const r = await page.request.get(`/api/v1/firewalls/${fw.id}/${view}`);
    const body = await r.text();
    console.log(`KEA ${view} -> ${r.status()} ${body.slice(0, 1500)}`);
  }
  await context.close();
});
