import { expect, test, type Page } from "@playwright/test";
import { Totp } from "./totp";

// Lab-only and read-only: opens the traffic stream (ADR-0023) through Caddy and checks that events
// arrive one by one. Run through scripts/e2e-lab-hosts.sh with LAB_SPEC=lab-traffic-stream.
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

test("traffic stream delivers a sample about every second", async ({ browser }) => {
  test.skip(!USER || !PASSWORD, "run through scripts/e2e-lab-hosts.sh");
  const context = await browser.newContext({ ignoreHTTPSErrors: true, serviceWorkers: "block" });
  const page = await context.newPage();
  await signInAndEnrol(page);
  const list = await (await page.request.get("/api/v1/firewalls")).json();
  const fw = list.find((f: { name: string }) => f.name === FIREWALL);
  expect(fw, `firewall ${FIREWALL} exists`).toBeTruthy();

  const arrivals: { at: number; time: number | null }[] = await page.evaluate(
    (id) =>
      new Promise((resolve, reject) => {
        const out: { at: number; time: number | null }[] = [];
        const es = new EventSource(`/api/v1/firewalls/${id}/traffic/stream`);
        const done = setTimeout(() => {
          es.close();
          resolve(out);
        }, 8000);
        es.onmessage = (e) => out.push({ at: performance.now(), time: JSON.parse(e.data).time });
        es.onerror = () => {
          clearTimeout(done);
          es.close();
          reject(new Error("stream error"));
        };
      }),
    fw.id,
  );
  const gaps = arrivals.slice(1).map((a, i) => a.at - (arrivals[i]?.at ?? a.at));
  console.log(`STREAM events=${arrivals.length} gaps_ms=${gaps.map(Math.round).join(",")}`);
  const newer = arrivals.slice(1).filter((a, i) => (a.time ?? 0) > (arrivals[i]?.time ?? 0)).length;
  console.log(`STREAM samples_with_new_firewall_time=${newer}`);
  expect(arrivals.length).toBeGreaterThanOrEqual(5);
  expect(Math.max(...gaps)).toBeLessThan(2500);
  await context.close();
});
