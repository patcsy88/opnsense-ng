import { expect, test, type Page } from "@playwright/test";
import { pick } from "./select";
import { Totp } from "./totp";

// Lab-only. Writes ONE throwaway Kea reservation (ADR-0021) through the staged flow: create, edit
// the hostname, delete. The IP is outside the dynamic pool and the MAC is locally administered.
// Run: LAB_SPEC=kea-write ./scripts/e2e-lab-hosts.sh. Needs allow_writes on the lab firewall.
const USER = process.env.E2E_LAB_USER ?? "";
const PASSWORD = process.env.E2E_LAB_PASSWORD ?? "";
const FIREWALL = process.env.E2E_LAB_FIREWALL ?? "OPNsense.test";

const IP = "192.168.1.50";
const MAC = "02:00:00:ad:21:50";
const HOST = "zz-adr21";
const HOST_EDITED = "zz-adr21-edit";

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

async function settle(page: Page): Promise<void> {
  const id = /\/changes\/([0-9a-f-]{36})/.exec(page.url())?.[1] ?? "";
  expect(id).not.toBe("");
  let last = { status: "", failure_message: "" as string | null };
  await expect
    .poll(
      async () => {
        last = await (await page.request.get(`/api/v1/changes/${id}`)).json();
        return last.status;
      },
      { timeout: 60_000 },
    )
    .not.toMatch(/^(applying|approved)$/);
  console.log(`KEA-WRITE change ${id} ended ${last.status}`);
  if (last.status !== "applied") {
    throw new Error(`apply ended as ${last.status}: ${last.failure_message}`);
  }
}

async function review(page: Page, confirm?: string): Promise<void> {
  await page.getByRole("button", { name: "Submit for review" }).click();
  await page.getByRole("button", { name: "Approve" }).click();
  await page.getByRole("button", { name: "Apply to firewall…" }).click();
  const dialog = page.getByRole("alertdialog");
  if (confirm) await dialog.getByLabel(/Type/).fill(confirm);
  await dialog.getByRole("button", { name: "Apply now" }).click();
  await settle(page);
}

test("Kea reservation: create, edit, delete on the lab firewall", async ({
  browser,
}) => {
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
  expect(fw.allow_writes, `allow_writes is on for ${FIREWALL}`).toBe(true);

  const row = () => page.getByRole("row", { name: new RegExp(IP) });
  const open = async () => {
    await page.goto("/dhcp");
    await pick(page, page.getByRole("button", { name: /Firewall/ }), FIREWALL);
    await page.getByRole("tab", { name: "Kea", exact: true }).click();
    await page.getByRole("tab", { name: "Reservations" }).click();
    await expect(page.getByText("Loading…")).toHaveCount(0);
  };
  const deleteIt = async () => {
    await page.getByRole("button", { name: `Delete ${IP}` }).click();
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "Create change request" })
      .click();
    await page.waitForURL(/\/changes\//);
    await review(page, IP);
    await open();
  };

  await open();
  await expect(
    page.getByRole("button", { name: "New reservation" }),
  ).toBeEnabled();
  if ((await row().count()) > 0) {
    // A throwaway left by an interrupted run: remove it through the same reviewed flow.
    await deleteIt();
  }
  await expect(row()).toHaveCount(0);

  // Create (normal risk)
  await page.getByRole("button", { name: "New reservation" }).click();
  await page.getByLabel("IP address", { exact: true }).fill(IP);
  await page.getByLabel("MAC address", { exact: true }).fill(MAC);
  await page.getByLabel("Hostname (optional)").fill(HOST);
  await page.getByRole("button", { name: "Create change request" }).click();
  await page.waitForURL(/\/changes\//);
  await review(page);
  await open();
  await expect(row()).toContainText(MAC);
  await expect(row()).toContainText(HOST);

  // Edit the hostname only (normal risk)
  await page.getByRole("button", { name: `Edit ${IP}` }).click();
  await page.getByLabel("Hostname (optional)").fill(HOST_EDITED);
  await page.getByRole("button", { name: "Create change request" }).click();
  await page.waitForURL(/\/changes\//);
  await review(page);
  await open();
  await expect(row()).toContainText(HOST_EDITED);

  // Delete (high risk: the IP is typed)
  await deleteIt();
  await expect(row()).toHaveCount(0);

  await context.close();
});
