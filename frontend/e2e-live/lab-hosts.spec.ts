import { expect, test, type Page } from "@playwright/test";
import { Totp } from "./totp";

// Lab-only: creates, edits and deletes one throwaway Dnsmasq static host on the lab firewall.
// Run through scripts/e2e-lab-hosts.sh, which makes a temporary admin. Skipped otherwise.
const USER = process.env.E2E_LAB_USER ?? "";
const PASSWORD = process.env.E2E_LAB_PASSWORD ?? "";
const FIREWALL = process.env.E2E_LAB_FIREWALL ?? "OPNsense.test";

const HOST = "zz-adr17-test";
const DOMAIN = "adr17.test";
const DESCRIPTION = "ADR17 lab test host";
const MAC = "aa:bb:cc:00:ad:17";

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

async function chooseFirewall(page: Page): Promise<void> {
  await page.goto("/dhcp/entries");
  await page.locator("select").selectOption({ label: FIREWALL });
}

async function settle(page: Page): Promise<string> {
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
  if (last.status !== "applied") {
    throw new Error(`apply ended as ${last.status}: ${last.failure_message}`);
  }
  return id;
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

const hostRow = (page: Page) =>
  page.getByRole("row", { name: new RegExp(HOST) });

async function fill(page: Page, ips: string): Promise<void> {
  await page.getByLabel("Host name", { exact: true }).fill(HOST);
  await page.getByLabel("Domain", { exact: true }).fill(DOMAIN);
  await page.getByLabel("IP addresses", { exact: true }).fill(ips);
  await page.getByLabel("MAC addresses", { exact: true }).fill(MAC);
  await page.getByLabel("Description", { exact: true }).fill(DESCRIPTION);
}

test("Dnsmasq static host: create, edit, delete on the lab firewall", async ({
  page,
}) => {
  test.skip(!USER || !PASSWORD, "run through scripts/e2e-lab-hosts.sh");
  await signInAndEnrol(page);

  const options = await (await page.request.get("/api/v1/firewalls")).json();
  const fw = options.find((f: { name: string }) => f.name === FIREWALL);
  expect(fw, `firewall ${FIREWALL} exists`).toBeTruthy();
  expect(
    fw.allow_writes,
    `allow_writes is on for ${FIREWALL} (turn it on first)`,
  ).toBe(true);

  await chooseFirewall(page);
  await expect(hostRow(page)).toHaveCount(0);

  // Create
  await page.getByRole("button", { name: "New host" }).click();
  await fill(page, "192.0.2.77");
  await page.getByRole("button", { name: "Create change request" }).click();
  await page.waitForURL(/\/changes\//);
  await review(page);
  await chooseFirewall(page);
  await expect(hostRow(page)).toContainText("192.0.2.77");
  await expect(hostRow(page)).toContainText(MAC);

  // Edit
  await page.getByRole("button", { name: `Edit ${DESCRIPTION}` }).click();
  await page.getByLabel("IP addresses", { exact: true }).fill("192.0.2.78");
  await page.getByRole("button", { name: "Create change request" }).click();
  await page.waitForURL(/\/changes\//);
  await review(page);
  await chooseFirewall(page);
  await expect(hostRow(page)).toContainText("192.0.2.78");

  // Delete (high risk: the description is typed)
  await page.getByRole("button", { name: `Delete ${DESCRIPTION}` }).click();
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Create change request" })
    .click();
  await page.waitForURL(/\/changes\//);
  await review(page, DESCRIPTION);
  await chooseFirewall(page);
  await expect(hostRow(page)).toHaveCount(0);
});
