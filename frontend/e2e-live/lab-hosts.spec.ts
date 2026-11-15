import { expect, test, type Page } from "@playwright/test";
import { pick } from "./select";
import { Totp } from "./totp";

// Lab-only: creates, edits and deletes one throwaway Dnsmasq static host on the lab firewall.
// Run through scripts/e2e-lab-hosts.sh, which makes a temporary admin. Skipped otherwise.
const USER = process.env.E2E_LAB_USER ?? "";
const PASSWORD = process.env.E2E_LAB_PASSWORD ?? "";
const FIREWALL = process.env.E2E_LAB_FIREWALL ?? "OPNsense.test";

test.describe.configure({ mode: "serial" });
let page: Page;
test.beforeAll(async ({ browser }) => {
  if (!USER || !PASSWORD) return;
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    serviceWorkers: "block",
  });
  page = await context.newPage();
  await signInAndEnrol(page);
});
test.afterAll(async () => {
  await page?.context().close();
});

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
  await page.goto("/dhcp");
  await pick(page, page.getByRole("combobox", { name: "Firewall" }), FIREWALL);
  // The page opens on Kea when Dnsmasq is stopped, so pick the engine explicitly.
  await page.getByRole("tab", { name: "Dnsmasq" }).click();
  await page.getByRole("tab", { name: "Static hosts" }).click();
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

test("Dnsmasq static host: create, edit, delete on the lab firewall", async () => {
  test.skip(!USER || !PASSWORD, "run through scripts/e2e-lab-hosts.sh");
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

const OVERRIDE = "zz-adr17.test";
const OVERRIDE_DESCRIPTION = "ADR17 lab test override";

test("Dnsmasq domain override: create, edit, delete on the lab firewall", async () => {
  test.skip(!USER || !PASSWORD, "run through scripts/e2e-lab-hosts.sh");
  const options = await (await page.request.get("/api/v1/firewalls")).json();
  const fw = options.find((f: { name: string }) => f.name === FIREWALL);
  expect(fw?.allow_writes, `allow_writes is on for ${FIREWALL}`).toBe(true);

  const overrideRow = () =>
    page.getByRole("row", { name: new RegExp(OVERRIDE) });
  const open = async () => {
    await page.goto("/dns");
    await pick(page, page.getByRole("combobox", { name: "Firewall" }), FIREWALL);
    await page.getByRole("tab", { name: "Dnsmasq" }).click();
  };
  const submit = async (server: string) => {
    await page.getByLabel("Domain", { exact: true }).fill(OVERRIDE);
    await page.getByLabel("DNS server IP", { exact: true }).fill(server);
    await page
      .getByLabel("Description", { exact: true })
      .fill(OVERRIDE_DESCRIPTION);
    await page.getByRole("button", { name: "Create change request" }).click();
    await page.waitForURL(/\/changes\//);
  };

  await open();
  await expect(
    page.getByRole("button", { name: "New override" }),
  ).toBeVisible();
  await expect(page.getByText("Loading…")).toHaveCount(0);
  if ((await overrideRow().count()) > 0) {
    // A throwaway left by an interrupted run: remove it through the same reviewed flow.
    await page
      .getByRole("button", { name: /^Delete override / })
      .first()
      .click();
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "Create change request" })
      .click();
    await page.waitForURL(/\/changes\//);
    await review(page, OVERRIDE_DESCRIPTION);
    await open();
  }
  await expect(overrideRow()).toHaveCount(0);

  await page.getByRole("button", { name: "New override" }).click();
  await submit("192.0.2.53");
  await review(page, OVERRIDE_DESCRIPTION);
  await open();
  await expect(overrideRow()).toContainText("192.0.2.53");

  await page
    .getByRole("button", { name: `Edit override ${OVERRIDE_DESCRIPTION}` })
    .click();
  await page.getByLabel("DNS server IP", { exact: true }).fill("192.0.2.54");
  await page.getByRole("button", { name: "Create change request" }).click();
  await page.waitForURL(/\/changes\//);
  await review(page, OVERRIDE_DESCRIPTION);
  await open();
  await expect(overrideRow()).toContainText("192.0.2.54");

  await page
    .getByRole("button", { name: `Delete override ${OVERRIDE_DESCRIPTION}` })
    .click();
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Create change request" })
    .click();
  await page.waitForURL(/\/changes\//);
  await review(page, OVERRIDE_DESCRIPTION);
  await open();
  await expect(overrideRow()).toHaveCount(0);
});

const UNBOUND_HOST = "zz-adr18";
const UNBOUND_DOMAIN = "adr18.test";
const UNBOUND_DESCRIPTION = "ADR18 lab test host";

test("Unbound host override: create, edit, disable, delete on the lab firewall", async () => {
  test.skip(!USER || !PASSWORD, "run through scripts/e2e-lab-hosts.sh");
  const options = await (await page.request.get("/api/v1/firewalls")).json();
  const fw = options.find((f: { name: string }) => f.name === FIREWALL);
  expect(fw?.allow_writes, `allow_writes is on for ${FIREWALL}`).toBe(true);

  const row = () => page.getByRole("row", { name: new RegExp(UNBOUND_HOST) });
  const open = async () => {
    await page.goto("/dns");
    await pick(page, page.getByRole("combobox", { name: "Firewall" }), FIREWALL);
    await page.getByRole("tab", { name: "Host overrides" }).click();
  };
  const stageDialogAction = async (name: string) => {
    await page.getByRole("button", { name }).click();
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "Create change request" })
      .click();
    await page.waitForURL(/\/changes\//);
  };

  await open();
  await expect(row()).toHaveCount(0);

  // Create
  await page.getByRole("button", { name: "New host override" }).click();
  await page.getByLabel("Host name", { exact: true }).fill(UNBOUND_HOST);
  await page.getByLabel("Domain", { exact: true }).fill(UNBOUND_DOMAIN);
  await page.getByLabel("IP address", { exact: true }).fill("192.0.2.80");
  await page
    .getByLabel("Description", { exact: true })
    .fill(UNBOUND_DESCRIPTION);
  await page.getByRole("button", { name: "Create change request" }).click();
  await page.waitForURL(/\/changes\//);
  await review(page);
  await open();
  await expect(row()).toContainText("192.0.2.80");

  // Edit
  await page
    .getByRole("button", { name: `Edit host override ${UNBOUND_DESCRIPTION}` })
    .click();
  await page.getByLabel("IP address", { exact: true }).fill("192.0.2.81");
  await page.getByRole("button", { name: "Create change request" }).click();
  await page.waitForURL(/\/changes\//);
  await review(page);
  await open();
  await expect(row()).toContainText("192.0.2.81");

  // Disable (normal risk)
  await stageDialogAction(`Disable host override ${UNBOUND_DESCRIPTION}`);
  await review(page);
  await open();
  await expect(row()).toContainText("Disabled");

  // Enable again
  await stageDialogAction(`Enable host override ${UNBOUND_DESCRIPTION}`);
  await review(page);
  await open();
  await expect(row()).not.toContainText("Disabled");

  // Delete (high risk: the description is typed)
  await stageDialogAction(`Delete host override ${UNBOUND_DESCRIPTION}`);
  await review(page, UNBOUND_DESCRIPTION);
  await open();
  await expect(row()).toHaveCount(0);
});

const FORWARD_DOMAIN = "zz-adr18-fwd.test";
const FORWARD_DESCRIPTION = "ADR18 lab test forward";

test("Unbound domain forward: create, edit, disable, enable, delete on the lab firewall", async () => {
  test.skip(!USER || !PASSWORD, "run through scripts/e2e-lab-hosts.sh");
  const options = await (await page.request.get("/api/v1/firewalls")).json();
  const fw = options.find((f: { name: string }) => f.name === FIREWALL);
  expect(fw?.allow_writes, `allow_writes is on for ${FIREWALL}`).toBe(true);

  const row = () => page.getByRole("row", { name: new RegExp(FORWARD_DOMAIN) });
  const open = async () => {
    await page.goto("/dns");
    await pick(page, page.getByRole("combobox", { name: "Firewall" }), FIREWALL);
    await page.getByRole("tab", { name: "Domain forwards" }).click();
  };
  const stageDialogAction = async (name: string) => {
    await page.getByRole("button", { name }).click();
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "Create change request" })
      .click();
    await page.waitForURL(/\/changes\//);
  };

  await open();
  await expect(row()).toHaveCount(0);

  await page.getByRole("button", { name: "New forward" }).click();
  await page.getByLabel("Domain", { exact: true }).fill(FORWARD_DOMAIN);
  await page.getByLabel("DNS server IP", { exact: true }).fill("192.0.2.53");
  await page
    .getByLabel("Description", { exact: true })
    .fill(FORWARD_DESCRIPTION);
  await page.getByRole("button", { name: "Create change request" }).click();
  await page.waitForURL(/\/changes\//);
  await review(page, FORWARD_DESCRIPTION);
  await open();
  await expect(row()).toContainText("192.0.2.53");

  await page
    .getByRole("button", { name: `Edit forward ${FORWARD_DESCRIPTION}` })
    .click();
  await page.getByLabel("DNS server IP", { exact: true }).fill("192.0.2.54");
  await page.getByRole("button", { name: "Create change request" }).click();
  await page.waitForURL(/\/changes\//);
  await review(page, FORWARD_DESCRIPTION);
  await open();
  await expect(row()).toContainText("192.0.2.54");

  await stageDialogAction(`Disable forward ${FORWARD_DESCRIPTION}`);
  await review(page, FORWARD_DESCRIPTION);
  await open();
  await expect(row()).toContainText("Disabled");

  await stageDialogAction(`Enable forward ${FORWARD_DESCRIPTION}`);
  await review(page, FORWARD_DESCRIPTION);
  await open();
  await expect(row()).not.toContainText("Disabled");

  await stageDialogAction(`Delete forward ${FORWARD_DESCRIPTION}`);
  await review(page, FORWARD_DESCRIPTION);
  await open();
  await expect(row()).toHaveCount(0);
});

const PEER = "zz-adr19-peer";
const TUNNEL = "zz-adr19-wg";

test("WireGuard tunnel and peer: create, edit, toggle, delete on the lab firewall", async () => {
  test.skip(!USER || !PASSWORD, "run through scripts/e2e-lab-hosts.sh");
  const options = await (await page.request.get("/api/v1/firewalls")).json();
  const fw = options.find((f: { name: string }) => f.name === FIREWALL);
  expect(fw?.allow_writes, `allow_writes is on for ${FIREWALL}`).toBe(true);

  // A fresh random public key; no private key exists for it anywhere.
  const pubkey = Buffer.from(
    Array.from({ length: 32 }, () => Math.floor(Math.random() * 256)),
  ).toString("base64");

  const tunnelRow = () => page.getByRole("row", { name: new RegExp(TUNNEL) });
  const peerRow = () => page.getByRole("row", { name: new RegExp(PEER) });
  const open = async (tab: "Peers" | "Tunnels") => {
    await page.goto("/vpn");
    await pick(page, page.getByRole("combobox", { name: "Firewall" }), FIREWALL);
    await page.getByRole("tab", { name: tab }).click();
  };
  const stageDialogAction = async (name: string) => {
    await page.getByRole("button", { name }).click();
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "Create change request" })
      .click();
    await page.waitForURL(/\/changes\//);
  };
  const submit = async () => {
    await page.getByRole("button", { name: "Create change request" }).click();
    await page.waitForURL(/\/changes\//);
  };

  await open("Tunnels");
  await expect(tunnelRow()).toHaveCount(0);

  // Create a tunnel (always high risk: the name is typed). No key is sent.
  await page.getByRole("button", { name: "New tunnel" }).click();
  await page.getByLabel("Name", { exact: true }).fill(TUNNEL);
  await page.getByLabel("Listen port", { exact: true }).fill("51899");
  await page.getByLabel("Tunnel address", { exact: true }).fill("10.99.0.1/24");
  await submit();
  await review(page, TUNNEL);
  await open("Tunnels");
  await expect(tunnelRow()).toContainText("10.99.0.1/24");
  await expect(tunnelRow()).toContainText("51899");

  // Edit the tunnel (MTU)
  await page.getByRole("button", { name: `Edit tunnel ${TUNNEL}` }).click();
  await page.getByLabel("MTU (optional)", { exact: true }).fill("1380");
  await submit();
  await review(page, TUNNEL);

  // Peer: create (normal risk) inside the new tunnel
  await open("Peers");
  await expect(peerRow()).toHaveCount(0);
  await page.getByRole("button", { name: "New peer" }).click();
  await page.getByLabel("Name", { exact: true }).fill(PEER);
  await page
    .getByLabel("Tunnel address", { exact: true })
    .fill("10.99.0.250/32");
  await page.getByLabel("Public key", { exact: true }).fill(pubkey);
  await page.getByLabel(new RegExp(TUNNEL)).check();
  await submit();
  await review(page);
  await open("Peers");
  await expect(peerRow()).toContainText("10.99.0.250/32");

  // Peer: edit keepalive (normal risk)
  await page.getByRole("button", { name: `Edit peer ${PEER}` }).click();
  await page.getByLabel("Keepalive (optional)", { exact: true }).fill("25");
  await submit();
  await review(page);

  // Peer: disable (high risk), enable (normal risk)
  await open("Peers");
  await stageDialogAction(`Disable peer ${PEER}`);
  await review(page, PEER);
  await open("Peers");
  await expect(peerRow()).toContainText("Disabled");
  await stageDialogAction(`Enable peer ${PEER}`);
  await review(page);
  await open("Peers");
  await expect(peerRow()).not.toContainText("Disabled");

  // Tunnel: disable and enable (high risk)
  await open("Tunnels");
  await stageDialogAction(`Disable tunnel ${TUNNEL}`);
  await review(page, TUNNEL);
  await open("Tunnels");
  await expect(tunnelRow()).toContainText("Disabled");
  await stageDialogAction(`Enable tunnel ${TUNNEL}`);
  await review(page, TUNNEL);

  // Delete the peer, then the tunnel
  await open("Peers");
  await stageDialogAction(`Delete peer ${PEER}`);
  await review(page, PEER);
  await open("Peers");
  await expect(peerRow()).toHaveCount(0);
  await open("Tunnels");
  await stageDialogAction(`Delete tunnel ${TUNNEL}`);
  await review(page, TUNNEL);
  await open("Tunnels");
  await expect(tunnelRow()).toHaveCount(0);
});
