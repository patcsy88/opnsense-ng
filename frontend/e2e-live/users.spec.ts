import { expect, test, type Browser, type Page } from "@playwright/test";
import { Totp } from "./totp";

const ADMIN = "e2e-admin";
const USER = "e2e-user";
const NEW_PASSWORD = "e2e-brand-new-passphrase-1";
const adminPassword = process.env.E2E_ADMIN_PASSWORD ?? "";

async function signIn(
  page: Page,
  username: string,
  password: string,
  totp?: Totp,
) {
  await page.goto("/login");
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  if (totp) {
    await page.getByLabel("Authentication code").fill(await totp.next());
    await page.getByRole("button", { name: "Verify" }).click();
  }
  try {
    await page.waitForURL((u) => !u.pathname.startsWith("/login"), {
      timeout: 15_000,
    });
  } catch {
    const shown = await page.getByRole("alert").allInnerTexts();
    throw new Error(
      `sign-in as ${username} stayed on login: ${shown.join(" | ")}`,
    );
  }
}

async function enrol(page: Page, password: string): Promise<Totp> {
  await expect(page).toHaveURL(/\/account/);
  await page.getByLabel("Confirm your password").fill(password);
  await page.getByRole("button", { name: "Continue" }).click();
  const secret = (await page.getByLabel("Setup key").innerText()).trim();
  const totp = new Totp(secret);
  await page
    .getByLabel("Code from your app", { exact: true })
    .fill(await totp.next());
  await page
    .getByRole("button", { name: "Turn on two-factor authentication" })
    .click();
  await expect(page.getByLabel("Recovery codes")).toBeVisible();
  await page.getByRole("button", { name: "I have saved these codes" }).click();
  return totp;
}

async function newPage(browser: Browser): Promise<Page> {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    serviceWorkers: "block",
  });
  return context.newPage();
}

const row = (page: Page, name: string) =>
  page.getByRole("row", { name: new RegExp(name) });

test("user management, start to finish", async ({ browser }) => {
  test.skip(!adminPassword, "run through scripts/e2e-live.sh");

  // The admin has no MFA yet: the session is restricted until they enrol.
  const admin = await newPage(browser);
  await signIn(admin, ADMIN, adminPassword);
  const adminTotp = await enrol(admin, adminPassword);

  // Create a user and read the one-time password.
  await admin.goto("/administration/users");
  await admin.getByLabel("Username", { exact: true }).fill(USER);
  await admin.locator("form select").selectOption("read_only");
  await admin.getByRole("button", { name: "Create user" }).click();
  const temp = (await admin.getByTestId("temp-password").innerText()).trim();
  expect(temp).toHaveLength(20);
  await admin.getByRole("button", { name: "Done" }).click();
  await expect(admin.getByTestId("temp-password")).toHaveCount(0);
  await expect(row(admin, USER)).toContainText("Temporary password");

  // The new user is forced to change the password, then to enrol MFA.
  const user = await newPage(browser);
  await signIn(user, USER, temp);
  await expect(user).toHaveURL(/\/account/);
  expect((await user.request.get("/api/v1/firewalls")).status()).toBe(403);
  await user.getByLabel("Temporary password").fill(temp);
  await user.getByLabel("New password", { exact: true }).fill(NEW_PASSWORD);
  await user.getByLabel("Repeat new password").fill(NEW_PASSWORD);
  await user.getByRole("button", { name: "Change password" }).click();
  await expect(user.getByText("Password changed.")).toBeVisible();
  let userTotp = await enrol(user, NEW_PASSWORD);
  expect((await user.request.get("/api/v1/firewalls/options")).status()).toBe(
    200,
  );

  // A role change ends the user's session.
  await admin.reload();
  await row(admin, USER)
    .getByLabel(`Role for ${USER}`)
    .selectOption("network_admin");
  await expect(row(admin, USER).getByLabel(`Role for ${USER}`)).toHaveValue(
    "network_admin",
  );
  await expect
    .poll(async () => (await user.request.get("/api/v1/auth/me")).status())
    .toBe(401);

  // Deactivate: cannot sign in. Reactivate: can again.
  await signIn(user, USER, NEW_PASSWORD, userTotp);
  await row(admin, USER).getByRole("button", { name: "Deactivate" }).click();
  await admin
    .getByRole("alertdialog")
    .getByRole("button", { name: "Deactivate" })
    .click();
  await expect(row(admin, USER)).toContainText("Inactive");
  expect((await user.request.get("/api/v1/auth/me")).status()).toBe(401);
  await user.goto("/login");
  await user.getByLabel("Username", { exact: true }).fill(USER);
  await user.getByLabel("Password", { exact: true }).fill(NEW_PASSWORD);
  await user.getByRole("button", { name: "Sign in" }).click();
  await expect(user.getByRole("alert")).toBeVisible();
  await row(admin, USER).getByRole("button", { name: "Reactivate" }).click();
  await admin
    .getByRole("alertdialog")
    .getByRole("button", { name: "Reactivate" })
    .click();
  await expect(row(admin, USER)).toContainText("Active");
  await signIn(user, USER, NEW_PASSWORD, userTotp);

  // An admin cannot deactivate or demote themselves, or the last admin.
  await row(admin, ADMIN).getByRole("button", { name: "Deactivate" }).click();
  const dialog = admin.getByRole("alertdialog");
  await dialog.getByRole("button", { name: "Deactivate" }).click();
  await expect(dialog.getByRole("alert")).toContainText(/own account/);
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await row(admin, ADMIN)
    .getByLabel(`Role for ${ADMIN}`)
    .selectOption("read_only");
  await expect(admin.getByRole("alert").first()).toContainText(/own account/);
  await expect(row(admin, ADMIN).getByLabel(`Role for ${ADMIN}`)).toHaveValue(
    "admin",
  );

  // Reset MFA needs the admin's own password and a current code, and forces re-enrolment.
  await row(admin, USER).getByRole("button", { name: "Reset MFA" }).click();
  const mfaDialog = admin.getByRole("dialog");
  await mfaDialog.getByLabel("Your password").fill("not-my-password-at-all");
  await mfaDialog
    .getByLabel("Your authenticator code")
    .fill(await adminTotp.next());
  await mfaDialog.getByRole("button", { name: "Reset MFA" }).click();
  await expect(mfaDialog.getByRole("alert")).toBeVisible();
  await mfaDialog.getByLabel("Your password").fill(adminPassword);
  await mfaDialog
    .getByLabel("Your authenticator code")
    .fill(await adminTotp.next());
  await mfaDialog.getByRole("button", { name: "Reset MFA" }).click();
  await expect(mfaDialog).toHaveCount(0);
  expect((await user.request.get("/api/v1/auth/me")).status()).toBe(401);
  await signIn(user, USER, NEW_PASSWORD);
  userTotp = await enrol(user, NEW_PASSWORD);
  expect(userTotp).toBeTruthy();

  // Admin resets the password: a fresh temporary password forces another change.
  await admin.reload();
  await row(admin, USER)
    .getByRole("button", { name: "Reset password" })
    .click();
  await admin
    .getByRole("alertdialog")
    .getByRole("button", { name: "Reset password" })
    .click();
  const second = (await admin.getByTestId("temp-password").innerText()).trim();
  expect(second).not.toBe(temp);
  await admin.getByRole("button", { name: "Done" }).click();
  await signIn(user, USER, second, userTotp);
  await expect(user.getByText(/set by an administrator/)).toBeVisible();

  // The audit trail names every step and holds no password.
  const audit = await admin.request.get(
    "/api/v1/audit?action=user.&page_size=200",
  );
  const text = await audit.text();
  for (const action of [
    "user.create",
    "user.role_change",
    "user.deactivate",
    "user.reactivate",
    "user.mfa_reset",
    "user.password_reset",
  ]) {
    expect(text).toContain(action);
  }
  const all = await (
    await admin.request.get("/api/v1/audit?page_size=200")
  ).text();
  for (const secret of [temp, second, NEW_PASSWORD, adminPassword])
    expect(all).not.toContain(secret);
});
