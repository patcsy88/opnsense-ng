import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, READER, renderApp } from "@/test/utils";

const ANN = "33333333-3333-4333-8333-333333333333";

const row = (over: object = {}) => ({
  id: ANN,
  username: "ann",
  role: "read_only",
  is_active: true,
  mfa_enabled: true,
  must_change_password: false,
  created_at: "2026-11-01T10:00:00+00:00",
  sessions: 1,
  ...over,
});

const ME = { ...ADMIN, mfa_enabled: true };

function setup(rows: object[] = [row()]) {
  document.cookie = "csrf_token=tok; path=/";
  const posts: { path: string; body: unknown }[] = [];
  server.use(
    http.get("/api/v1/auth/me", () => HttpResponse.json(ME)),
    http.get("/api/v1/users", () => HttpResponse.json(rows)),
  );
  return posts;
}

describe("Users page", () => {
  it("lists accounts without any secrets", async () => {
    setup([
      row(),
      row({
        id: "44444444-4444-4444-8444-444444444444",
        username: "zed",
        is_active: false,
      }),
    ]);
    renderApp(<App />, "/administration/users");
    expect(await screen.findByText("ann")).toBeInTheDocument();
    expect(screen.getByText("zed")).toBeInTheDocument();
    expect(screen.getByText("Inactive")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Reactivate" }),
    ).toBeInTheDocument();
  });

  it("shows the temporary password once after creating a user", async () => {
    let sent: unknown = null;
    setup([]);
    server.use(
      http.post("/api/v1/users", async ({ request }) => {
        sent = await request.json();
        return HttpResponse.json(
          {
            user: row({ must_change_password: true }),
            temporary_password: "Abcd2345Efgh6789Jklm",
          },
          { status: 201 },
        );
      }),
    );
    renderApp(<App />, "/administration/users");
    fireEvent.change(await screen.findByLabelText("Username"), {
      target: { value: "ann" },
    });
    fireEvent.change(screen.getByLabelText("Role"), {
      target: { value: "network_admin" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create user" }));
    expect(await screen.findByTestId("temp-password")).toHaveTextContent(
      "Abcd2345Efgh6789Jklm",
    );
    expect(sent).toEqual({ username: "ann", role: "network_admin" });
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() =>
      expect(screen.queryByTestId("temp-password")).not.toBeInTheDocument(),
    );
  });

  it("changes a role", async () => {
    let sent: unknown = null;
    setup();
    server.use(
      http.post(`/api/v1/users/${ANN}/role`, async ({ request }) => {
        sent = await request.json();
        return HttpResponse.json(row({ role: "security_admin" }));
      }),
    );
    renderApp(<App />, "/administration/users");
    fireEvent.change(await screen.findByLabelText("Role for ann"), {
      target: { value: "security_admin" },
    });
    await waitFor(() => expect(sent).toEqual({ role: "security_admin" }));
  });

  it("shows the last-admin refusal when deactivating", async () => {
    setup();
    server.use(
      http.post(`/api/v1/users/${ANN}/deactivate`, () =>
        HttpResponse.json(
          { detail: "The last active administrator cannot be changed" },
          { status: 409 },
        ),
      ),
    );
    renderApp(<App />, "/administration/users");
    fireEvent.click(await screen.findByRole("button", { name: "Deactivate" }));
    const dialog = await screen.findByRole("alertdialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Deactivate" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      /last active administrator/,
    );
  });

  it("shows the new temporary password after a reset", async () => {
    setup();
    server.use(
      http.post(`/api/v1/users/${ANN}/reset-password`, () =>
        HttpResponse.json({
          user: row({ must_change_password: true }),
          temporary_password: "Zzzz2345Yyyy6789Wwww",
        }),
      ),
    );
    renderApp(<App />, "/administration/users");
    fireEvent.click(
      await screen.findByRole("button", { name: "Reset password" }),
    );
    const dialog = await screen.findByRole("alertdialog");
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Reset password" }),
    );
    expect(await screen.findByTestId("temp-password")).toHaveTextContent(
      "Zzzz2345Yyyy6789Wwww",
    );
  });

  it("sends the admin's password and code to reset MFA", async () => {
    let sent: unknown = null;
    setup();
    server.use(
      http.post(`/api/v1/users/${ANN}/reset-mfa`, async ({ request }) => {
        sent = await request.json();
        return HttpResponse.json(row({ mfa_enabled: false }));
      }),
    );
    renderApp(<App />, "/administration/users");
    fireEvent.click(await screen.findByRole("button", { name: "Reset MFA" }));
    fireEvent.change(await screen.findByLabelText("Your password"), {
      target: { value: "admin-secret-pass" },
    });
    fireEvent.change(screen.getByLabelText("Your authenticator code"), {
      target: { value: "123456" },
    });
    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Reset MFA" }));
    await waitFor(() =>
      expect(sent).toEqual({ password: "admin-secret-pass", code: "123456" }),
    );
  });

  it("is not available to other roles", async () => {
    server.use(http.get("/api/v1/auth/me", () => HttpResponse.json(READER)));
    renderApp(<App />, "/administration/users");
    expect(await screen.findByText("Not permitted")).toBeInTheDocument();
  });
});

describe("Temporary password", () => {
  it("sends a user with a temporary password to the Account page to change it", async () => {
    let sent: unknown = null;
    document.cookie = "csrf_token=tok; path=/";
    server.use(
      http.get("/api/v1/auth/me", () =>
        HttpResponse.json({ ...READER, must_change_password: true }),
      ),
      http.post("/api/v1/auth/password", async ({ request }) => {
        sent = await request.json();
        return new HttpResponse(null, { status: 204 });
      }),
    );
    renderApp(<App />, "/dashboard");
    expect(
      await screen.findByText(/set by an administrator/),
    ).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Temporary password"), {
      target: { value: "Abcd2345Efgh6789Jklm" },
    });
    fireEvent.change(screen.getByLabelText("New password"), {
      target: { value: "a-brand-new-passphrase" },
    });
    fireEvent.change(screen.getByLabelText("Repeat new password"), {
      target: { value: "a-brand-new-passphrase" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    await waitFor(() =>
      expect(sent).toEqual({
        current_password: "Abcd2345Efgh6789Jklm",
        new_password: "a-brand-new-passphrase",
      }),
    );
  });

  it("refuses mismatched new passwords without calling the server", async () => {
    let called = false;
    server.use(
      http.get("/api/v1/auth/me", () =>
        HttpResponse.json({ ...READER, must_change_password: true }),
      ),
      http.post("/api/v1/auth/password", () => {
        called = true;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    renderApp(<App />, "/account");
    fireEvent.change(await screen.findByLabelText("Temporary password"), {
      target: { value: "x".repeat(20) },
    });
    fireEvent.change(screen.getByLabelText("New password"), {
      target: { value: "a-brand-new-passphrase" },
    });
    fireEvent.change(screen.getByLabelText("Repeat new password"), {
      target: { value: "something-else-entirely" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect(
      await screen.findByText("The new passwords do not match"),
    ).toBeInTheDocument();
    expect(called).toBe(false);
  });
});
