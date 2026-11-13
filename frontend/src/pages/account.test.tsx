import { fireEvent, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { App } from "@/App";
import { server } from "@/test/server";
import { ADMIN, renderApp } from "@/test/utils";

const RESTRICTED = {
  ...ADMIN,
  mfa_enabled: false,
  mfa_enrolment_required: true,
};
const ENROLLED = { ...ADMIN, mfa_enabled: true, mfa_enrolment_required: false };

const QR = [
  [true, false, true],
  [false, true, false],
  [true, false, true],
];

function status(over: object = {}) {
  return http.get("/api/v1/auth/mfa", () =>
    HttpResponse.json({
      enabled: false,
      required: true,
      recovery_codes_left: 0,
      ...over,
    }),
  );
}

describe("MFA login step", () => {
  it("asks for a code after the password and then signs in", async () => {
    let sent: unknown = null;
    server.use(
      http.get(
        "/api/v1/auth/me",
        () => new HttpResponse(null, { status: 401 }),
      ),
      http.post("/api/v1/auth/login", () =>
        HttpResponse.json({ mfa_required: true, challenge: "chal-1" }),
      ),
      http.post("/api/v1/auth/login/mfa", async ({ request }) => {
        sent = await request.json();
        return HttpResponse.json({ user: ENROLLED, csrf_token: "tok" });
      }),
    );
    renderApp(<App />, "/login");
    fireEvent.change(await screen.findByLabelText("Username"), {
      target: { value: "alice" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "correct-horse-battery" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    fireEvent.change(await screen.findByLabelText("Authentication code"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    await waitFor(() =>
      expect(sent).toEqual({ challenge: "chal-1", code: "123456" }),
    );
  });

  it("shows the error and keeps the code step on a wrong code", async () => {
    server.use(
      http.get(
        "/api/v1/auth/me",
        () => new HttpResponse(null, { status: 401 }),
      ),
      http.post("/api/v1/auth/login", () =>
        HttpResponse.json({ mfa_required: true, challenge: "chal-1" }),
      ),
      http.post("/api/v1/auth/login/mfa", () =>
        HttpResponse.json(
          { detail: "Invalid or expired code" },
          { status: 401 },
        ),
      ),
    );
    renderApp(<App />, "/login");
    fireEvent.change(await screen.findByLabelText("Username"), {
      target: { value: "alice" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "correct-horse-battery" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    fireEvent.change(await screen.findByLabelText("Authentication code"), {
      target: { value: "000000" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(
      await screen.findByText("Invalid or expired code"),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Authentication code")).toBeInTheDocument();
  });
});

describe("Account page", () => {
  it("sends a user who must enrol to the account page", async () => {
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(RESTRICTED)),
      status(),
    );
    renderApp(<App />, "/firewall");
    expect(
      await screen.findByText(/requires two-factor authentication/),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Account" }),
    ).toBeInTheDocument();
  });

  it("enrols: password, QR drawn as svg, code, then recovery codes shown once", async () => {
    let confirmed: unknown = null;
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(RESTRICTED)),
      status(),
      http.post("/api/v1/auth/mfa/enrol/start", () =>
        HttpResponse.json({
          secret: "JBSWY3DPEHPK3PXP",
          otpauth_uri: "otpauth://totp/x",
          qr: QR,
        }),
      ),
      http.post("/api/v1/auth/mfa/enrol/confirm", async ({ request }) => {
        confirmed = await request.json();
        return HttpResponse.json({
          recovery_codes: ["AAAA-BBBB-CCCC-DDDD", "EEEE-FFFF-GGGG-HHHH"],
        });
      }),
    );
    document.cookie = "csrf_token=tok; path=/";
    renderApp(<App />, "/account");
    fireEvent.change(await screen.findByLabelText("Confirm your password"), {
      target: { value: "correct-horse-battery" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    const qr = await screen.findByRole("img", { name: /QR code/ });
    expect(qr.tagName.toLowerCase()).toBe("svg");
    expect(qr.querySelectorAll("rect").length).toBe(1 + 5); // background + dark modules
    expect(screen.getByLabelText("Setup key")).toHaveTextContent(
      "JBSWY3DPEHPK3PXP",
    );
    fireEvent.change(screen.getByLabelText("Code from your app"), {
      target: { value: "123456" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Turn on two-factor authentication" }),
    );
    expect(await screen.findByText("AAAA-BBBB-CCCC-DDDD")).toBeInTheDocument();
    expect(confirmed).toEqual({ code: "123456" });
    expect(document.querySelector("img")).toBeNull();
  });

  it("does not offer to turn MFA off when the role requires it", async () => {
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(ENROLLED)),
      status({ enabled: true, required: true, recovery_codes_left: 7 }),
    );
    renderApp(<App />, "/account");
    expect(
      await screen.findByText(/7 recovery codes left/),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Get new recovery codes" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Turn off" }),
    ).not.toBeInTheDocument();
  });

  it("offers turning MFA off when the role does not require it", async () => {
    server.use(
      http.get("/api/v1/auth/me", () => HttpResponse.json(ENROLLED)),
      status({ enabled: true, required: false, recovery_codes_left: 10 }),
    );
    renderApp(<App />, "/account");
    expect(
      await screen.findByRole("button", { name: "Turn off" }),
    ).toBeInTheDocument();
  });
});
