# ADR-0012: TOTP multi-factor authentication

- Status: accepted
- Date: 2026-11-13
- Deciders: project owner

## Context

Login is a password check followed by an immediate session (`POST /api/v1/auth/login`). Phase 5 adds
a second factor. The app can change firewall rules, so a stolen or guessed password should not be
enough. There is no account page, no in-app user management and no self-service credential change
yet. Secrets at rest are already encrypted with the Fernet key, with the record id bound into the
ciphertext.

## Decision

1. **Method:** TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 s step, one step of drift either way). The
   algorithm is written with the Python standard library, with constant-time comparison. No
   dependency is added for it. Passkeys (WebAuthn), SMS and email codes are out of scope.
2. **Secret storage:** a random 160-bit secret, stored encrypted with the credential key and bound to
   the user id. It is shown once at enrolment and never returned again. The last accepted time step
   is stored per user, so a code cannot be used twice.
3. **Two-step login for users with MFA on.** The password step creates **no session**. It returns
   `mfa_required` and a challenge: a random token (only its hash is stored), valid for 5 minutes,
   single use, with at most 5 code attempts. `POST /api/v1/auth/login/mfa` takes the challenge and a
   code or recovery code, then creates the session. Wrong codes count toward the existing
   per-username lockout. The responses for an unknown user, a wrong password and a wrong code stay
   indistinguishable where they were before.
4. **Required for every role.** A user without MFA can still pass the password step, but gets a
   restricted session. Every endpoint except enrolment, `me` and logout answers 403
   `mfa_enrolment_required` until MFA is on. The frontend sends such users to the Account page. The
   rule is `MFA_REQUIRED_ROLES` (default: all four roles). An empty list makes MFA optional.
5. **Enrolment (self-service, Account page):**
   - Starting needs the current password. The response holds the secret as text and as a QR code.
   - MFA turns on only after the user enters a first valid code.
   - Ten single-use recovery codes are shown once and stored as hashes.
6. **QR code:** generated in the backend with `segno`. The API returns the QR as a boolean matrix,
   and the frontend draws it as inline SVG. No image, HTML or `data:` URL is involved, so the
   existing Content Security Policy stays as it is. The secret and the `otpauth://` URI are never
   logged or audited. The text secret stays available for typing in by hand.
7. **Disabling and changing:** need the password and a valid code or recovery code. Turning MFA on,
   off or regenerating recovery codes ends the user's other sessions. Where a role is in
   `MFA_REQUIRED_ROLES`, a user cannot turn MFA off.
8. **Recovery:** an admin CLI command `python -m app.auth.cli reset-mfa <username>` clears the
   user's MFA, deletes their sessions and audits the reset. Admin reset in the app waits for the user
   management ADR.
9. **Audit:** enrolment started, enabled, disabled, recovery codes regenerated, MFA login success and
   failure, recovery code used, and CLI reset. No code, secret or challenge value is ever recorded.
10. **Dependency (needs approval):** add `segno` 1.6.6. It is a pure-Python wheel with no runtime
    dependencies on Python 3.15, and it is used only to build the QR matrix. The license is checked
    when it is added to the lockfile. Nothing else is added.

## Consequences

- A leaked or guessed password alone no longer gives access.
- Every user has to enrol before using the app, including `labadmin` after the upgrade. A user who
  loses their device needs the CLI reset, since there is no in-app admin reset yet. At least one
  admin should keep their recovery codes safe.
- Login takes an extra step and an extra round trip, and the login throttle now covers both steps.
- A restricted session exists for users who have not enrolled. It can only reach the enrolment
  endpoints, and the route guard test checks that no other endpoint is open to it.
- The credential key now also protects MFA secrets. Rotating it follows the existing MultiFernet
  process.
- Clock drift of more than about 30 s on the user's phone makes codes fail.

## Alternatives considered

- **A TOTP library such as pyotp.** Rejected: RFC 6238 is about 20 lines, and fewer dependencies mean
  less supply-chain exposure.
- **Optional MFA.** Rejected by the owner: required for every role.
- **No QR code.** Rejected by the owner: typing a key by hand is error-prone.
- **A `data:` image or server-rendered SVG for the QR.** Rejected: it would need a CSP change or
  injected markup. A boolean matrix drawn by React needs neither.
- **Passkeys (WebAuthn).** Stronger against phishing, but a larger change. It can follow as its own
  ADR.
- **Making MFA depend on the session cookie alone.** Rejected: a password-only session must never
  exist for an MFA user, so the challenge is separate from sessions.
