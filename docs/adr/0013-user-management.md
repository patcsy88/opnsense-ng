# ADR-0013: User management

- Status: accepted
- Date: 2026-11-13
- Deciders: project owner

## Context

Users can only be created, given a new password or have their MFA cleared through the CLI on the
server (`create`, `set-password`, `reset-mfa`). There is no list of users in the app, no way to
deactivate an account or change a role, and no way for a user to change their own password. ADR-0012
made MFA required, so a lost device now needs shell access. Administration shows "Users" as planned.

## Decision

1. **Who:** only `admin` can list, create, change and deactivate users. Other roles cannot see the
   list. Every user can change their own password.
2. **Users page** (Administration, Users): username, role, active, MFA on or off, created, and the
   number of live sessions. No password hash, MFA secret or recovery code is ever returned.
3. **Create:** the admin enters a username and a role. The server generates a one-time temporary
   password (20 random characters), shows it once to the admin, and stores only its hash. The new
   user must change it at first sign-in (`must_change_password`). Until then the session is
   restricted in the same way as the MFA enrolment session: only the password change, `me` and
   logout work. The admin never chooses or sees a long-lived password.
4. **Change role:** takes effect on the next request, and the user's other sessions are ended.
5. **Deactivate and reactivate:** deactivating sets `is_active` to false and deletes all the user's
   sessions at once. Users are never deleted, so the audit log and change requests keep their names.
6. **Reset password (admin):** generates a new temporary password in the same way, sets
   `must_change_password`, and ends the user's sessions.
7. **Reset MFA (admin):** clears the user's MFA secret, recovery codes and challenges, and ends
   their sessions. They enrol again at next sign-in. This needs the admin's own password and a
   current MFA code, so a stolen admin session alone cannot strip another account's second factor.
8. **Self-service password change:** needs the current password, applies the existing password
   policy, ends the user's other sessions and clears `must_change_password`. For a user with MFA it
   also needs a current code.
9. **Protections:**
   - The last active admin cannot be deactivated or moved to another role, and an admin cannot
     deactivate or demote themselves. The check runs in the same transaction as the change and locks
     the admin rows, so two admins cannot remove each other at once.
   - Username is fixed after creation.
   - Every change needs authentication, the admin role, CSRF and an audit record.
10. **Audit:** `user.create`, `user.role_change` (old and new role), `user.deactivate`,
    `user.reactivate`, `user.password_reset`, `user.mfa_reset`, `auth.password_change`. The detail
    holds the target username and role names only. A temporary password is never logged or audited.
11. **Rate limits and lockout:** wrong password or code on the admin confirmation counts toward the
    admin's own username lockout, as for MFA.
12. **Migration `0005`:** adds `users.must_change_password` (default false). No new dependency.

## Consequences

- Lost-device recovery no longer needs shell access. The CLI stays as the break-glass path.
- The temporary password is visible to the admin once. It travels over the admin's own browser
  session and must be handed to the user out of band. A user who never signs in keeps a valid
  temporary password until it is reset or the account is deactivated. A limit on how long it stays
  valid can be added later.
- An admin can reset any other user's password, and so sign in as them after the user's first
  change. The audit log records every reset, and the user is forced to choose a new password.
- Roles stay a fixed list of four. Custom roles are out of scope.

## Alternatives considered

- **Admin types the initial password.** Rejected: the admin would know a password that the user may
  keep.
- **Invitation or reset links by email.** Rejected: the app has no mail sending, and adding it is a
  larger change with its own risks.
- **Deleting users.** Rejected: it would break the audit trail and change history. Deactivation
  gives the same access result.
- **Letting `security_admin` view the user list.** Possible later. Not needed now, and it widens who
  sees account names.
- **Requiring a second admin to approve role changes.** Rejected for now: heavy for a small lab
  deployment. The audit log and the last-admin rule cover the main risk.
