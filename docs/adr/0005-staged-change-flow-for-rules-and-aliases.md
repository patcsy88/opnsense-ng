# ADR-0005: Staged change flow for firewall rules and aliases

- Status: accepted
- Date: 2026-11-11
- Deciders: project owner (accepted 2026-11-11 with the decisions in "Owner decisions")

## Context

Phase 2 so far is read-only (interfaces, rules, aliases). The project rules require that config
changes are **staged → validated → reviewed → applied**, with stale-revision checks, RBAC, CSRF,
input validation and an audit record for every state-changing call, and extra confirmation for
destructive actions (deleting rules, anything that can lock out management).

What the OPNsense API actually does (from the `opnsense/core` source on master; **to be confirmed on
the 26.7.8_2 lab before any write operation is marked verified**):

- Rules: `addRule`, `setRule/{uuid}`, `delRule/{uuid}`, `toggleRule/{uuid}`, `moveRuleBefore`
  under `/api/firewall/filter/*`. Each call **writes the change to the firewall's config
  immediately**. It only becomes active after `POST /api/firewall/filter/apply`
  (`configd filter reload`).
- Aliases: `addItem`, `setItem/{uuid}`, `delItem/{uuid}`, `toggleItem/{uuid}` under
  `/api/firewall/alias/*`, activated by `POST /api/firewall/alias/reconfigure`.
- Server-side validation exists but is part of the write call itself (`validateAndSave`); there is no
  dry-run endpoint that validates without saving.
- No savepoint or timed auto-rollback was found in the filter controller on master.
- The rules privilege (`Firewall: Rules [new]`) covers read and write together. Aliases split them:
  `Firewall: Aliases` is read-only, `Firewall: Alias: Edit` allows changes.

Consequences for the design: OPNsense has no "staged" state we can use. A change is either not on
the firewall at all, or saved but not active, or active. Staging therefore has to live in our
database, and the firewall must not be touched until a human explicitly applies.

## Decision

### 1. Staging lives in PostgreSQL, not on the firewall

New table `change_requests` (one row per proposed change) and `change_request_events`
(append-only history). Fields on a request: id, firewall_id, kind (`rule` | `alias`), action
(`create` | `update` | `delete` | `toggle`), target uuid (null for create), the **proposed object**
(our normalised schema, validated by Pydantic), the **base snapshot** (normalised object as read
when the request was created), a **base fingerprint** (SHA-256 of the base snapshot), status,
requester, reviewer, applier, timestamps.

Status machine: `draft → validated → in_review → approved → applying → applied`, with side exits
`rejected`, `cancelled`, `failed` and `stale`. Only forward transitions listed here are allowed;
each transition is one audited, transactional update.

### 2. Validation is ours, in two layers

- **Local validation (at stage time):** Pydantic schemas with strict enums and size limits, plus
  semantic checks (e.g. alias names, port ranges, CIDR syntax, no `any/any` pass on WAN without
  an explicit flag, no rule or alias change that references a missing alias).
- **Lockout guard:** changes that could cut off management (disabling or deleting the LAN
  anti-lockout rules, blocking the management port from the management network, deleting the
  alias the lockout rules use) are flagged `high_risk`. They need an admin approver and a typed
  confirmation of the target's name.
- **Firewall validation happens at apply** as the response to the write call. A validation error
  from OPNsense marks the request `failed` and leaves a clear message.

### 3. Stale check before apply

At apply time the backend re-reads the target object, normalises it and compares its fingerprint
to the request's base fingerprint. A mismatch (somebody changed it in the firewall UI after we
staged) sets the request to `stale`; nothing is written. For `create`, the stale check covers
uniqueness (e.g. alias name). The check and the write are not atomic on OPNsense, so the
residual race window is documented, not hidden. Applies are serialised per firewall with a
database advisory lock.

### 4. Roles (default deny)

| Action | read_only | security_admin | network_admin | admin |
|---|---|---|---|---|
| View requests | yes | yes | yes | yes |
| Create / edit own draft, submit | no | no | rules and aliases | yes |
| Approve / reject | no | no | rules and aliases | yes |
| Apply | no | no | no | yes |

Rules:
- `network_admin` handles both rules and aliases; only `admin` may apply. `security_admin` is
  view-only for now.
- A `network_admin` may not approve their own request (four-eyes, enforced in the backend).
- An `admin` **may** approve their own request. The audit record and the request history then
  carry `self_approved: true`.
- `high_risk` requests need an `admin` approver.
- Apply also requires the firewall's `allow_writes` flag.

### 5. Apply procedure (one request at a time, per firewall)

1. Lock the firewall, check status `approved`, re-run the stale check.
2. Call the registry write operation (`firewall.rules.add` and so on) once. Each is its own
   registry entry with `read_only=False`, its own privilege, and `verified=False` until proven on
   the lab.
3. Call the activation step (`filter/apply` or `alias/reconfigure`) as a separate, audited
   operation. If activation fails, the request is `failed` with a message that the change is saved
   on the firewall but not active, so nobody is surprised.
4. Read back the object and store the result snapshot on the request.
5. There is **no automatic rollback**. Undo is a new change request created from the stored base
   snapshot ("revert"), going through the same flow. This is stated plainly in the UI.

### 6. Scope of the first release

- Aliases first: create, update, delete, toggle for `host`, `network` and `port` types.
  Anything else (GeoIP, URL tables, external) stays read-only.
- Then rules: create, update, toggle, delete. **Reordering (`moveRuleBefore`) is excluded** from
  the first release because it renumbers neighbouring rules and is hard to stale-check.
- Importing and uploading rules, NAT and other kinds are out of scope.

### 7. Security controls on every write endpoint

Session auth, RBAC, CSRF token, request size limits, Pydantic validation, rate limit, and an audit
record (user, firewall, request id, action, outcome, and a field-level diff **without secrets**).
Audit rows survive deletion of the firewall, as today. Credentials never leave the backend. The
write API user needs elevated privileges, so the firewall record gets an explicit
`allow_writes` flag, **off by default**; with it off, every apply is refused. Non-admins get
collapsed error details as in the read paths.

### 8. Frontend

A "Changes" area: create request (form per kind, with a diff against the base), request list with
status filters, a detail page showing diff, validation result, history, and role-appropriate
buttons. The Apply button states what will run and that it cannot be rolled back automatically.

## Consequences

- Nothing reaches a firewall until an authorised person explicitly applies. A bug in staging cannot
  change a firewall.
- Four-eyes review slows single-person labs, mitigated by letting one admin hold two accounts.
- OPNsense has no dry-run, so firewall-side validation is only known at apply. Our local checks
  must catch most problems earlier, and `failed` must be handled cleanly.
- The apply is not atomic and has no automatic rollback. Revert is a manual, reviewed change.
- The write API user is more powerful than the read user. Lab keys must stay separate from
  production keys, and `allow_writes` limits the blast radius per firewall.
- New migrations (two tables, one column on firewalls), new registry write entries, new
  endpoints, new UI. This is a large piece, so it will be built in small increments (see below).
- No new dependencies are expected.

## Build order (each step is a separate commit and is tested)

1. Migration and models, status machine, audit events, no OPNsense calls (unit tests only).
2. Alias create requests: stage, validate, submit, approve, reject, cancel (no apply yet).
3. Registry write entries for aliases and the apply procedure behind `allow_writes`, tested with
   mocked OPNsense. Then the **first lab test**, on a throwaway alias only.
4. Frontend for alias changes.
5. Alias update, toggle, delete.
6. The same for rules, starting with create and toggle, then update and delete.

## Owner decisions (2026-11-11)

1. `network_admin` handles rules and aliases; `admin` applies.
2. An `admin` may approve their own requests (audited as self-approved); others may not.
3. Aliases first, then rules.
4. The lab API user may get **Firewall: Alias: Edit** when the build reaches the lab test, for a
   throwaway alias only.

## Savepoint and rollback (checked against the OPNsense source, 2026-11-11)

- **Aliases:** the alias controller has no savepoint or revert endpoint on master, 26.1 or 25.7.
  Undo for an alias is a new reviewed change request (delete the alias we created).
- **Rules:** the 25.7 and 26.1 branches of the filter controller have `savepoint` and
  `revert/{revision}` actions (revert reloads the filter). They are **not** on master, so they may be
  gone on the lab's 26.7.8_2. They are not used in this release. Whether to use them for rules is
  decided in build step 6, after checking the lab.
- Apply therefore stays without automatic rollback, as decided above.

## Alternatives considered

- **Write straight to OPNsense and rely on its apply step as the "stage".** Rejected: saved changes
  are visible to the firewall's other admins, and the config is changed before review.
- **Use OPNsense's own savepoint/rollback.** Not found in the API on master; may exist on the
  lab. Even if present, it would complement, not replace, our staging.
- **Direct editing with no review.** Rejected, contradicts the project rules.
- **Store staged changes only in the browser.** Rejected: not auditable, lost on logout, and no
  second reviewer.
- **Apply several requests as a batch.** Deferred: one change at a time keeps stale checks and
  failure handling simple.
