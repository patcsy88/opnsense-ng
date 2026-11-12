# ADR-0006: Staged changes for NAT port forwards

- Status: accepted
- Date: 2026-11-12
- Deciders: project owner (accepted 2026-11-12 as written)

## Context

NAT listing (port forwards and outbound) is read-only and lab-verified. The project rules require
config changes to be staged, validated, reviewed and explicitly applied (ADR-0005). A port forward
is more sensitive than most rules: it exposes an internal host to whatever network the traffic
arrives on.

What the OPNsense API does (from `opnsense/core` master; **unverified on the 26.7.8_2 lab until
the lab test**):

- `DNatController` extends the same base as the filter controller. Endpoints under
  `/api/firewall/d_nat/*`: `addRule`, `setRule/{uuid}`, `delRule/{uuid}`, `toggleRule/{uuid}`,
  `moveRuleBefore`, `toggleRuleLog`, plus `apply` (`configd filter reload skip_alias`).
- Writes go to the config immediately and are activated by `apply`. There is no dry run, no
  savepoint and no revert, the same as rules and aliases.
- The privilege `Firewall: NAT: Destination NAT` covers read and write (and the category search).
  The lab API user already has it.
- Port forward fields use nested names: `source.network`, `source.port`, `destination.network`,
  `destination.port`, `target`, `local-port`, `descr`, and the **inverted** flag `disabled`.
- The sequence has no default; `DNatSequenceField` assigns one when loading. How it behaves on
  `addRule` must be confirmed on the lab.
- The `pass` option can be set to "Register rule", which makes OPNsense create a matching filter
  rule as a side effect.

## Decision

### 1. Same staging model as ADR-0005

A new change kind `nat_forward` (the existing `kind` column is a free string, so there is no
migration). Same table, status machine, four-eyes rules, `allow_writes` gate, per-firewall apply
lock, stale check (SHA-256 fingerprint of the normalised base object), result snapshot, audit
records and "no automatic rollback, undo is a new reviewed request".

Roles are the same as for rules: `network_admin` stages and reviews, only `admin` applies,
`security_admin` and `read_only` are view-only, a `network_admin` cannot approve their own request,
an `admin` may (flagged `self_approved`).

### 2. Scope of the first release (owner decision)

- **Port forwards only:** create, update, toggle (enable/disable) and delete.
- **Outbound NAT stays read-only.** A wrong outbound rule can cut all internet access for a network,
  and it needs its own lockout-style risk rules and lab test.
- Not included: reordering, "no redirect" (`nordr`) exception rules, 1:1 NAT, NPTv6, import/upload.
  Existing `nordr` rules are shown but are "not editable here".

### 3. Field subset (anything else is refused)

enabled, one interface, IP version (IPv4 or IPv6), protocol (TCP, UDP or TCP/UDP), source (any, IP,
CIDR or alias) with optional port, destination (any, an interface address keyword such as `wanip`,
IP, CIDR or alias) with optional port, redirect target (IP or alias), target port (number or
alias), log, description (required, unique, identifies the rule).

Fixed by the backend and not settable: `pass` is left at **Manual**, so a staged forward never
registers a filter rule. The matching pass rule is created through the existing rules flow, so
each exposure is reviewed on its own. Also fixed to defaults: pool options, NAT reflection, tags,
categories, sync and `nordr`.

Ports are required when the protocol is TCP, UDP or TCP/UDP and a redirect port is given; a target
without a port keeps the destination port. Alias references (addresses and ports) are checked
against the firewall at stage time and re-checked at apply, as for rules.

### 4. Risk (owner decision)

**High risk** (admin approver plus a typed description at apply):
- any forward on the WAN interface,
- any forward whose source is `any` and whose destination port is empty or a range,
- every delete.

All other changes are normal risk. The reasons are stored on the request and shown in the UI.

### 5. Update, toggle, delete

- **Update** keeps the interface, description and sequence fixed (as for rules). Everything else in
  the subset can change.
- **Toggle** writes the inverted `disabled` flag explicitly (`0` or `1`), never the firewall's
  "flip" default, so a retry cannot undo itself.
- **Delete** is always high risk and needs the typed description.
- **Create** places the forward after all others (highest sequence + 1), as for rules, unless the
  lab shows the firewall already does so.

### 6. Apply

Same procedure as rules: lock, re-check status and stale fingerprint, call the registry write
operation once, then the separate activation call `POST /api/firewall/d_nat/apply`, then read back
and store the result snapshot. If activation fails the request is `failed` with a message that the
change is saved on the firewall but not active.

### 7. Registry

New entries, all `read_only=False` except the list, `verified=False` until the lab test:
`firewall.nat.port_forwards.add`, `.update`, `.delete`, `.toggle` and `.apply`, privilege
`Firewall: NAT: Destination NAT`. Writes are never retried.

## Consequences

- A port forward can only reach a firewall after an admin applies a reviewed request.
- The risk rules make the common dangerous cases (internet-facing, wide open, deletes) need an
  admin and a typed confirmation, at the cost of friction on WAN forwards, which are the main use.
- A forward does not open traffic by itself: the user must also stage the pass rule. This is a
  deliberate extra step, noted in the UI.
- The same non-atomic apply and no-rollback limits as ADR-0005.
- The lab test needs one throwaway forward to a non-existent internal address on a non-standard
  port.
- No new dependencies and no migration.

## Build order (each step is a separate commit and is tested)

1. Local validation schema and risk rules (unit tests only).
2. Stage, submit, approve, reject and cancel for create/update/toggle/delete (no apply).
3. Registry write entries and the apply procedure behind `allow_writes`, tested with mocked
   OPNsense. Then the **first lab test**, with a throwaway forward only.
4. Frontend: forms, diff, risk display, buttons on the NAT page.
5. Lab-test update, toggle and delete, then mark the operations verified.

## Alternatives considered

- **Also stage outbound NAT now.** Rejected for the first release (internet-outage risk, separate
  design).
- **Allow `pass: Register rule`.** Rejected: one request would open traffic as a side effect and
  need a second stale check.
- **Treat every forward change as high risk.** Rejected: toggles and edits of internal-only forwards
  would need an admin and typed confirmation for little benefit.
