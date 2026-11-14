# ADR-0018: Unbound host overrides and domain forwards (staged)

- Status: accepted
- Date: 2026-11-14
- Deciders: project owner

## Context

The lab is moving DNS from Dnsmasq to Unbound (Dnsmasq keeps DHCP). ADR-0017 covers the Dnsmasq
equivalents; ADR-0010 gives a read-only Unbound overview. Operators still cannot add a local DNS
name or send a domain to another DNS server on the Unbound side.

What the OPNsense API does (from `opnsense/core` master: `Unbound/Api/SettingsController.php`,
`ServiceController.php` and the `Unbound.xml` model; **to be confirmed on the 26.7.8_2 lab before any
write is marked verified**):

- **Host overrides** (`hosts.host`): `searchHostOverride`, `getHostOverride/{uuid}`,
  `addHostOverride`, `setHostOverride/{uuid}`, `delHostOverride/{uuid}`, `toggleHostOverride`.
  The body root key is `host`. Fields: `enabled`, `hostname` (a leading `*` wildcard is allowed),
  `domain`, `rr` (`A`, `AAAA`, `MX`, `TXT`), `server` (the IP for A and AAAA), `mxprio` and `mx`
  (for MX), `txtdata` (for TXT), `ttl`, `addptr`, `description`.
- **Host aliases** (`hosts.alias`) are a separate object linked to a host by uuid
  (`searchHostAlias`, `addHostAlias`, ...). Deleting a host also deletes its aliases.
- **Domain forwards** (`dots.dot` with `type=forward`): `searchForward`, `getForward/{uuid}`,
  `addForward`, `setForward/{uuid}`, `delForward/{uuid}`, `toggleForward/{uuid}`. The body root key is
  `dot`. Fields: `enabled`, `domain` (empty means *all* queries), `server`, `port`, `description`
  and flags for TCP upstream and forward-first. **The same list holds DNS-over-TLS entries**
  (`type=dot`), which are filtered out by `type`. This is Unbound's equivalent of a Dnsmasq domain
  override.
- Writes save to the config only. They take effect after `POST /api/unbound/service/reconfigure`,
  which restarts Unbound, so DNS pauses briefly for **every client on the network**.
- No dry run, savepoint or revert, as for aliases, rules, NAT and Dnsmasq.
- The privilege is "Services: Unbound", already needed by ADR-0010. It also covers settings, ACLs,
  blocklists and service control, so it is broader than what this feature uses.
- **Differences from Dnsmasq that matter:** a forward with an empty domain redirects *all* DNS; a
  host can be an MX or TXT record, not only an address; entries have an `enabled` flag, so they can
  be disabled without deleting; there are no MAC addresses, so the ADR-0017 visibility problem does
  not arise.

## Decision

### 1. Same staging model as ADR-0005 and ADR-0017

Two new change kinds, `unbound_host` and `unbound_forward`. The `kind` column is a free string, so
**no migration**. Same table, status machine, four-eyes rules, `allow_writes` gate, per-firewall
apply lock, SHA-256 stale fingerprint, result snapshot and audit records. No automatic rollback;
undo is a new reviewed request from the stored base snapshot.

Roles as for ADR-0017: `network_admin` stages and reviews, only `admin` applies, `security_admin`
and `read_only` are view-only, a `network_admin` cannot approve their own request, an `admin` may
(flagged `self_approved`).

The apply procedure is the shared Dnsmasq one (`_apply_dnsmasq` with a spec), generalised and
renamed so that both resolvers use it. Behaviour of the Dnsmasq kinds must not change; their tests
stay as they are.

### 2. Scope of the first release

- **Host overrides:** create, update, delete and enable/disable, for record types **A and AAAA
  only**.
- **Domain forwards:** create, update, delete and enable/disable, for `type=forward` only.
- **Out of scope:** MX and TXT hosts, host aliases (CNAMEs), CSV import and export, DNS-over-TLS
  entries, ACLs, blocklists, general and advanced settings, statistics reset and service control.
  Each needs its own decision. Existing MX/TXT hosts and aliases are listed read-only and marked "not
  editable here"; they are never touched.

### 3. Field subset (anything else is refused)

**Host (A/AAAA):** `hostname` (a DNS label, no wildcard), `domain`, one IP address whose family
matches the record type (no networks), `ttl` (optional), description (required), `enabled`.
`addptr` is left at its default. Not settable: MX, TXT, aliases.

**Forward:** `domain` (required, at least two labels), one server IP, optional port, description
(required), `enabled`. TCP-upstream and forward-first stay at defaults. **A forward with an empty
domain, a single label, the root or a broad suffix is refused outright**, using the same
`BROAD_SUFFIXES` list as ADR-0017.

Local validation: DNS name rules, IP parsing, sizes capped. A duplicate (same hostname, domain and
record type; or same forward domain) is refused at stage time and re-checked at apply.

### 4. Risk

**High risk** (admin approver, description typed at apply):
- **every forward**: create, update, delete and toggle (it decides who answers for a whole domain);
- **any delete**;
- a host whose name is the firewall's own name or `localhost`, or whose IP is the firewall's own
  address;
- a host in a domain that has an existing forward (the host would be shadowed or would shadow it).

Everything else (a new or changed plain A/AAAA host, enabling or disabling one) is normal risk.

### 5. Apply procedure

Lock the firewall, re-check status and the stale fingerprint, call the one write operation, call
`reconfigure` as a separate audited operation, read the object back and store the result. If
`reconfigure` fails, the request is `failed` with a message that the change is saved but **not
active**. Because `setHostOverride` and `setForward` are upserts, apply confirms the object exists
and still matches its fingerprint first. The confirmation dialog states that **Unbound restarts and
DNS pauses for all clients**.

New registry operations, `verified=False` until the lab test:
`unbound.hosts.list`, `.add`, `.update`, `.delete`, `.toggle`; `unbound.forwards.list`, `.add`,
`.update`, `.delete`, `.toggle`; and `unbound.reconfigure`. Lists are read-only and need no
`allow_writes`.

### 6. Visibility

No MAC addresses are involved. Host and forward lists are shown to `admin` and `network_admin`,
matching ADR-0017, because the entries reveal the internal naming scheme and DNS topology.
`security_admin` and `read_only` see them only inside change requests they are allowed to view, as
today.

### 7. Frontend

On the existing DNS page, which is read-only today, add two tabs, "Host overrides" and "Domain
forwards", for `admin` and `network_admin`. Each has a table of what is on the firewall, its open
requests, create/edit/delete/toggle actions and a diff against the current object. Proposals go to
Administration, Changes for review and apply. The overview stays as the first tab.

### 8. Tests, dependencies and the lab

Mocked OPNsense (`respx`) for every operation: stale and duplicate detection, the refused domains,
family-versus-record-type checks, risk rules, role and four-eyes rules, `allow_writes`, the apply
order including a `reconfigure` failure, MX/TXT entries being listed but never edited, and audit
rows. Frontend tests for the forms and role views. **No new dependency.** The lab test (extending
`scripts/e2e-lab-hosts.sh`) uses a throwaway host in a `.test` domain, then a throwaway forward for a
`.test` domain, each deleted afterwards. The lab API user needs "Services: Unbound" (it already has
it for ADR-0010), and the test confirms that the privilege allows writes.

### 9. Build order

1. Generalise the shared apply and add host overrides, with tests.
2. Lab test of a host, then mark those operations verified.
3. Domain forwards, with tests, then a lab test and mark verified.

## Consequences

- Operators manage local DNS names and per-domain forwarding for the resolver the lab is moving to,
  with review.
- Every apply restarts Unbound, which pauses DNS for the whole network. The UI says so before apply.
- The privilege is broader than the feature, as accepted for earlier writes. `allow_writes` limits
  the blast radius per firewall.
- A forward can still capture a domain's traffic if an admin approves a hostile server. Making each
  one high risk and admin-approved stops a single `network_admin` doing it alone, but a self-approving
  admin can.
- Mixed lists (MX/TXT hosts, aliases) are shown but not editable, so a user may need OPNsense itself
  for those.

## Alternatives considered

- **Support MX, TXT and aliases now.** Rejected: more fields and a second linked object, with little
  day-to-day use. Can follow.
- **Allow an empty forward domain ("forward everything").** Rejected: it redirects all DNS and is
  better done deliberately in OPNsense.
- **Treat forwards as normal risk when the server is a private address.** Rejected: an internal
  server can still be wrong or hostile.
- **Show MX/TXT hosts as editable.** Rejected: unreviewed surface for the first release.

## Owner decisions (2026-11-14)

All accepted as proposed: (1) first release is A/AAAA host overrides and `type=forward` forwards
only; (2) every forward is high risk, and so is a host inside a forwarded domain; (3) enable/disable
is included, host toggles are normal risk and any forward toggle is high risk; (4) the lists are
visible to `admin` and `network_admin` only; (5) hosts first, then a lab test, then forwards.

## Build status

Not started. Step 1 (shared apply generalisation and host overrides) is next.
