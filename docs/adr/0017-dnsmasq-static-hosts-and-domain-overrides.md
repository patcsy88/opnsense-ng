# ADR-0017: Dnsmasq static hosts and domain overrides (staged)

- Status: accepted
- Date: 2026-11-14
- Deciders: project owner

## Context

The lab keeps Dnsmasq as its DHCP server (owner, 2026-11-14), and ADR-0008 gives a read-only lease
list. Two things operators change often are not available here:

- **Static host entries** (`hosts`): a name and address, optionally tied to a MAC address so that
  DHCP always hands the same address to that device, plus aliases (CNAMEs).
- **Domain overrides** (`domainoverrides`): send queries for a domain to a specific DNS server.

What the OPNsense API does (from `opnsense/core` master, `Dnsmasq/Api/SettingsController.php` and
the `Dnsmasq.xml` model; **to be confirmed on the 26.7.8_2 lab before any write is marked
verified**):

- Hosts: `searchHost`, `getHost/{uuid}`, `addHost`, `setHost/{uuid}`, `delHost/{uuid}`.
  Domain overrides: `searchDomain`, `getDomain/{uuid}`, `addDomain`, `setDomain/{uuid}`,
  `delDomain/{uuid}`. The same controller also has DHCP ranges, tags, options, boot options and
  settings, which are **out of scope**.
- Each write saves to the config immediately. It takes effect only after
  `POST /api/dnsmasq/service/reconfigure`, which restarts Dnsmasq, so DNS and DHCP are briefly
  interrupted at apply.
- There is no dry run, no savepoint and no revert, the same as aliases, rules and NAT.
- One privilege, "Services: Dnsmasq DNS/DHCP: Settings", covers read and write (and is the one
  ADR-0008 already uses for leases).
- A host entry has: `host`, `domain`, `ip` (a list), `cnames`, `hwaddr` (a list of MACs),
  `client_id`, `lease_time`, `ignore`, `local`, `set_tag`, `descr`, `comments`, `aliases`. `ignore`
  makes Dnsmasq refuse DHCP to that client. A wildcard host name is allowed.
- A domain override has: `domain` (wildcard allowed), `ip` (the server to ask), `srcip`, `port`,
  `ipset`, `sequence`, `descr`.
- `setHost` and `setDomain` are upserts, so apply must confirm the object exists first.

Both kinds can hurt. A wrong static host can give two devices one address or hide a real one. A
domain override can send a domain (including internal or banking names) to an attacker's DNS
server, and one for `.` or a broad suffix can break all name resolution.

## Decision

### 1. Same staging model as ADR-0005 and ADR-0006

Two new change kinds, `dnsmasq_host` and `dnsmasq_domain`. The `kind` column is a free string, so
**no migration**. Same table, status machine, four-eyes rules, `allow_writes` gate, per-firewall
apply lock, stale check (SHA-256 fingerprint of the normalised base object), result snapshot and
audit records. No automatic rollback. Undo is a new reviewed request created from the stored base
snapshot.

Roles are as for rules: `network_admin` stages and reviews, only `admin` applies, `security_admin`
and `read_only` are view-only (see the visibility point in decision 6), a `network_admin` cannot
approve their own request, an `admin` may (flagged `self_approved`).

### 2. Scope of the first release

- **Static hosts:** create, update and delete. Disabling is done by deleting, or by `ignore`
  (decision 3), since the model has no enabled flag.
- **Domain overrides:** create, update and delete.
- **Out of scope:** DHCP ranges, tags, options, boot options, general Dnsmasq settings, CSV
  import and export (`uploadHosts`, `downloadHosts`) and lease deletion. They need their own
  decision if wanted.

### 3. Field subset (anything else is refused)

**Host:** `host` (a name, or `*` only if the owner agrees, see questions), `domain`, one or more
IP addresses (IPv4 or IPv6, no networks), zero or more MAC addresses, zero or more CNAME aliases,
`ignore` (default off), description (required). Left at defaults and not settable: client id,
lease time, tags, `local`, comments.

**Domain override:** `domain` (no wildcard in the first release), one DNS server IP, optional
port, description (required). Left at defaults and not settable: source IP, ipset, sequence.

Local validation: names against the DNS name rules, IPs parsed, MACs normalised to lower case,
sizes capped (at most 8 addresses, 8 MACs, 16 aliases per host). A duplicate (same host and
domain, or same MAC, or same override domain) is refused at stage time and re-checked at apply.

### 4. Risk (proposed, owner to confirm)

**High risk** (admin approver, and the description typed at apply):
- any **domain override** (it redirects name resolution), and especially one for a single label,
  the root, or a broad public suffix, which is **refused outright**;
- a host with `ignore` on (it blocks a device from DHCP);
- any **delete**;
- a host whose IP is the firewall's own address or whose name is `localhost` or the firewall's
  host name.

Everything else (a new or changed plain host entry) is normal risk.

### 5. Apply procedure

As in ADR-0005: lock the firewall, re-check status and the stale fingerprint, call the one write
operation, then `reconfigure` as a separate audited operation, read the object back and store the
result. If `reconfigure` fails the request is `failed` with a message that the change is saved on
the firewall but not active. The confirmation dialog states that **Dnsmasq restarts, so DNS and
DHCP pause for a moment**. Dnsmasq's DHCP leases survive the restart.

New registry operations, all `read_only=False`, `verified=False` until the lab test:
`dnsmasq.hosts.list`, `.add`, `.update`, `.delete`, `dnsmasq.domains.list`, `.add`, `.update`,
`.delete` and `dnsmasq.reconfigure`. The list operations are read-only POSTs/GETs that need no
`allow_writes`.

### 6. Visibility and MAC addresses (owner decision needed)

ADR-0008 deliberately keeps MAC addresses out of the browser. Static host entries are mostly about
MACs, so an editor without them is useless. Proposed: MAC addresses are shown and edited **only to
`admin` and `network_admin`**, in this feature only. The read-only lease list is unchanged. A
`security_admin` or `read_only` user sees the host name, IP and description but not the MACs, and
the stored request snapshot is filtered the same way for them.

### 7. Frontend

A "DNS and DHCP entries" area, reachable from the existing DHCP page for admin and network_admin
roles: two tabs (Static hosts, Domain overrides), each a table of what is on the firewall now plus
the open requests, and a form to propose a create, edit or delete. Proposals go to the existing
Changes page for review and apply. Every form shows the diff against the current firewall object.

### 8. Tests, dependencies and the lab

Mocked OPNsense (`respx`) for every operation, stale detection, duplicate checks, high-risk rules,
the refused domains, role and four-eyes rules, `allow_writes`, MAC visibility per role, the apply
procedure including a `reconfigure` failure, and the audit rows. Frontend tests for the forms and
role views. No new dependency. The first lab test uses a throwaway host entry for an unused
address and name, then a throwaway override for a `.test` domain, each deleted afterwards.

## Consequences

- Operators can manage static DHCP reservations and DNS entries from one place, with review.
- Every apply restarts Dnsmasq, so DNS and DHCP pause briefly. The UI says so before apply.
- The API user's privilege is broader than reading, as already accepted for aliases, rules, NAT
  and now services. `allow_writes` limits the blast radius per firewall.
- MAC addresses become visible to two roles in this area, which is a deliberate change from
  ADR-0008, limited to this feature.
- Domain overrides are powerful. Making each one high risk and admin-approved keeps a single
  `network_admin` from redirecting DNS alone, but a self-approving admin still can.
- The restart-based activation and the missing dry run mean a bad value is only found at apply.
  Our local validation has to catch most problems.

## Alternatives considered

- **Direct edits with no review, like service control.** Rejected: these are config changes, and
  the project rules require staged review.
- **Make Unbound the target instead.** Not chosen: the owner said Dnsmasq keeps serving DHCP, and
  Unbound host and domain overrides are a separate, similar change (its own ADR).
- **Hide MAC addresses everywhere and let the firewall pair devices by name.** Not workable: a
  DHCP reservation is defined by the MAC.
- **Include DHCP ranges, options and settings.** Rejected for now: a wrong range or option can
  take down DHCP for a whole network. They need their own lockout-style rules.
- **Import hosts from CSV.** Deferred: bulk changes are hard to review and stale-check.

## Questions for the owner

1. Are MAC addresses shown to `admin` and `network_admin` only, as proposed in decision 6?
2. Should wildcard host names (`*`) be allowed? I propose **no** in the first release, and no
   wildcard domain overrides.
3. Are all domain overrides high risk (admin approver), as proposed?
4. Do you want host entries only first (build, lab test, then domain overrides), or both together?

## Owner decisions (2026-11-14)

Accepted as proposed: (1) MAC addresses only for `admin` and `network_admin`; (2) no wildcard host
names or overrides; (3) every domain override is high risk; (4) **static hosts are built first**,
then a lab test, then domain overrides in a separate step.
