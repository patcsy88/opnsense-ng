# ADR-0021: Kea DHCPv4 reservation changes (staged)

- Status: proposed (needs owner approval before any code)
- Date: 2026-11-15
- Deciders: project owner

## Context

ADR-0020 phase A gave read-only Kea leases, reservations and subnets. Subnets and reservations are
verified on the lab (26.7.8_2). Operators still cannot add, change or remove a reservation without the
OPNsense UI. ADR-0020 section 2 reserved this as phase B, needing its own approval.

What the OPNsense API does (from `opnsense/core` master, **to be confirmed on the lab before any write
is marked verified**):

- Reservations live under `/api/kea/dhcpv4/`: `addReservation`, `getReservation/{uuid}`,
  `setReservation/{uuid}`, `delReservation/{uuid}`. The body root key is probably `reservation`.
- Verified read shape of a reservation row: `uuid`, `subnet` (a **uuid**), `%subnet` (readable, for
  example `192.168.1.0/24`), `ip_address`, `hw_address`, `client_id`, `hostname`, `description`, plus
  option fields (`next_server`, `option_data.*`, `option`).
- Writes save to the config only and take effect after `POST /api/kea/service/reconfigure`. Whether
  this drops active leases or only reloads Kea is **unconfirmed**; the safe assumption is a Kea restart
  with a short DHCP gap.
- There is no dry run, savepoint or revert, as for earlier staged kinds.
- **Privilege:** the lab API user already reads Kea ("Services: Kea DHCP"). Whether that same privilege
  covers the write and `reconfigure` endpoints is unconfirmed.

## Decision (proposed)

### 1. Same staging model as ADR-0005, ADR-0017, ADR-0018 and ADR-0019

New change kind `kea_reservation`. The `kind` column is a free string, so **no migration**. Same table,
status machine, four-eyes rules, `allow_writes` gate, per-firewall apply lock, SHA-256 stale
fingerprint, result snapshot and audit records. No automatic rollback; undo is a new reviewed request.

Roles as before: `network_admin` stages and reviews, only `admin` applies, `security_admin` and
`read_only` are view-only, a `network_admin` cannot approve their own request. Reservations are visible
to `admin` and `network_admin` only, as in ADR-0020, because they carry MAC addresses.

The apply procedure reuses the shared resolver one (lock, stale check, write, separate audited
`reconfigure`, read back) through `ResolverSpec`. If `reconfigure` fails the request is `failed`, with
the message that the change is saved but **not active**. Existing Dnsmasq, Unbound and WireGuard
behaviour must not change.

### 2. Scope

- **Reservations:** create, update and delete.
- **Out of scope:** subnets, pools, DHCP options (routers, DNS servers, next server, boot file),
  client id, DDNS and DHCPv6. A wrong pool or option can take DHCP down for a whole network, so they
  need their own ADR. Existing option values on a reservation are shown as "set" and left untouched.
- Enable and disable do not exist for reservations in the API, so none is offered. Remove it by delete.

### 3. Field subset (anything else is refused)

`subnet` (an existing subnet uuid, chosen from the subnet list), `ip_address` (IPv4, **inside that
subnet**), `hw_address` (a MAC, normalised to lower case), optional `hostname` (DNS label rules) and
optional `description`. Sizes capped.

Duplicates are refused at stage time and re-checked at apply: the same MAC in the same subnet, or the
same IP in any subnet. The IP should not lie inside a dynamic pool of its subnet, because Kea can then
hand it to another client first. That is **refused**, not warned (open question 3).

### 4. Risk (proposed, owner to confirm)

**High risk** (admin approver, the IP typed at apply):
- any **delete** (the device loses its fixed address and may get a different one);
- **changing the MAC or IP** of an existing reservation (it moves an address to another device).

**Normal risk:** creating a reservation, or changing only hostname or description.

### 5. Apply procedure

Lock the firewall, re-check status and the stale fingerprint, confirm the reservation still exists and
matches its fingerprint (the `set` calls are upserts), call the one write operation, call
`reconfigure` as a separate audited operation, read the reservation back and store the result. The
confirmation dialog says that **Kea may restart and DHCP may pause briefly**.

New registry operations, all `verified=False` until the lab test: `kea.reservations4.add`, `.update`
and `.delete`, `kea.reconfigure`. The list operations from ADR-0020 are unchanged.

### 6. Frontend

On the DHCP page, Kea tab, the Reservations section gains "New reservation", edit and delete actions for
`admin` and `network_admin`, a list of open requests of this kind and a diff against the current object.
Proposals go to Administration, Changes for review and apply. The subnet is a dropdown fed by the
subnet list, and the form refuses an IP outside it before sending.

### 7. Tests, dependencies and the lab

Mocked OPNsense (`respx`) for every operation: duplicate MAC and IP, IP outside the subnet, IP inside a
pool, stale detection, risk rules, role and four-eyes rules, `allow_writes`, apply order including a
`reconfigure` failure, and audit rows. Frontend tests for the form and role views. **No new
dependency.**

The lab test (`scripts/e2e-lab-hosts.sh`, new spec) creates one throwaway reservation on the existing
test subnet 192.168.1.0/24 with an IP outside the pool and a locally administered MAC, edits it and
deletes it. It confirms the privilege, the body root key and what `reconfigure` does to Kea.

### 8. Build order

1. Registry, normaliser changes, schema, staging, apply spec, with tests.
2. Frontend form and actions, with tests.
3. Lab test, then mark the operations verified and update the docs.

## Consequences

- Operators can manage Kea reservations with review, without the OPNsense UI.
- Every apply may restart Kea. The UI says so before apply.
- The Kea privilege may also cover subnet and option writes in OPNsense. As for earlier writes,
  `allow_writes` limits the blast radius per firewall, and this app only sends reservation fields.
- A self-approving admin can still add a reservation that takes over an address.

## Alternatives considered

- **Include subnets and options.** Rejected: higher blast radius, own ADR.
- **Treat every reservation change as high risk.** Possible, but routine additions become as heavy as a
  delete. Offered in the questions.
- **Allow an IP inside a pool with a warning.** Possible; refusing is safer.

## Open questions for the owner

1. Is the risk split in section 4 right (create normal; delete and MAC/IP change high)?
2. Do `admin` and `network_admin` see MAC addresses of reservations, as in ADR-0020?
3. Refuse an IP that lies inside a dynamic pool, as proposed, or only warn?
4. Does the lab API user's Kea privilege cover writes and `reconfigure`? If not, grant it.
5. May the lab test create, edit and delete one throwaway reservation on 192.168.1.0/24?
6. Are subnets, pools and options out of scope for this release?
