# ADR-0020: Kea DHCP leases and reservations

- Status: accepted (Phase A only; Phase B needs a separate approval after Phase A is verified)
- Date: 2026-11-15
- Deciders: project owner

## Context

The DHCP page has an engine tab for Kea, but it is a placeholder. ADR-0008 lists Kea as future work.
Kea is installed on the lab firewall but not enabled, so nothing can be verified there until it is
turned on. The lab API user has no Kea privileges yet.

OPNsense API endpoints (from `opnsense/core`, **to be confirmed on the 26.7.8_2 lab before any
operation is marked verified**):

- Leases: `GET /api/kea/leases4/search` (and `leases6/search`).
- Subnets: `searchSubnet`, `getSubnet`, `addSubnet`, `setSubnet`, `delSubnet` under `/api/kea/dhcpv4/`.
- Reservations: `searchReservation`, `getReservation`, `addReservation`, `setReservation`,
  `delReservation` under `/api/kea/dhcpv4/`.
- Service: `/api/kea/service/status` and `/api/kea/service/reconfigure`.
- Writes save to the config only and take effect after `reconfigure`. No dry run or revert.

## Decision (proposed)

### 1. Phase A: read-only

- Registry operations `kea.leases4.list`, `kea.reservations4.list` and `kea.subnets4.list`, all marked
  unverified until confirmed on the lab.
- Backend endpoints `GET /firewalls/{id}/kea/leases`, `/kea/reservations`, `/kea/subnets`. All roles may
  read leases and subnets, as for Dnsmasq leases (admin, network_admin, security_admin; not read_only,
  since a lease list is a device inventory). Leases never carry MAC addresses or client ids.
  Reservations do carry MAC addresses, so only admin and network_admin may read them. Responses are
  normalised in the backend and use the existing `registry_verified` flag.
- DHCPv4 only. DHCPv6 is out of scope until asked for.
- Frontend: the Kea tab replaces its placeholder with Leases, Reservations and Subnets. The unverified
  badge shows until the operations are verified.
- No migration and no new dependency.

### 2. Phase B: reservation writes (separate approval after Phase A is verified)

- New change kind `kea_reservation` (create, update, delete) through the existing staging model: roles,
  four-eyes, `allow_writes` gate, stale fingerprint, apply as admin, `reconfigure` as a separate audited
  call, read back. No automatic rollback.
- Risk: create and update are medium. Delete is high and needs the typed confirmation.
- A reservation must sit inside an existing subnet, and its IP and MAC must be unique. A duplicate is
  refused at validation.
- Subnet and pool edits are **not** proposed. A wrong pool or option can take DHCP down for a whole
  network, so they need their own ADR.

### 3. Privileges

- The lab API user needs the Kea privileges ("Services: Kea DHCP" in the OPNsense UI). The exact names
  are confirmed against the lab. Phase A needs read access only. The owner grants them. The app does not.
- Kea must be enabled on the lab before verification. The owner does that.

### 4. Out of scope

- Starting or stopping Kea. The Services page shows state only.
- DHCPv6, HA peers, and option or pool editing.

## Consequences

- Operators on Kea see leases and reservations without the OPNsense UI.
- Phase A has no write risk. Phase B reuses the existing change pipeline.
- Verification waits for Kea to be enabled on the lab and for the privileges.

## Open questions

- Exact privilege names and the `search*` response shapes on 26.7.8_2.
- Whether `reconfigure` drops active leases or only reloads the config.
