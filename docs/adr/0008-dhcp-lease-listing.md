# ADR-0008: Read-only DHCP lease listing (Dnsmasq)

- Status: accepted
- Date: 2026-11-12
- Deciders: project owner

## Context

Phase 4 starts with read-only views. The lab runs Dnsmasq for DHCP and DNS. OPNsense lists its leases
with `GET /api/dnsmasq/leases/search` (from the source on master; not yet checked on 26.7.8_2). Each
row holds the address, hostname, MAC address, a vendor name from the MAC database, client id, IAID,
expiry, interface and a dynamic or static lease type.

Leases are an inventory of devices on the network. The required privilege, "Services: Dnsmasq
DNS/DHCP: Settings", also covers every other `api/dnsmasq/*` call, including settings writes.

## Decision

1. **Registry:** new operation `dhcp.leases`, `GET /api/dnsmasq/leases/search`, `read_only=True`,
   `verified=False` until checked on the lab. No other Dnsmasq endpoint is added, so nothing in this
   app can change DHCP or DNS settings.
2. **Normalised fields:** address, IP version, hostname, interface, lease type (`dynamic` or `static`),
   vendor name and expiry. **MAC addresses, client ids and IAIDs are dropped in the backend** and never
   reach the browser. Showing MACs later, for example to admins only, needs a new decision.
3. **Backend:** `GET /api/v1/firewalls/{id}/dhcp/leases`, capped at 1000 rows with a `truncated` flag.
   Audited like other firewall calls.
4. **Access:** admin, network_admin and security_admin. `read_only` is excluded, as for logs, because
   the list is a device inventory. Non-admin errors are collapsed with `public_status`.
5. **Frontend:** a DHCP page with a filter box and a table: address, hostname, interface, type, vendor
   and expiry. No actions. The page refreshes every 30 s and nothing is stored.
6. **Out of scope:** static mappings, DHCP and DNS settings and lease deletion are config writes and
   need their own ADR.

## Consequences

- Operators see who holds which address without opening OPNsense.
- The API user needs a privilege broader than reading. This is the same trade-off as for firewall
  rules and is limited in practice because the registry has no Dnsmasq write operation.
- Without MACs, two devices with the same hostname cannot be told apart by hardware address.
- A Kea setup would need a separate operation (`kea/leases4/search`).

## Alternatives considered

- **Show MAC addresses to admins only.** Useful for tracing, but adds an exposure we can defer.
- **Include `read_only`.** Rejected: hostnames and devices are internal inventory.
- **Hide the lease list until a narrower privilege exists.** Rejected: OPNsense has none.
