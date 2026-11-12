# ADR-0010: Read-only Unbound DNS overview

- Status: accepted
- Date: 2026-11-13
- Deciders: project owner

## Context

The lab is moving its DNS resolver from Dnsmasq to Unbound. Dnsmasq has no statistics endpoint, only
configuration. Unbound has two read-only sources (from the source on master; not yet checked on
26.7.8_2):

- `GET /api/unbound/diagnostics/stats`: resolver counters such as queries, cache hits, cache misses
  and uptime.
- `GET /api/unbound/overview/totals/{n}`: totals, the top queried domains and the top blocked domains.

Both need extended statistics to be enabled in Unbound (Services > Unbound DNS > Advanced). The
required privilege, "Services: Unbound", covers all of `api/unbound/*`. That includes settings
writes, host and domain overrides, the statistics reset and service control.

`GET /api/unbound/overview/searchQueries` returns recent queries with the client IP and domain. That
is a per-device browsing history.

## Decision

1. **Registry:** two read-only operations, `dns.stats` and `dns.totals`, both `verified=False` until
   checked on the lab. No other Unbound endpoint is added, so nothing in this app can change DNS
   settings, overrides, statistics or the service.
2. **Excluded:** `searchQueries` (per-client history), the statistics reset, cache dumps, local data
   and zone listings, settings and overrides, and service control. Each needs its own ADR.
3. **Normalised fields, by whitelist:** total queries, cache hits, cache misses, hit rate and uptime.
   The top queried and top blocked lists keep the domain and its count, capped at 10 each, plus the
   blocklist name for blocked domains. No client address is ever passed on.
4. **Backend:** `GET /api/v1/firewalls/{id}/dns` makes both calls and merges them. If extended
   statistics are off or a call returns nothing usable, the response says so (`stats_available`
   false) instead of showing zeros. Audited like other firewall calls.
5. **Access:** admin, network_admin and security_admin. `read_only` is excluded. Non-admin errors are
   collapsed with `public_status`.
6. **Frontend:** a DNS page with counter cards, the hit rate and two small tables of top domains.
   No actions. It refreshes every 30 s and nothing is stored.
7. **Dnsmasq:** unchanged. The DHCP page keeps using `dhcp.leases`. If Dnsmasq is turned off entirely,
   that page needs a different lease source (for example Kea) and its own decision.

## Consequences

- Operators see resolver load, cache efficiency and blocked domains without opening OPNsense.
- The API user needs "Services: Unbound", which is broader than reading. The registry has no Unbound
  write operation, which is the same trade-off as for Dnsmasq and WireGuard.
- Top domains show what the network looks at, without tying it to a client.
- The page is empty until extended statistics are turned on in OPNsense.

## Alternatives considered

- **Counters only.** Rejected: blocked domains are the most useful part of the overview.
- **Recent queries with client IPs.** Rejected: a per-device browsing history.
- **A Dnsmasq configuration view instead.** Rejected: it is not an overview, and the lab is leaving
  Dnsmasq for DNS.
- **Include `read_only`.** Rejected: top domains reveal network activity.
