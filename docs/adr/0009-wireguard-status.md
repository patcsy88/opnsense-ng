# ADR-0009: Read-only WireGuard status

- Status: accepted
- Date: 2026-11-13
- Deciders: project owner

## Context

Phase 4 continues with read-only views. The lab runs WireGuard. OPNsense reports tunnel and peer state
with `GET /api/wireguard/service/show` (from the source on master; not yet checked on 26.7.8_2). The
result is built from `wg show all dump`. Each row is an `interface` or a `peer`, with the configured
name, public key, endpoint, allowed IPs, transfer counters, keepalive, listen port and latest
handshake. OPNsense adds `peer-status`: `online` if the last handshake was within 300 s, `stale` if
older, `offline` if there was none.

The raw dump also holds the interface **private key** and any peer **preshared key**.

The required privilege, "VPN: WireGuard: Status", grants `api/wireguard/service/*`. That includes
start, stop, restart and reconfigure, but not the server and client configuration endpoints.

## Decision

1. **Registry:** new operation `wireguard.status`, `GET /api/wireguard/service/show`, `read_only=True`,
   `verified=False` until checked on the lab. No other WireGuard endpoint is added, so nothing in this
   app can start, stop or change a tunnel or peer.
2. **Normalised fields, by whitelist:** interface name, tunnel name, peer name, row type, peer status,
   latest handshake (timestamp), bytes received and sent, allowed IPs, peer endpoint and listen port.
   **Private keys, preshared keys and public keys are dropped in the backend** and never reach the
   browser. Showing public keys later needs a new decision.
3. **Backend:** `GET /api/v1/firewalls/{id}/vpn/wireguard`, capped at 500 rows with a `truncated` flag.
   Audited like other firewall calls. A test checks that no key material appears in the response.
4. **Access:** admin, network_admin and security_admin. `read_only` is excluded because peer endpoints
   are real client addresses. Non-admin errors are collapsed with `public_status`.
5. **Frontend:** a VPN page that groups peers under their tunnel, with an online, stale or offline
   badge and a filter box. No actions. It refreshes every 30 s and nothing is stored.
6. **Out of scope:** adding or editing tunnels and peers, and starting, stopping or restarting
   WireGuard. Each needs its own ADR.

## Consequences

- Operators see which peers are connected and how much traffic they carry without opening OPNsense.
- The API user needs "VPN: WireGuard: Status". It also allows service control in OPNsense, but the
  registry has no such operation.
- Without public keys, two peers with the same name cannot be told apart by key.
- Peer endpoints show where users connect from, so they are limited to the three roles above.
- The handshake age is derived from the timestamp. The 300 s online threshold comes from OPNsense.

## Alternatives considered

- **Show public keys.** Rejected for now: little value on a status page.
- **Hide peer endpoints.** Rejected: they are the main way to tell who is connected from where.
- **Include `read_only`.** Rejected: endpoints are client addresses.
- **Use the configuration endpoints for names.** Rejected: `show` already returns the names, and the
  configuration privilege is broader.
