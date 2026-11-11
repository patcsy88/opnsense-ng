# OPNsense API Integration

Status: eight read-only operations verified. New endpoints must be verified against a lab OPNsense before `verified=True`.

## Rules

- Authenticate with an API key and secret (HTTP basic auth) held only by the backend.
- Do not assume GUI parity. Record gaps as unsupported.
- Many changes need a separate apply/reconfigure call. Record this per operation.
- Use least-privilege API keys: create a dedicated non-admin OPNsense user per connection and grant only the privileges listed below.
- Endpoint paths use snake_case (for example `system_information`).
- A 401 means the key/secret pair is wrong; a 403 means the user lacks the privilege; a 404 is reported as `endpoint_not_found` (a registry or version problem).
- Self-signed firewalls: store the firewall's certificate as the per-firewall CA bundle. The certificate must carry the hostname used in the connection URL as a SAN; the web certificate that OPNsense generates by default has only a DNS name, so connect by that hostname rather than the IP.

## Capability table

Registry source: `backend/app/opnsense/registry/entries.py`. Verified on OPNsense 26.7.8_2 (lab, 2026-11-11) with a non-admin API user holding only the privilege shown.

| Operation id | Method | Endpoint | Privilege | Read-only | Apply required | Min version | Verified |
|---|---|---|---|---|---|---|---|
| `system.status` | GET | `/api/diagnostics/system/system_information` | Lobby: Dashboard | yes | no | 26.7.8_2 | yes |
| `system.time` | GET | `/api/diagnostics/system/system_time` | Lobby: Dashboard | yes | no | 26.7.8_2 | yes |
| `system.connectivity` | GET | `/api/diagnostics/system/system_time` | Lobby: Dashboard | yes | no | 26.7.8_2 | yes |
| `system.resources` | GET | `/api/diagnostics/system/system_resources` | Lobby: Dashboard | yes | no | 26.7.8_2 | yes |
| `cpu.usage` (SSE) | GET | `/api/diagnostics/cpu_usage/stream` | Lobby: Dashboard | yes | no | 26.7.8_2 | yes |
| `system.disk` | GET | `/api/diagnostics/system/system_disk` | Lobby: Dashboard | yes | no | 26.7.8_2 | yes |
| `interfaces.overview` | GET | `/api/interfaces/overview/interfacesInfo` | Status: Interfaces | yes | no | 26.7.8_2 | yes |
| `firewall.rules.list` | GET | `/api/firewall/filter/searchRule` | Firewall: Rules [new] | yes | no | 26.7.8_2 | yes |

Observed response fields (non-secret):
- `system_information`: `name` (hostname), `versions` (list of strings), `updates` (text).
- `system_time`: `uptime`, `datetime`, `boottime`, `config`, `loadavg`.

## Candidates for the dashboard (not yet in the registry, unverified)

From the OPNsense ACL definition (master branch), also under "Lobby: Dashboard": `system_swap`, `system_temperature`, `pf_states`. Verify each against the lab before adding.

## Streaming (SSE) operations

Operations with `response_kind=sse` are never run through `execute()`. `OPNsenseClient.sample_stream()` opens the stream, collects at most 3 JSON `data:` events (the status route asks for 2), and closes it. Limits: 5 s, 64 kB per line, 256 kB total, no retries. The CPU route allows one sample per firewall at a time and caches the result for 5 s. See ADR-0004.

Observed CPU event fields on 26.7.8_2: `total`, `user`, `nice`, `sys`, `intr`, `idle`, all integers. `total` is the used percentage (an idle firewall reported total 0, idle 100). Only an idle reading has been observed so far.

Observed `system_disk` response: `devices` list; the dashboard uses the entry with `mountpoint` `/` and its `total_bytes` and `used_bytes`. Figures are shown in binary units (GiB), so a decimal-unit UI may show a slightly larger total.

## Interfaces

`interfaces.overview` needs the **Status: Interfaces** privilege in addition to Lobby: Dashboard. It returns a search-style result (`rows`). The backend keeps identifier, description, device, status, enabled, link type, IPv4/IPv6 addresses, gateways and VLAN tag, and drops MAC addresses, counters and other fields. Verified on 26.7.8_2: LAN, WAN and loopback rows returned identifier-derived descriptions, devices, status, IPv4/IPv6 addresses and gateways; unassigned system interfaces (enc0, pflog0) come back with description `Unassigned Interface` and no `enabled` flag.

## Firewall rules

`firewall.rules.list` needs **Firewall: Rules [new]**. That privilege also covers the rule write endpoints under `/api/firewall/filter/*`, so grant it only to a lab or trusted API user; this app only reads. The result is search-style (`rows`) with flags as "0"/"1" strings. The backend keeps uuid, enabled, action, interface, direction, IP protocol, protocol, source/destination network and port, description, log and sequence. It drops categories, statistics and other metadata, and caps the list at 2000 rules. Verified on 26.7.8_2: user rules come back with sequence and interface, and the list also includes auto-generated system rules (default deny, IPv6 ICMP, sshlockout, DHCP, anti-lockout) that have no sequence, and sometimes no interface (floating).
