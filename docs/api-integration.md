# OPNsense API Integration

Status: nine read-only operations verified. New endpoints must be verified against a lab OPNsense before `verified=True`.

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
| `firewall.aliases.list` | GET | `/api/firewall/alias/searchItem` | Firewall: Aliases | yes | no | 26.7.8_2 | yes |
| `firewall.aliases.add` | POST | `/api/firewall/alias/addItem` | Firewall: Alias: Edit | no | yes | 26.7.8_2 | yes |
| `firewall.aliases.reconfigure` | POST | `/api/firewall/alias/reconfigure` | Firewall: Alias: Edit | no | no | 26.7.8_2 | yes |
| `firewall.aliases.update` | POST | `/api/firewall/alias/setItem/{uuid}` | Firewall: Alias: Edit | no | yes | 26.7.8_2 | yes |
| `firewall.aliases.delete` | POST | `/api/firewall/alias/delItem/{uuid}` | Firewall: Alias: Edit | no | yes | 26.7.8_2 | yes |
| `firewall.rules.add` | POST | `/api/firewall/filter/addRule` | Firewall: Rules [new] | no | yes | 26.7.8_2 | yes |
| `firewall.rules.update` | POST | `/api/firewall/filter/setRule/{uuid}` | Firewall: Rules [new] | no | yes | 26.7.8_2 | yes |
| `firewall.rules.delete` | POST | `/api/firewall/filter/delRule/{uuid}` | Firewall: Rules [new] | no | yes | 26.7.8_2 | yes |
| `firewall.rules.toggle` | POST | `/api/firewall/filter/toggleRule/{uuid}` | Firewall: Rules [new] | no | yes | 26.7.8_2 | yes |
| `firewall.rules.apply` | POST | `/api/firewall/filter/apply` | Firewall: Rules [new] | no | no | 26.7.8_2 | yes |
| `firewall.log` | GET | `/api/diagnostics/firewall/log` | Diagnostics: Logs: Firewall: Live View | yes | no | 26.7.8_2 | yes |
| `firewall.nat.port_forwards.list` | GET | `/api/firewall/d_nat/searchRule` | Firewall: NAT: Destination NAT | yes | no | 26.7.8_2 | yes |
| `firewall.nat.outbound.list` | GET | `/api/firewall/source_nat/searchRule` | Firewall: NAT: Source NAT | yes | no | 26.7.8_2 | yes |
| `traffic.interfaces` | GET | `/api/diagnostics/traffic/interface` | Reporting: Traffic | yes | no | 26.7.8_2 | yes |
| `firewall.nat.port_forwards.add` | POST | `/api/firewall/d_nat/addRule` | Firewall: NAT: Destination NAT | no | yes | 26.7.8_2 | yes |
| `firewall.nat.port_forwards.update` | POST | `/api/firewall/d_nat/setRule/{uuid}` | Firewall: NAT: Destination NAT | no | yes | 26.7.8_2 | yes |
| `firewall.nat.port_forwards.delete` | POST | `/api/firewall/d_nat/delRule/{uuid}` | Firewall: NAT: Destination NAT | no | yes | 26.7.8_2 | yes |
| `firewall.nat.port_forwards.enable` | POST | `/api/firewall/d_nat/toggleRule/{uuid}/0` | Firewall: NAT: Destination NAT | no | yes | 26.7.8_2 | yes |
| `firewall.nat.port_forwards.disable` | POST | `/api/firewall/d_nat/toggleRule/{uuid}/1` | Firewall: NAT: Destination NAT | no | yes | 26.7.8_2 | yes |
| `firewall.nat.port_forwards.apply` | POST | `/api/firewall/d_nat/apply` | Firewall: NAT: Destination NAT | no | no | 26.7.8_2 | yes |

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

## Firewall aliases

`firewall.aliases.list` needs **Firewall: Aliases**, which in the OPNsense source covers `api/firewall/alias/search*`, `list*`, `get*` and `export`; the Edit privilege (add, set, delete) is separate. The result is search-style (`rows`) with `content` as one string. On 26.7.8_2 the entries are newline-separated; the normaliser also accepts commas. The backend keeps uuid, name, type, enabled, description and content (split into a list, at most 200 items per alias, 1000 aliases), and drops categories. Verified on 26.7.8_2: system aliases (bogons, sshlockout, virusprot, `__lan_network`, ...) have empty content, and a test host alias returned both entries.

## Alias writes (staged flow, ADR-0005)

`firewall.aliases.add` and `firewall.aliases.reconfigure` are only called from the reviewed apply
procedure (`backend/app/changes/apply.py`), never directly by an endpoint, and only for firewalls
with `allow_writes` on. They need **Firewall: Alias: Edit**. `addItem` saves the alias on the
firewall without activating it; `reconfigure` activates it. Both are never retried. Both were verified on the lab (26.7.8_2) on 2026-11-11: the body
(`{alias: {enabled, name, type, content, description}}`, content newline-separated) was accepted, the
replies were `result: saved` and `status: ok`, and the alias appeared in the read-back.

`firewall.aliases.update` (`setItem/{uuid}`) and `firewall.aliases.delete` (`delItem/{uuid}`) take one
declared `{uuid}` path slot, filled only with a canonical lowercase UUID. Both were verified on the lab
(26.7.8_2) on 2026-11-12 through the full staged flow. `setItem` is an upsert, so apply re-reads the
alias list first and refuses (status `stale`) if the alias is gone or differs from the recorded base.
Update cannot rename or change the type. Delete is always high risk. The wording for a delete refused
because the alias is in use is still unverified on the wire.

## Rule writes (staged flow, ADR-0005 step 6)

`firewall.rules.toggle` and `firewall.rules.apply` (`filter/apply`, activates saved rule changes) were verified on the lab (26.7.8_2) on 2026-11-12 through the full staged flow: disable, then enable, a user rule. Apply compares the rule's normalised state with the state recorded at staging and refuses (`stale`) on any difference. Add, update and delete remain unverified. There is no savepoint/revert on master, so undo is a new reviewed request.

`firewall.rules.add` (`addRule`) is called only from the reviewed apply for rule creation. Body `{rule: {...}}` with the narrow field set (enabled, sequence, action, quick=1, interface, direction, ipprotocol, protocol, source_net, source_port, destination_net, destination_port, log, description). The new rule gets a sequence one above the highest existing sequence; it is never left to the firewall default (1, which would put it first). Create has no before-state, so apply re-checks that the description is still unused and that every named alias still exists as the right kind (port alias for ports, otherwise not). Verified on the lab (26.7.8_2) on 2026-11-12: the rule was created through the full staged flow and appeared on the firewall as proposed.

`firewall.rules.update` (`setRule/{uuid}`) and `firewall.rules.delete` (`delRule/{uuid}`) are called only from the reviewed apply. Update keeps the rule's interface, description and sequence; delete is always high risk. Both were verified on the lab (26.7.8_2) on 2026-11-12 through the full staged flow.

`firewall.log` is read-only. It returns the newest packet-filter records (default 1000 from the firewall; the backend keeps the newest 200 and only the fields the Logs page shows: time, action, interface, direction, protocol, addresses, ports, rule label, reason). Digests, TCP internals and raw lines are dropped. Viewing is limited to admin, network_admin and security_admin because logs expose internal traffic. Verified on the lab (26.7.8_2) on 2026-11-12 with the privilege Diagnostics: Logs: Firewall: Live View.

Live view: the Logs page's Live toggle polls `GET /api/v1/firewalls/{id}/firewall/logs/new?since=<cursor>` every 4 seconds. The cursor is the digest of the newest record from the previous response; the backend passes it to `firewall.log` as the `digest` query parameter (with `limit=200`) and returns only records newer than it. This reuses `firewall.log`, so it adds no registry operation, privilege or stream. It was chosen over sampling `stream_log` because that stream replays the last 5 lines on every connection and ADR-0004 caps a sample at 3 events, which would drop the newest entries. Registry operations declare the query parameter names they accept (`query_params`); values must be short alphanumerics.

NAT is read-only for now. Port forwards come from `d_nat/searchRule` (dotted field names such as `destination.network` and `local-port`, a `disabled` flag, `nordr` for "no redirect"); outbound rules come from `source_nat/searchRule` (`source_net`, `target`, `enabled`, `nonat` for "do not NAT"). Outbound results also include automatic rules (`is_automatic`) depending on the firewall's outbound mode. The backend keeps only the display fields, caps the list at 2000, and drops categories and audit metadata. Both privileges also cover the matching write endpoints (`/api/firewall/d_nat/*`, `/api/firewall/source_nat/*`), so grant them only to a lab or trusted API user; this app does not write NAT. Both operations were verified on the lab (26.7.8_2) on 2026-11-12: port forward and outbound lists matched the firewall's own NAT pages.

Port forward changes (ADR-0006) use the `firewall.nat.port_forwards.*` write operations, called only from the reviewed apply procedure for `nat_forward` requests. Apply re-reads the forwards (stale check by fingerprint), saves with `addRule` or `setRule/{uuid}`, activates with `d_nat/apply`, then reads back. `pass` is always sent blank (Manual) on create so no filter rule is registered, and pool options, NAT reflection and `nordr` are fixed to defaults; update omits those fields. Toggle uses the explicit `toggleRule/{uuid}/0` (enable) or `/1` (disable) forms, never the flip default. All six operations were verified on 26.7.8_2: create, edit, disable, enable and delete behaved as described, and a created forward has no filter rule association.

Traffic (ADR-0007) uses only the plain `traffic/interface` snapshot: cumulative byte and packet counters per interface, keyed by interface identifier with a friendly `name`. The backend normalises it to in/out bytes and packets, caches it for 2 s per firewall, and stores nothing. The browser works out rates from consecutive polls. Verified on the lab (26.7.8_2) with the privilege Reporting: Traffic. Limited to admin, network_admin and security_admin.
