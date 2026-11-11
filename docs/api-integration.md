# OPNsense API Integration

Status: three read-only operations verified. New endpoints must be verified against a lab OPNsense before `verified=True`.

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

Observed response fields (non-secret):
- `system_information`: `name` (hostname), `versions` (list of strings), `updates` (text).
- `system_time`: `uptime`, `datetime`, `boottime`, `config`, `loadavg`.

## Candidates for the dashboard (not yet in the registry, unverified)

From the OPNsense ACL definition (master branch), also under "Lobby: Dashboard": `system_resources` (memory), `system_disk`, `system_swap`, `system_temperature`, `cpu_usage`, `pf_states`. Verify each against the lab before adding.
