# Security Requirements

| Area | Requirement |
|---|---|
| API credentials | Backend only, encrypted at rest |
| Transport | HTTPS/TLS to the app and to OPNsense (certificate verification on by default) |
| Authentication | Secure login, session cookies (HttpOnly, Secure, SameSite), expiry, logout |
| Authorisation | RBAC: admin, network_admin, security_admin, read_only. Default deny |
| API permissions | Least-privilege OPNsense API keys |
| Input validation | Pydantic schemas on every request |
| CSRF | Required for all state-changing requests |
| Audit | User, action, firewall, timestamp, outcome, independent of OPNsense logs |
| Rate limiting | All endpoints; stricter on login |
| Network | Restrict to trusted networks or VPN |
| Client | No credentials or firewall data in localStorage or service-worker caches |
| Changes | Staged, validated, reviewed, explicitly applied; stale-revision detection; locking |

High-impact actions (reboot, shutdown, firmware upgrade, rule deletion, disabling WAN/LAN/management interfaces) need extra confirmation and elevated privilege.
