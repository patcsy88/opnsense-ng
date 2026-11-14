# Security Requirements

| Area | Requirement |
|---|---|
| API credentials | Backend only, encrypted at rest |
| Transport | HTTPS/TLS to the app and to OPNsense (certificate verification on by default) |
| Authentication | Secure login, session cookies (HttpOnly, Secure, SameSite), expiry, logout |
| Multi-factor | TOTP (RFC 6238) required for every role by default (`MFA_REQUIRED_ROLES`). Two-step login with no session after the password step; challenge is single use, 5 minutes, 5 attempts. Secret encrypted at rest, codes single use, recovery codes hashed. Users who have not enrolled get a restricted session (ADR-0012) |
| User management | Admin-only (ADR-0013): create, change role, deactivate or reactivate, reset password, reset MFA. Temporary passwords are random, shown once, never logged or audited, and force a change at first sign-in (other endpoints answer 403 `password_change_required`). Role change, deactivation and resets end the target's sessions. The last active admin and an admin's own account are protected. Resetting someone's MFA needs the admin's password and code. Users are never deleted |
| Authorisation | RBAC: admin, network_admin, security_admin, read_only. Default deny |
| API permissions | Least-privilege OPNsense API keys |
| Input validation | Pydantic schemas on every request |
| CSRF | Required for all state-changing requests |
| Audit | User, action, firewall, timestamp, outcome, independent of OPNsense logs |
| Multi-firewall overview | `GET /api/v1/firewalls/overview` (ADR-0015), read-only, any signed-in role. Non-admins see only reachable or unreachable. At most 4 firewalls are queried at once, 10 s budget each, 50 firewalls maximum, results cached 15 s per firewall, CPU from the sampler cache only. One audit row per request (`firewall.overview`, counts and unreachable ids only) instead of one per operation: a deliberate exception for this endpoint. The response is never cached by the service worker |
| Service control | Start, stop and restart (ADR-0016): admin only, direct (not staged), `allow_writes` required, CSRF, 10 actions per minute per user. The backend re-reads the live service list and refuses unknown or `locked` services; `configd` and `webgui` cannot be stopped or restarted; stopping or restarting a high-impact service (DNS, DHCP, VPN, NTP, syslog) needs its name typed. One action at a time per firewall (advisory lock). OPNsense answers `ok` when the command is queued, so the result is read back for up to 10 s and reported as confirmed or not confirmed. One audit row per action, refusals included. The lab API user's `Status: Services` privilege covers both listing and control (unverified until the lab test) |
| Rate limiting | All endpoints; stricter on login. The login limits (`POST /auth/login`, `POST /auth/login/mfa`, `LOGIN_RATE_LIMIT`, default 5/minute per IP) are counted in PostgreSQL, so they are exact across restarts and backend processes (ADR-0014). The general limit (`DEFAULT_RATE_LIMIT`) is in memory per process |
| Network | Restrict to trusted networks or VPN |
| Client | No credentials or firewall data in localStorage or service-worker caches |
| Changes | Staged, validated, reviewed, explicitly applied; stale-revision detection; locking |

High-impact actions (reboot, shutdown, firmware upgrade, rule deletion, disabling WAN/LAN/management interfaces) need extra confirmation and elevated privilege.
