# Roadmap

| Phase | Scope | Priority |
|---|---|---|
| 1 | Foundation, OpenCode setup, authentication, API connectivity, dashboard | P0 |
| 2 | Interface monitoring, firewall rules, aliases | P0 |
| 3 | NAT, firewall logs, traffic monitoring (done) | P1 |
| 4 | VPN, DHCP, DNS, service management (read-only views done; service start, stop and restart built per ADR-0016, pending the lab test; Dnsmasq static hosts and domain overrides built per ADR-0017 and lab-verified; VPN and Unbound changes need their own ADRs) | P1 |
| 5 | Audit logging, advanced security, multi-firewall (done: audit viewer, TOTP MFA, user management, PostgreSQL login limits, multi-firewall overview) | P2 |
| 6 | Analytics, notifications, automation | P2 |

MVP: secure connection to OPNsense, health/interface/resource view, rule management, logs and blocked traffic, alias management with apply.

Note: audit logging and multi-firewall `firewall_id` plumbing are needed from Phase 1 even though the brief schedules their full features later.
