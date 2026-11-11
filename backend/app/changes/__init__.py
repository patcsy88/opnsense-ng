"""Staged change management (ADR-0005). Status machine and service; no OPNsense calls yet.

Planned workflow for every state-changing firewall configuration operation:

1. stage    - the user submits a change; it is stored as a staged change against a
              ``firewall_id`` together with the firewall revision it was based on.
2. validate - schema and semantic validation (and OPNsense-side validation where the
              API offers it). Nothing is applied yet.
3. review   - a user with sufficient privilege reviews the diff. High-impact actions
              (reboot, shutdown, firmware upgrade, rule deletion, disabling WAN/LAN/
              management interfaces) need extra confirmation and elevated privilege.
4. apply    - explicit apply. The base revision is re-checked (stale-revision detection)
              and a per-firewall lock (PostgreSQL row lock) prevents concurrent overwrites.
              Every step is written to the audit log.
"""
