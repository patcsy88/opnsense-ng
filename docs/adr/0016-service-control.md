# ADR-0016: Service start, stop and restart

- Status: accepted
- Date: 2026-11-14
- Deciders: project owner

## Context

The Services page lists the firewall's services and whether each is running (read-only). The
owner wants to start, stop and restart them.

What OPNsense does (from `opnsense/core` master, `Core/Api/ServiceController.php`; **to be
confirmed on the 26.7.8_2 lab before any operation is marked verified**):

- `POST /api/core/service/start/{name}/{id}`, `.../stop/...` and `.../restart/...`. `id` is an
  optional instance id (for example a WireGuard or OpenVPN instance).
- Every call answers `{"result":"ok"}` as soon as the command is queued with configd. It does not
  say whether the service actually came up or went down. Success is only known by reading the
  service list again.
- The list call (`search`) is in the same controller, so the privilege the lab API user already
  has for reading services (`Status: Services`) may also allow control. If so, nothing in OPNsense
  limits this app to reading, and our own controls are the only guard.
- Rows flagged `locked` are services OPNsense itself does not let you control from its UI.
- There is no dry run and no undo. Restarting is the only quick way back from a stop.

This is not a config change. Nothing is saved or reviewed on the firewall, so the staged flow of
ADR-0005 (draft, review, apply, stale check) does not fit. But stopping the wrong service can cut
off DNS, DHCP, the VPN or the management interface, so it is high impact.

## Decision

1. **Direct action, not staged.** Start, stop and restart run immediately from the Services page
   once confirmed. No change request, no second approver. The controls below replace the review.
2. **Roles:** `admin` only. Everyone else sees the page read-only, as today. (Alternative below.)
3. **`allow_writes` required.** The firewall's `allow_writes` flag (off by default, admin-only to
   change) must be on, otherwise the action is refused with 403. The Services page hides the
   buttons for firewalls where it is off and says why.
4. **Only services the firewall reports.** The backend never builds a path from free text. For
   each request it reads the service list fresh, requires that the `name` and optional instance
   exist in it, and only then calls the fixed endpoint. Names also match
   `^[A-Za-z0-9_.-]{1,64}$`. Services marked `locked` are refused.
5. **Protected services.** Stop and restart are refused for the services that carry the management
   path itself: `configd` and `webgui` (the web interface and API this app talks to). The list is
   a constant in the code, not a setting, and is shown in the UI as "not available here".
6. **Extra confirmation.**
   - Start: a normal confirm dialog.
   - Restart and stop: a confirm dialog that names the service and the firewall.
   - Stop (and restart) of a **high-impact** service (`unbound`, `dnsmasq`, `wireguard`,
     `openvpn`, `ipsec`, `dhcpd` and other DHCP or DNS services, `ntpd`, `syslog-ng`) needs the
     service name typed. Every other service is treated as normal.
7. **Result is read back, not assumed.** After the call the backend polls the service list for up
   to 10 seconds (every 1 s) until the service shows the expected state: running after start or
   restart, stopped after stop. The response says `confirmed` or `not_confirmed` with the observed
   state. The UI never shows success on the strength of `result: ok`. For restart, the backend
   cannot tell a fast restart from "nothing happened", so it reports the observed running state
   only and says so.
8. **Bounded and serialised.** One service action at a time per firewall (a PostgreSQL advisory
   lock, as in the apply procedure). A request that finds the lock held gets 409. Rate limit 10
   service actions per minute per user.
9. **Audit.** One row per action: `firewall.service.start`, `.stop` or `.restart`, with the user,
   firewall, service name and instance, the state before, the state observed after, and the
   outcome. Refusals (`allow_writes` off, locked, protected, unknown service, role) are audited
   as failures with the reason. No secrets are involved.
10. **Registry.** Three new write operations (`services.start`, `services.stop`,
    `services.restart`), `read_only=False`, `verified=False` until the lab test. The registry's
    path model today allows only a trailing `{uuid}`, so it gains one more declared parameter
    kind, `{service}` with an optional `{instance}`, validated by the regex above before the URL
    is built. Free text still never reaches a URL.
11. **Frontend.** Start, Stop and Restart buttons per row for admins on firewalls with
    `allow_writes` on, a confirm dialog per decision 6, a busy state while the backend reads the
    state back, and the observed result shown plainly ("Stopped, confirmed" or "Still running
    after 10 s"). The list refetches afterwards. The service worker already does not cache the
    API.
12. **Privilege on the lab.** If the current lab API user can already control services through
    `Status: Services`, that is recorded in the registry notes and in the security docs. A
    narrower privilege is not available for this controller, so no change to the key is needed.
13. **Tests.** Mocked OPNsense (`respx`): each action, read-back confirmed and not confirmed,
    the fresh-list check, unknown service, locked and protected refusals, `allow_writes` off,
    non-admin 403, CSRF, the advisory lock (409), rate limit, audit rows, path safety. Frontend
    tests for buttons, dialogs and the typed confirmation. The live end-to-end test is not
    extended (no firewall in the disposable stack). The lab test uses a harmless service
    (restart `ntpd` or stop and start a test service) with the owner present.
14. **No new dependency and no migration.**

## Consequences

- One mistaken click on a high-impact service can interrupt DNS, DHCP or a VPN until someone
  starts it again. Mitigated by admin only, `allow_writes`, the typed name, and the protected list.
- There is no review step. If the owner wants four-eyes for stops, that needs a staged variant and
  a separate decision.
- `result: ok` carries no information, so the 10 second read-back is the real answer. A service
  that takes longer to stop shows as `not_confirmed` even if it later succeeds. The page refetches
  so the true state appears on the next refresh.
- The backend holds a request open up to about 10 seconds per action.
- The protected list is short and static. A service that is not on it but that the owner depends
  on (for example the one carrying the lab's VPN) is protected only by the typed confirmation.

## Alternatives considered

- **Stage service actions through the change flow.** Rejected for now: heavy for a runtime action
  with no config to diff, and it would make restarting a stuck service slow. It remains an option
  if four-eyes is wanted.
- **Let `network_admin` restart and start, admin only for stop.** Possible and more useful for
  day to day work. Not chosen to keep the first release strict. Easy to loosen later.
- **Restart only, no stop.** Safer, but the owner asked for all three.
- **Step-up check (password or TOTP code) before a stop.** Not included. It fits the existing
  MFA reset pattern if the owner wants it for high-impact stops.
- **Fire and forget with no read-back.** Rejected: `ok` is returned even when nothing happened.
- **An editable allow or deny list in settings.** Rejected: a hard-coded protected list cannot be
  weakened by a mistaken setting.
