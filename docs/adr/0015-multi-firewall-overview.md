# ADR-0015: Multi-firewall overview

- Status: accepted
- Date: 2026-11-14
- Deciders: project owner

## Context

Every operation already takes a `firewall_id`, and the Dashboard shows one firewall at a time
through a selector. With more than one firewall record, an operator has to switch the selector to
learn which firewall is down or running hot. The roadmap lists "multi-firewall" for Phase 5.

The existing per-firewall status call (`/system/status`) makes up to five OPNsense requests (status,
time, resources, CPU, disk) and writes one audit row for each. Polling it for every firewall would
multiply both the load on the firewalls and the size of the audit log.

## Decision

1. **Read-only roll-up.** New page "Overview" (route `/overview`, first item under Dashboard in the
   navigation) with one row or card per firewall: name, reachable or not, hostname, version, uptime,
   CPU, memory and disk usage, and a link to that firewall's Dashboard. No write operation, no new
   OPNsense endpoint and no new registry operation: it reuses the existing `system.status`,
   `system.time`, `system.resources` and `system.disk` operations and their normalisers.
2. **Endpoint:** `GET /api/v1/firewalls/overview`, any signed-in role (same as the firewall
   selector). It returns one entry per firewall record, with the same fields the Dashboard already
   exposes. No URL, credential or TLS detail is included.
3. **Roles and error detail:** non-admin users see `reachable` or `unreachable` only, as on the
   Dashboard (`public_status`). Admins also see the specific status and message.
4. **Bounded fan-out:**
   - At most 4 firewalls are queried at the same time, and each firewall has a total time budget of
     10 seconds. A slow or dead firewall shows as `unreachable` for that row and never delays the
     others beyond that budget.
   - The overview is capped at 50 firewalls. Beyond that the response says `truncated`.
   - CPU is taken from the existing sampler cache only. The overview never starts a new CPU sample
     stream, so it adds no streaming load.
5. **Server-side cache:** each firewall's result is kept for 15 seconds. Several browsers, or a
   short refresh interval, cannot make the backend query a firewall more than about four times a
   minute. A "Refresh now" button bypasses the cache at most once per 15 seconds per firewall.
6. **Audit:** one record per overview request, action `firewall.overview`, with counts only
   (firewalls queried, reachable, unreachable). The per-operation audit rows are not written for
   overview calls, so a refreshing page does not flood the log. Failures against a specific firewall
   are still recorded in that record's detail by firewall id. This is a deliberate exception to
   "one audit row per firewall call". It applies to this read-only endpoint only.
7. **Browser:** the page refreshes every 60 seconds by default (options 30 s, 60 s, off). The
   interval is in memory only. The service worker does not cache the response.
8. **Capability registry:** the endpoint is listed as a composite of existing read-only operations,
   so the registry test that lists reachable operations still holds. No operation is added.
9. **No schema change and no dependency.** No migration.
10. **Tests:** backend tests mock OPNsense (`respx`) for mixed up and down firewalls, the role
    difference in error detail, the concurrency and time budget, the cache, the audit rows, and RBAC.
    Frontend tests cover rendering, the role view and refresh. The live end-to-end test is not
    extended, since the disposable stack has no firewall.

## Consequences

- One screen answers "which firewall needs attention?" without switching.
- Load on each firewall is bounded (about four requests per minute per operation) regardless of how
  many people have the page open.
- The audit log records an overview as one entry, which is less detailed than the per-operation rows
  of the Dashboard. The audit stays complete about who looked and when.
- Firewall names and up or down state are visible to every signed-in role. Names are already visible
  in the selector, so this adds only up or down state and the headline numbers the Dashboard shows.
- A firewall that times out costs up to 10 seconds of that request. The page shows the rest as soon
  as the response arrives, and the whole request is bounded by the slowest budget, not the sum.

## Alternatives considered

- **Poll each firewall's full `/system/status` from the browser.** Rejected: up to five OPNsense
  requests and five audit rows per firewall per poll.
- **Server-sent events with a background poller.** Rejected for now: a permanent background job and
  more moving parts. The cache already gives bounded load.
- **Aggregate rules, alerts or traffic across firewalls.** Out of scope. This is a health summary
  only. A cross-firewall rule or alias view would need its own decision.
- **Restrict the overview to admins.** Possible. Not chosen, because the Dashboard already shows the
  same data to every role.
- **Keep per-operation audit rows.** Rejected for the reason above. It is the main point where the
  owner may prefer a different trade-off.
