# ADR-0007: Interface traffic monitoring

- Status: accepted
- Date: 2026-11-12
- Deciders: project owner

## Context

Phase 3 includes traffic monitoring. OPNsense exposes `GET /api/diagnostics/traffic/interface`, a plain
JSON snapshot of cumulative byte and packet counters per interface (from the source on master; not yet
checked on 26.7.8_2). It also has an SSE stream (`traffic/stream`) and a top-talkers call
(`traffic/top/{interfaces}`), which lists internal hosts.

Counters are cumulative, so a rate needs two samples.

## Decision

1. **Source:** only the plain `traffic/interface` snapshot. The SSE stream and top talkers are not used.
   No new long-lived connection exists between the browser, the backend or the firewall.
2. **Registry:** new operation `traffic.interfaces`, `GET /api/diagnostics/traffic/interface`,
   `read_only=True`, `verified=False` until checked on the lab. The privilege is confirmed on the lab
   and recorded in `docs/api-integration.md`.
3. **Backend:** `GET /api/v1/firewalls/{id}/traffic` returns normalised rows
   `{interface, in_bytes, out_bytes, in_packets, out_packets}` plus the sample time. The result is cached
   for 2 s per firewall so several open pages cause one firewall call. The backend stores nothing.
4. **Rates:** computed in the browser from the difference between two polls (every 5 s). The browser keeps
   about 5 minutes of history in memory. A counter that decreases (reboot, interface reset) restarts that
   interface's series instead of drawing a spike. Polling pauses while the page is hidden.
5. **Frontend:** a Traffic page with an in/out line chart per interface and a table of current rates,
   drawn with `recharts` (already approved in ADR-0003, no new dependency).
6. **Access:** admin, network_admin and security_admin. `read_only` is excluded, as for logs, because
   usage patterns are sensitive. Audited like other firewall calls.

## Consequences

- No worker, no PostgreSQL storage and no stream handling. History is lost on page reload.
- Rates are only as accurate as the 5 s poll; the first sample has no rate.
- Long history across restarts needs a background poller and storage: a later metrics phase.

## Alternatives considered

- **SSE `traffic/stream`.** Real-time, but needs a long-lived stream per firewall (see ADR-0004).
- **Top talkers.** Exposes internal host addresses and needs its own decision.
- **Hand-drawn SVG chart.** No library, but more code to maintain; recharts is already approved.
- **Background poller storing samples.** Gives history, but adds a worker and storage.
