# ADR-0023: Near-real-time traffic over a backend SSE stream

- Status: accepted and implemented (approved by project owner on 2026-11-15)
- Date: 2026-11-15
- Deciders: project owner

## Context

The Traffic page polls `GET /firewalls/{id}/traffic` every 5 s (ADR-0007). The owner wants a near-real-time chart.

Two earlier decisions rejected a long-lived backend-to-browser stream:

- ADR-0007 rejected using OPNsense's `traffic/stream` because it needs a long-lived stream per firewall.
- ADR-0004 rejected relaying a firewall stream to the browser because of connection count, attack surface and firewall load. It noted that a later relay would need an ADR-0001 amendment.

This ADR changes that decision in a narrow way. It does not relay OPNsense's stream. The backend keeps using the plain snapshot call and pushes the result to the browser.

Other facts:

- The snapshot is cached for 2 s per firewall, so polling faster than 2 s returns repeated samples. The browser's `addSample` treats a sample that is not newer as a reset of that interface's series, so naive 1 s polling would draw gaps.
- Counters are cumulative, so the rate for a sample needs the previous one.
- The backend is sync FastAPI with sync SQLAlchemy.
- Caddy fronts everything, and the service worker already never caches `/api`.

## Decision

1. **Source:** unchanged. The existing registry operation `traffic.interfaces` (`GET /api/diagnostics/traffic/interface`). OPNsense's own `traffic/stream` is still not used. No registry change.
2. **Endpoint:** `GET /api/v1/firewalls/{id}/traffic/stream`, `text/event-stream`, read-only.
   - Roles: the same as `/traffic` (admin, network_admin, security_admin). Default deny.
   - Each event is `data:` JSON in the existing `TrafficOut` shape. A comment line (`: keep-alive`) goes out every 15 s.
3. **Shared sampler:** one upstream snapshot per firewall per second, shared by all subscribers of that firewall. It runs only while at least one subscriber is connected and stops when the last one leaves. Firewall load is one call per second per firewall however many tabs are open. The shared fetch uses its own 1 s coalescing, and the existing 2 s cache for `/traffic` is untouched.
4. **Bounds:**
   - at most 3 open streams per user, 10 per firewall and 50 per process; extra requests get 429
   - a stream ends after 10 minutes; the browser reconnects, which re-checks the session, the role and that the firewall still exists
   - the stream ends at once if the session is revoked or expires
   - after 3 consecutive upstream failures the stream sends one `error` event with a collapsed message (as for non-admin errors elsewhere) and closes
5. **Audit:** one audit record when a stream opens and one when it closes, with the user, firewall and reason. Individual samples are not audited, because a record per second would flood the audit log.
6. **Security:** GET only, no state change, so CSRF does not apply. The session cookie is the only credential; `EventSource` is same-origin. Nothing from OPNsense reaches the browser except the fields `/traffic` already returns.
7. **Frontend:**
   - The Traffic page opens an `EventSource` and feeds each event to the existing `addSample`.
   - On error it falls back to the current 5 s polling, and retries the stream after a pause.
   - It closes the stream while the tab is hidden and reopens it when the tab is visible.
   - It selects the correct firewall on change by closing and opening the stream.
   - Card text is updated to say "about every second".
8. **Proxy:** Caddy gets `flush_interval -1` for the stream path so events are not buffered, and the path is excluded from compression. A test checks the real stack, not only the backend.
9. **Service worker:** no change. `/api` stays uncached, and the build check keeps enforcing it.
10. **Multiple workers:** the sampler and the limits are per process, like the in-memory rate limit. With more than one worker the per-firewall load is one call per second per worker. The deployment doc records this.

## Consequences

- Chart updates about every second with a bounded, shared firewall load.
- This is the project's first long-lived HTTP connection to browsers, so there is new surface: connection exhaustion, idle connections and proxy buffering. The caps above and the reconnect-and-recheck cycle limit those.
- Each stream holds one connection but no thread while idle if built with an async generator; the blocking fetch runs in a worker thread, one per firewall rather than one per viewer.
- The rate is only as fresh as OPNsense's counters. If they update less often than once a second, repeated samples are skipped by the browser and the chart looks like the slower rate. This is checked on the UniFi record (read-only) before building.
- ADR-0007 decision 4 (5 s polling) is superseded for browsers that can use the stream. Polling remains the fallback. ADR-0004's note about a future relay is satisfied by this ADR.

## Alternatives considered

- **Poll every 1-2 s.** One line to change, but every tab adds a request per second to the firewall path, and 1 s hits the 2 s cache. Fine for a single user, poor for many.
- **WebSocket.** The page only needs server-to-browser data, so SSE is simpler and works through Caddy with fewer settings.
- **Relay OPNsense's `traffic/stream`.** Rejected in ADR-0004 and ADR-0007. It would hold a long connection to the firewall per viewer, and its payload is unverified.
- **Background poller storing samples in PostgreSQL.** Gives history across reloads but adds a worker and storage. Still a later metrics phase.

## Test plan

- Unit: the sampler starts for the first subscriber, stops for the last, and shares one upstream call per second across subscribers.
- API: role check (read_only gets 403), per-user, per-firewall and per-process caps, 10-minute cut-off, ended session closes the stream, collapsed error after repeated upstream failures, and the open and close audit records.
- Frontend: samples feed the chart, a stream error falls back to polling, a hidden tab closes the stream.
- Live on the disposable stack through Caddy: events arrive about once a second, not buffered, and uncompressed.
- Lab: read-only check that counters change between samples (done, see Counter check). The one-second cadence is confirmed through the stream itself on the lab.

## Counter check

Done read-only on 2026-11-15 on two OPNsense records (9 and 2 interfaces), calling `/traffic` twelve times at about 1.1 s intervals. The 2 s cache meant each record answered with a new sample about every 2.4 s. Every new sample had a later firewall `time` and higher byte counters, so the counters are read live on each call and are not refreshed on a slow timer. This does not show the counters at one-second granularity, because the cache hid it. The sampler calls the snapshot directly every second, and its first live run shows whether consecutive samples differ. If they often repeat, the browser skips them and the chart simply updates at the counters' own rate.

## Outcome

- Built as described. The hub is `backend/app/opnsense/traffic_stream.py`, the endpoint is `backend/app/api/traffic_stream.py`, and the browser hook is `frontend/src/features/traffic/use-traffic-stream.ts`.
- Audit action names: `firewall.traffic.stream_open`, `firewall.traffic.stream_close` and `firewall.traffic.stream_denied` (a refused stream gets its own throttled record).
- A stream also ends with `session_ended` when the account is deactivated, loses its role, or must change its password, not only when the session expires. This is re-checked every 15 s.
- Editing or deleting a firewall ends its streams (`firewall_changed`), so a changed address or credential is never used by an old stream.
- Checked on the lab through Caddy on two OPNsense records: events arrived 0.93-1.05 s apart, and each had a newer firewall timestamp, so the counters do refresh every second.
- Not covered: more than one backend worker. Each would run its own sampler and keep its own limits.

