# ADR-0004: Bounded stream sampling for OPNsense SSE endpoints

- Status: accepted
- Date: 2026-11-11
- Deciders: project owner

## Context

CPU usage is only available from `GET /api/diagnostics/cpu_usage/stream`, a Server-Sent Events
endpoint that runs `configd` `system cpu stream` and emits a sample about every second, forever.
The existing client (`OPNsenseClient._once`) reads one complete JSON body, so it cannot consume it.
The privilege is the same as the other dashboard calls ("Lobby: Dashboard").

A naive pass-through would let a browser hold a long-lived connection that holds a long-lived
connection to the firewall. That breaks ADR-0001 (the browser never talks to OPNsense) in spirit
and creates a resource-exhaustion risk on the firewall.

## Decision

Add a **bounded sampler** to the backend. The stream is never exposed to the browser.

1. **Registry:** new `Operation` kind `stream` (new field `response_kind`: `json` | `sse`, default
   `json`). `cpu.usage` is declared `GET /api/diagnostics/cpu_usage/stream`, `read_only=True`,
   `response_kind="sse"`, `verified=False` until checked on the lab. `execute()` rejects `sse`
   operations; a separate `sample_stream(operation_id, max_events=1, timeout_s=3)` accepts only them.
2. **Client:** `sample_stream` uses `httpx.stream`, same pinned transport, TLS context, target
   policy and error mapping as `_once`. It reads SSE `data:` lines, parses JSON, returns after
   `max_events` events or `timeout_s` (whichever first), then closes the connection. Hard caps:
   `max_events <= 3`, `timeout_s <= 5`, line length <= 64 kB, total bytes <= 256 kB. No retries
   (a failed sample is simply absent).
3. **API:** CPU is added to `GET /firewalls/{id}/system/status` as best-effort `cpu_used_percent`
   (nullable), like memory. The browser keeps polling the existing endpoint; no new long-lived
   connection exists between browser and backend.
4. **Concurrency guard:** at most one sampling stream per firewall at a time
   (in-process lock keyed by firewall id; overlapping requests get `null`). Result is cached for
   5 s per firewall so several open dashboards cause one stream, not many.
5. **Normaliser:** tolerant mapping of the sample to a 0-100 float; bad shapes give `null`.
   The exact event payload is unknown (source only shows `system cpu stream`), so field names are
   confirmed against the lab and recorded in `docs/api-integration.md` before `verified=True`.
6. **CPU model** (`getCPUType`, plain JSON) is added as an ordinary registry operation.
7. **Audit:** each sample is audited like other firewall calls (action `firewall.cpu.sample`).

## Consequences

- Dashboard shows CPU usage with no new dependency (httpx already supports streaming).
- Status requests get slower by up to `timeout_s` when the stream is slow; mitigated by the cache
  and by running CPU sampling concurrently with the other best-effort calls.
- A firewall that never emits events costs one capped connection per 5 s window at most.
- Needs an unverified-then-verified step on the lab, as with other entries.
- Opens the door to a future backend-to-browser SSE relay (ADR-0001 amendment required then).

## Alternatives considered

- **Defer CPU usage; use load average as proxy.** Zero risk, but load average is not CPU percent.
- **Relay the stream to the browser over SSE.** Real-time, but long-lived connections per user,
  more attack surface and load on the firewall. Rejected for now.
- **Compute CPU from other endpoints.** No such non-streaming endpoint exists under this privilege.
- **Background poller storing samples in PostgreSQL.** Enables history graphs, but adds a worker
  process and storage; better suited to a later metrics phase.
