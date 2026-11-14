# ADR-0014: Login rate-limit counters in PostgreSQL

- Status: accepted
- Date: 2026-11-14
- Deciders: project owner

## Context

Two mechanisms slow down guessing:

- **Per-username lockout** (`login_throttle`): already in PostgreSQL. It survives restarts and is
  shared by every backend process.
- **Per-IP rate limits** (`slowapi`, in-memory): 5 per minute on `POST /auth/login` and
  `POST /auth/login/mfa`, and 120 per minute on everything else. The counters live in the process.
  A restart clears them, and if the backend is ever run as more than one process, each process
  counts separately, so the real limit becomes N times higher. ADR-0003 deferred this and excluded
  Redis.

Today the backend is one process, so the practical gain is modest. The restart reset matters little
because an attacker cannot trigger a restart, and the username lockout already survives one. The
change is mainly to remove a known limit before anyone scales the backend out, and to keep the
login limit exact if they do.

`slowapi` and its `limits` library have no PostgreSQL storage, so this needs a small custom
counter. It cannot be a configuration switch.

## Decision

1. **Scope: the two login limits only.** `POST /auth/login` and `POST /auth/login/mfa` count in
   PostgreSQL. The general 120 per minute limit stays in memory. It is a flood guard, not an
   authentication control, and writing to the database on every request (including each dashboard
   poll) would add load for little benefit.
2. **Table `rate_limit_counters`** (migration `0006`): `key` (text, for example `login:<ip>`),
   `window_start` (timestamptz) and `count`, with primary key (`key`, `window_start`).
3. **Fixed window, same as today.** `window_start` is the current time rounded down to the limit's
   period. Each request runs one atomic `INSERT … ON CONFLICT DO UPDATE SET count = count + 1
   RETURNING count`. A count above the limit answers 429 with `Retry-After`. Rejected requests
   count too, as they do now.
4. **Own transaction.** The counter is written and committed on its own short connection before
   the request logic runs, so a later rollback (for example a failed login) cannot undo it.
5. **Limit strings stay as they are** (`LOGIN_RATE_LIMIT`, default `5/minute`) and are parsed with
   the existing `limits` parser, which `slowapi` already installs. No new dependency, and
   `limits` is not added to the approved list as a direct dependency beyond what ADR-0003 allows
   through `slowapi`.
6. **Key** is the resolved client IP from `app.core.clientip`, unchanged, so the trusted-proxy rules
   still apply.
7. **Cleanup:** rows older than one hour are deleted. This runs opportunistically (about 1 in 100
   login attempts) and in `python -m app.auth.cli cleanup-sessions`.
8. **Failure behaviour:** if the database is unavailable the login request fails (5xx). It does not
   skip the limit. Login needs the database anyway.
9. **Privacy:** the table holds source IPs for at most an hour. The audit log already stores them
   for much longer.
10. **Tests:** the existing `limiter.reset()` calls keep working for the in-memory limit. The
    test fixture also truncates the new table. New tests cover the limit, the window rollover, the
    `Retry-After` value, counting across two app instances sharing one database, survival of a
    simulated restart, and cleanup.

## Consequences

- The login limit is exact across restarts and across several backend processes.
- Each login attempt adds one small database write. Login is rare, so the load is negligible.
- Two limiters now exist (PostgreSQL for login, in-memory for the rest). The code and the docs
  must say which is which.
- A fixed window allows up to twice the limit across a window boundary. This is the same as the
  current behaviour.
- The general limit is still per process. If the backend is scaled out, it should be revisited.

## Alternatives considered

- **Move every limit to PostgreSQL.** Rejected: a write on every request for little security
  gain.
- **Redis.** Rejected: a new service and dependency, already ruled out in ADR-0003.
- **Do nothing until the backend is scaled out.** Reasonable. The cost is that the limit is
  silently weaker the day someone adds a second process. Doing it now is a small change.
- **Sliding window or token bucket.** Rejected for now: more rows or more writes for a marginal
  gain.
- **Caddy rate limiting.** Rejected: it needs a non-standard Caddy module, which is a new
  dependency and image build.
