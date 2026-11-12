# ADR-0011: Audit log viewer and retention

- Status: accepted
- Date: 2026-11-13
- Deciders: project owner

## Context

Phase 5 starts with the audit log. Every endpoint already writes to the `audit_log` table: user,
action, firewall, timestamp, outcome, source IP, user agent and a free-form `detail` object. Nothing
reads it back in the app, and nothing removes old records. The Administration page shows "Audit log"
as planned.

`detail` is built at each call site. Today it holds reasons, status codes, change request ids, names
and base URLs. It is not validated, so a future call site could put something unsuitable in it.

## Decision

1. **Read-only viewer.** `GET /api/v1/audit` returns audit records, newest first, paged (50 per page,
   at most 200). Filters: username, action prefix, firewall, outcome and a date range. The endpoint
   cannot change or delete anything.
2. **Access:** `admin` and `security_admin`. Other roles get 403. Viewing the log is itself audited as
   `audit.view`, without the filter values.
3. **`detail` is whitelisted on output.** Only scalar values (string, number, boolean, null) under
   keys of up to 64 characters are returned, with strings cut to 200 characters. Nested objects and
   lists are dropped. The user agent is cut to 120 characters. A test checks this.
4. **Retention:** 12 months by default, set by `AUDIT_RETENTION_DAYS` (minimum 90). Records are never
   removed automatically.
5. **Purge:** `POST /api/v1/audit/purge`, `admin` only, with CSRF and a typed confirmation. It deletes
   only records older than the retention period, in one transaction, and writes an `audit.purge`
   record in the same transaction with the cutoff and the number removed. Records newer than the
   cutoff cannot be removed through the app. `security_admin` cannot purge.
6. **Frontend:** an Audit log page under Administration, with the filters above, a table (time, user,
   action, firewall, outcome, source IP) and a row detail view. The purge control shows the count it
   would remove before asking for confirmation.
7. **Out of scope:** export, alerting, tamper-evident chaining, and shipping records to an external
   system. Each can be added later.

## Consequences

- Security review no longer needs database access.
- Audit records outlive users and firewalls, so rows can show a username or firewall id that no longer
  exists. The viewer shows the stored value.
- Because `detail` is cut down on output, some context in old records is not visible in the app. The
  database still holds the full record.
- The log grows without limit until an admin purges it. A purge is the only destructive action and it
  is itself recorded.
- Source IPs and user agents are personal data. Limiting access to two roles and the retention limit
  keep that exposure bounded.

## Alternatives considered

- **Automatic purge by schedule.** Rejected: silent deletion of the audit trail. A manual, recorded
  step is safer.
- **Let `network_admin` and `read_only` view it.** Rejected: the log shows who did what and from where.
- **Return `detail` unfiltered.** Rejected: a future call site could leak something into it.
- **No purge at all.** Rejected: unbounded growth and no way to meet a retention limit.
