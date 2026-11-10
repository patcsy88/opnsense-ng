# ADR-0002: PostgreSQL as application datastore

- Status: accepted
- Date: 2026-11-10
- Deciders: project owner

## Context

The brief allows PostgreSQL or SQLite. Data: users, sessions, audit log, encrypted firewall credentials, staged changes.

## Decision

Use PostgreSQL, run as a Docker Compose service, with SQLAlchemy and Alembic migrations.

## Consequences

- Better concurrency, row locking for staged changes, and multi-firewall readiness.
- One more container to deploy and back up.

## Alternatives considered

- SQLite: simpler, but weaker for concurrent writes and locking.
