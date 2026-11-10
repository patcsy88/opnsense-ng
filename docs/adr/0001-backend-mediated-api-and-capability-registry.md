# ADR-0001: Backend-mediated access and API capability registry

- Status: accepted (approved by project owner on 2026-11-10)
- Date: 2026-11-10
- Deciders: project owner

## Context

The application holds privileged access to firewalls. OPNsense API coverage varies by version and plugin and does not match the GUI.

## Decision

- The browser communicates only with our backend. OPNsense credentials never leave it.
- The backend calls OPNsense only through a registry of explicitly declared operations. The frontend selects operations by id and never supplies paths or URLs.
- Operations not exposed by the API are recorded as unsupported and are not worked around.

## Consequences

- Prevents SSRF and arbitrary API access, and gives one place to enforce RBAC and audit.
- Adding a capability needs a registry entry plus a schema.

## Alternatives considered

- Generic proxy to OPNsense: rejected, too much privilege exposure.
