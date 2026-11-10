# OPNsense API Integration

Status: template. Endpoints must be verified against the target OPNsense version before being added.

## Rules

- Authenticate with an API key and secret (HTTP basic auth) held only by the backend.
- Do not assume GUI parity. Record gaps as unsupported.
- Many changes need a separate apply/reconfigure call. Record this per operation.
- Use least-privilege API keys.

## Capability table (to be filled as operations are verified)

| Operation id | Method | Endpoint | Privilege | Read-only | Apply required | Min version / plugin | Status |
|---|---|---|---|---|---|---|---|
| | | | | | | | |
