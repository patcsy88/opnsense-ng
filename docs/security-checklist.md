# Security Review Checklist

- [ ] Endpoint requires authentication
- [ ] RBAC check present; default deny
- [ ] CSRF protection on state-changing requests
- [ ] Request validated by a Pydantic schema
- [ ] Operation is in the registry; no client-supplied paths or URLs
- [ ] Audit record written for success and failure
- [ ] No secrets in logs, responses, bundles or caches
- [ ] Credentials encrypted at rest
- [ ] Rate limiting applied
- [ ] Error responses leak no internals
- [ ] Service worker does not cache API data
- [ ] High-impact actions require confirmation and elevated role
- [ ] Dependencies scanned (pip-audit, npm audit)
- [ ] TLS verification enabled for OPNsense calls
