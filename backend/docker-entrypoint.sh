#!/bin/sh
# Run database migrations, then replace this shell with the server (PID 1 gets SIGTERM).
# Set SKIP_MIGRATIONS=1 to start without migrating (e.g. when several replicas share a DB).
set -eu

if [ "${SKIP_MIGRATIONS:-0}" != "1" ]; then
    alembic upgrade head
fi

# No --proxy-headers: the app resolves X-Forwarded-For itself, honouring only TRUSTED_PROXIES.
exec uvicorn --factory app.main:create_app --host 0.0.0.0 --port 8000 --no-server-header
