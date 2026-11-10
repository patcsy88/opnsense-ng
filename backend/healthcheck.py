"""Container HEALTHCHECK: GET /health on localhost using only the standard library.

TrustedHostMiddleware rejects unknown Host headers, so the first ALLOWED_HOSTS entry is sent.
"""

import http.client
import json
import os
import sys


def _host() -> str:
    raw = os.environ.get("ALLOWED_HOSTS", "").strip()
    if raw.startswith("["):
        try:
            hosts = [str(h) for h in json.loads(raw)]
        except ValueError:
            hosts = []
    else:
        hosts = [h.strip() for h in raw.split(",")]
    return next((h for h in hosts if h and h != "*"), "localhost")


def main() -> int:
    try:
        conn = http.client.HTTPConnection("127.0.0.1", 8000, timeout=3)
        conn.request("GET", "/health", headers={"Host": _host()})
        return 0 if conn.getresponse().status == 200 else 1
    except OSError, http.client.HTTPException:
        return 1


if __name__ == "__main__":
    sys.exit(main())
