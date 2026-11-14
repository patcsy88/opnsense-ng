from slowapi import Limiter

from app.core.clientip import client_ip
from app.core.config import get_settings


def default_limit() -> str:
    return get_settings().default_rate_limit


# In-memory storage for the general flood guard only. The login limits are counted in
# PostgreSQL (app/auth/loginlimit.py, ADR-0014), so they are exact across restarts and processes.
# The key is the resolved client IP: the socket peer, or the right-most untrusted
# X-Forwarded-For entry when the peer is listed in TRUSTED_PROXIES.
limiter = Limiter(key_func=client_ip, default_limits=[lambda: default_limit()])
