from slowapi import Limiter

from app.core.clientip import client_ip
from app.core.config import get_settings


def default_limit() -> str:
    return get_settings().default_rate_limit


def login_limit() -> str:
    return get_settings().login_rate_limit


# In-memory storage: correct for a single backend process. Move to a shared store if the
# backend is ever scaled out (Redis is out of scope for Phase 1, see ADR-0003).
# The key is the resolved client IP: the socket peer, or the right-most untrusted
# X-Forwarded-For entry when the peer is listed in TRUSTED_PROXIES.
limiter = Limiter(key_func=client_ip, default_limits=[lambda: default_limit()])
