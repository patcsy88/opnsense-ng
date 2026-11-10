from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import get_settings


def default_limit() -> str:
    return get_settings().default_rate_limit


def login_limit() -> str:
    return get_settings().login_rate_limit


# In-memory storage: correct for a single backend process. Move to a shared store if the
# backend is ever scaled out (Redis is out of scope for Phase 1, see ADR-0003).
# NOTE: behind Caddy the client address needs trusted-proxy handling (see README).
limiter = Limiter(key_func=get_remote_address, default_limits=[lambda: default_limit()])
