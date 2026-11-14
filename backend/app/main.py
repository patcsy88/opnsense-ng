from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api import audit_log, changes, firewalls, health, overview, service_control
from app.auth import account as mfa_account
from app.auth import router as auth_router
from app.auth import users as users_api
from app.core.config import get_settings
from app.core.http import SecurityHeadersMiddleware
from app.core.logging import configure_logging
from app.core.ratelimit import limiter
from app.db.session import make_engine, make_sessionmaker


async def _validation_error(_request: Request, exc: Exception) -> JSONResponse:
    """422 without echoing the submitted values (they can contain API secrets)."""
    errors: list[dict[str, Any]] = []
    if isinstance(exc, RequestValidationError):
        for err in exc.errors():
            errors.append({"loc": list(err.get("loc", ())), "msg": str(err.get("msg", "invalid"))})
    return JSONResponse(status_code=422, content={"detail": errors})


def create_app() -> FastAPI:
    settings = get_settings()  # fails fast when required configuration is missing
    configure_logging()
    engine = make_engine(settings.database_url)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(
        title="OPNsense Firewall Manager",
        lifespan=lifespan,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.engine = engine
    app.state.sessionmaker = make_sessionmaker(engine)
    app.state.trusted_proxies = settings.trusted_proxy_networks

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, _validation_error)
    # Outermost last: host check first, then headers (so even 400s get them), then rate limit.
    app.add_middleware(SlowAPIMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

    app.include_router(health.router)
    app.include_router(auth_router.router)
    app.include_router(overview.router)  # before firewalls: fixed path, no id
    app.include_router(firewalls.router)
    app.include_router(service_control.router)
    app.include_router(changes.router)
    app.include_router(audit_log.router)
    app.include_router(mfa_account.router)
    app.include_router(users_api.router)
    app.include_router(users_api.password_router)
    return app
