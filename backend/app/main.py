from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api import firewalls, health
from app.auth import router as auth_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.ratelimit import limiter
from app.db.session import make_engine, make_sessionmaker


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

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
    app.add_middleware(SlowAPIMiddleware)

    app.include_router(health.router)
    app.include_router(auth_router.router)
    app.include_router(firewalls.router)
    return app
