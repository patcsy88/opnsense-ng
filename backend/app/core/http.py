"""HTTP boundary middleware: security headers and cache control for API responses."""

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
_DOCS_PATHS = ("/docs", "/openapi.json")


class SecurityHeadersMiddleware:
    """Adds hardening headers to every response and ``Cache-Control: no-store`` on /api.
    The CSP is skipped for the (opt-in) Swagger UI, which needs inline scripts and a CDN."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope.get("path", "")

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                if path.startswith("/api"):
                    headers["Cache-Control"] = "no-store"
                    headers["Pragma"] = "no-cache"
                if not path.startswith(_DOCS_PATHS):
                    headers["Content-Security-Policy"] = API_CSP
            await send(message)

        await self.app(scope, receive, send_wrapper)
