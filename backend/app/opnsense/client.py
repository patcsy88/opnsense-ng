"""Async OPNsense client. It can only execute operations declared in the capability registry."""

import asyncio
import json
import ssl
from typing import Any

import httpx

from app.core.logging import get_logger
from app.opnsense.errors import ConnectionStatus, FirewallError
from app.opnsense.netpolicy import (
    PinnedTransport,
    TargetNotAllowedError,
    TargetPolicy,
    split_host,
)
from app.opnsense.registry import (
    HttpMethod,
    Operation,
    ResponseKind,
    UnsupportedOperationError,
    get_operation,
)
from app.opnsense.tls import build_ssl_context

log = get_logger("opnsense.client")

_RETRY_STATUS = {502, 503, 504}

STREAM_MAX_EVENTS = 3
STREAM_MAX_SECONDS = 5.0
STREAM_MAX_BYTES = 256 * 1024
STREAM_MAX_LINE_BYTES = 64 * 1024


class OPNsenseClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        api_secret: str,
        verify_tls: bool = True,
        ca_bundle_pem: str | None = None,
        policy: TargetPolicy | None = None,
        connect_timeout_s: float = 5.0,
        read_timeout_s: float = 15.0,
        max_retries: int = 2,
        backoff_base_s: float = 0.25,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._max_retries = max_retries
        self._backoff = backoff_base_s
        self.policy = policy or TargetPolicy()
        self._host = split_host(base_url)[0]
        if transport is None:
            # Resolve -> validate -> connect to the validated IP (DNS-rebinding defence); TLS
            # keeps using the configured hostname for SNI and certificate verification.
            transport = PinnedTransport(
                ssl_context=build_ssl_context(verify_tls=verify_tls, ca_bundle_pem=ca_bundle_pem),
                policy=self.policy,
            )
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            auth=httpx.BasicAuth(api_key, api_secret),
            trust_env=False,
            timeout=httpx.Timeout(read_timeout_s, connect=connect_timeout_s),
            follow_redirects=False,
            transport=transport,
            headers={"Accept": "application/json"},
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def execute(
        self,
        operation_id: str,
        payload: dict[str, Any] | None = None,
        path_params: dict[str, str] | None = None,
        query: dict[str, str] | None = None,
    ) -> Any:
        """Run a registry operation by id. Raises UnknownOperationError/UnsupportedOperationError
        for ids that are not executable, and FirewallError for connectivity/API failures."""
        op = get_operation(operation_id)
        if op.response_kind is not ResponseKind.json:
            raise UnsupportedOperationError(f"{operation_id} is a stream; use sample_stream")
        if not self.policy.host_allowed(self._host):
            raise FirewallError(ConnectionStatus.blocked_target, "Firewall address is not allowed")
        endpoint = op.resolve_endpoint(path_params)
        return await self._send(op, payload, endpoint, op.check_query(query))

    async def sample_stream(
        self, operation_id: str, *, max_events: int = 1, timeout_s: float = 3.0
    ) -> list[Any]:
        """Open an SSE operation, collect a few JSON events, close the connection. Bounded in
        events, time, line length and bytes; never retried."""
        op = get_operation(operation_id)
        if op.response_kind is not ResponseKind.sse:
            raise UnsupportedOperationError(f"{operation_id} is not a stream operation")
        if not self.policy.host_allowed(self._host):
            raise FirewallError(ConnectionStatus.blocked_target, "Firewall address is not allowed")
        wanted = min(max(max_events, 1), STREAM_MAX_EVENTS)
        events: list[Any] = []
        try:
            async with asyncio.timeout(min(timeout_s, STREAM_MAX_SECONDS)):
                await self._read_events(op, wanted, events)
        except TimeoutError:
            if not events:
                raise FirewallError(
                    ConnectionStatus.timeout, "Firewall stream produced no data in time"
                ) from None
        if not events:
            raise FirewallError(ConnectionStatus.bad_response, "Firewall stream sent no events")
        return events

    async def _read_events(self, op: Operation, wanted: int, events: list[Any]) -> None:
        try:
            async with self._http.stream(
                "GET", op.endpoint, headers={"Accept": "text/event-stream"}
            ) as response:
                _check_status(op, response.status_code)
                buffer = b""
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    buffer += chunk
                    if total > STREAM_MAX_BYTES or len(buffer) > STREAM_MAX_LINE_BYTES:
                        raise FirewallError(
                            ConnectionStatus.bad_response, "Firewall stream exceeded size limits"
                        )
                    *lines, buffer = buffer.split(b"\n")
                    for raw in lines:
                        line = raw.decode("utf-8", "replace").strip()
                        if not line.startswith("data:"):
                            continue
                        try:
                            events.append(json.loads(line[5:].strip()))
                        except ValueError:
                            continue
                        if len(events) >= wanted:
                            return
        except httpx.HTTPError as exc:
            raise _translate(exc) from None

    async def _send(
        self,
        op: Operation,
        payload: dict[str, Any] | None,
        endpoint: str,
        query: dict[str, str] | None = None,
    ) -> Any:
        # Only idempotent reads are retried; state-changing calls are attempted exactly once.
        retryable = op.method is HttpMethod.GET and op.read_only
        attempts = self._max_retries + 1 if retryable else 1
        last: FirewallError | None = None
        for attempt in range(attempts):
            try:
                return await self._once(op, payload, endpoint, query)
            except FirewallError as exc:
                last = exc
                transient = exc.status in {
                    ConnectionStatus.timeout,
                    ConnectionStatus.unreachable,
                } or (exc.status is ConnectionStatus.server_error and exc.retry_ok)
                if not (retryable and transient) or attempt == attempts - 1:
                    raise
                delay = self._backoff * (2**attempt)
                log.warning(
                    "opnsense_retry", operation=op.operation_id, attempt=attempt + 1, delay=delay
                )
                await asyncio.sleep(delay)
        raise last or FirewallError(ConnectionStatus.unreachable, "Request not attempted")

    async def _once(
        self,
        op: Operation,
        payload: dict[str, Any] | None,
        endpoint: str,
        query: dict[str, str] | None = None,
    ) -> Any:
        try:
            response = await self._http.request(
                op.method.value,
                endpoint,
                json=payload if op.method is HttpMethod.POST else None,
                params=query or None,
            )
        except httpx.HTTPError as exc:
            raise _translate(exc) from None
        _check_status(op, response.status_code)
        try:
            return response.json()
        except ValueError:
            raise FirewallError(
                ConnectionStatus.bad_response, "Firewall returned a non-JSON response"
            ) from None


def _translate(exc: httpx.HTTPError) -> FirewallError:
    if isinstance(exc, httpx.TimeoutException):
        return FirewallError(ConnectionStatus.timeout, "Firewall request timed out")
    if isinstance(exc, httpx.ConnectError):
        if _has_cause(exc, TargetNotAllowedError):
            return FirewallError(ConnectionStatus.blocked_target, "Firewall address is not allowed")
        if _is_tls_error(exc):
            return FirewallError(ConnectionStatus.tls_error, "TLS certificate verification failed")
        return FirewallError(ConnectionStatus.unreachable, "Firewall is unreachable")
    return FirewallError(ConnectionStatus.unreachable, "Communication with firewall failed")


def _check_status(op: Operation, code: int) -> None:
    if code == 401:
        raise FirewallError(ConnectionStatus.auth_failed, "Firewall rejected the API credentials")
    if code == 403:
        raise FirewallError(
            ConnectionStatus.forbidden, "API key lacks the privilege for this operation"
        )
    if code == 404:
        # Not "operation unavailable": our registry path or the firewall version differs.
        log.error("registry_endpoint_not_found", endpoint=op.endpoint, operation=op.operation_id)
        raise FirewallError(
            ConnectionStatus.endpoint_not_found,
            "Registry endpoint not found on this firewall (registry or version problem)",
        )
    if code >= 500 or code in _RETRY_STATUS:
        err = FirewallError(ConnectionStatus.server_error, f"Firewall returned HTTP {code}")
        err.retry_ok = code in _RETRY_STATUS
        raise err
    if code >= 400:
        raise FirewallError(ConnectionStatus.bad_response, f"Firewall returned HTTP {code}")


def _has_cause(exc: BaseException, kind: type[BaseException]) -> bool:
    cause: BaseException | None = exc
    seen = 0
    while cause is not None and seen < 10:
        if isinstance(cause, kind):
            return True
        cause = cause.__cause__ or cause.__context__
        seen += 1
    return False


def _is_tls_error(exc: BaseException) -> bool:
    return _has_cause(exc, ssl.SSLError)
