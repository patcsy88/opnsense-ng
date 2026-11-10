"""Async OPNsense client. It can only execute operations declared in the capability registry."""

import asyncio
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
from app.opnsense.registry import HttpMethod, Operation, get_operation
from app.opnsense.tls import build_ssl_context

log = get_logger("opnsense.client")

_RETRY_STATUS = {502, 503, 504}


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

    async def execute(self, operation_id: str, payload: dict[str, Any] | None = None) -> Any:
        """Run a registry operation by id. Raises UnknownOperationError/UnsupportedOperationError
        for ids that are not executable, and FirewallError for connectivity/API failures."""
        op = get_operation(operation_id)
        if not self.policy.host_allowed(self._host):
            raise FirewallError(ConnectionStatus.blocked_target, "Firewall address is not allowed")
        return await self._send(op, payload)

    async def _send(self, op: Operation, payload: dict[str, Any] | None) -> Any:
        # Only idempotent reads are retried; state-changing calls are attempted exactly once.
        retryable = op.method is HttpMethod.GET and op.read_only
        attempts = self._max_retries + 1 if retryable else 1
        last: FirewallError | None = None
        for attempt in range(attempts):
            try:
                return await self._once(op, payload)
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

    async def _once(self, op: Operation, payload: dict[str, Any] | None) -> Any:
        try:
            response = await self._http.request(
                op.method.value, op.endpoint, json=payload if op.method is HttpMethod.POST else None
            )
        except httpx.TimeoutException:
            raise FirewallError(ConnectionStatus.timeout, "Firewall request timed out") from None
        except httpx.ConnectError as exc:
            if _has_cause(exc, TargetNotAllowedError):
                raise FirewallError(
                    ConnectionStatus.blocked_target, "Firewall address is not allowed"
                ) from None
            if _is_tls_error(exc):
                raise FirewallError(
                    ConnectionStatus.tls_error, "TLS certificate verification failed"
                ) from None
            raise FirewallError(ConnectionStatus.unreachable, "Firewall is unreachable") from None
        except httpx.HTTPError:
            raise FirewallError(
                ConnectionStatus.unreachable, "Communication with firewall failed"
            ) from None

        code = response.status_code
        if code == 401:
            raise FirewallError(
                ConnectionStatus.auth_failed, "Firewall rejected the API credentials"
            )
        if code == 403:
            raise FirewallError(
                ConnectionStatus.forbidden, "API key lacks the privilege for this operation"
            )
        if code == 404:
            # Not "operation unavailable": our registry path or the firewall version differs.
            log.error(
                "registry_endpoint_not_found", endpoint=op.endpoint, operation=op.operation_id
            )
            err = FirewallError(
                ConnectionStatus.endpoint_not_found,
                "Registry endpoint not found on this firewall (registry or version problem)",
            )
            raise err
        if code >= 500 or code in _RETRY_STATUS:
            err = FirewallError(ConnectionStatus.server_error, f"Firewall returned HTTP {code}")
            err.retry_ok = code in _RETRY_STATUS
            raise err
        if code >= 400:
            raise FirewallError(ConnectionStatus.bad_response, f"Firewall returned HTTP {code}")
        try:
            return response.json()
        except ValueError:
            raise FirewallError(
                ConnectionStatus.bad_response, "Firewall returned a non-JSON response"
            ) from None


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
