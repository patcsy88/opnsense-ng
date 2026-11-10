"""Firewall target policy (SSRF / DNS-rebinding defence) and base_url validation.

* ``parse_base_url`` is purely syntactic: https, host, optional port; nothing else.
* ``TargetPolicy`` decides whether an IP or hostname may be contacted. Loopback, link-local
  (incl. 169.254.169.254), unspecified, multicast, reserved and well-known cloud metadata
  addresses are ALWAYS denied. Beyond that the policy is an allow-list: by default only private
  ranges (RFC1918 + IPv6 ULA) are permitted, so public targets need an explicit
  ``allowed_networks`` entry. ``denied_networks`` removes ranges from the allow-list. An empty
  allow-list permits nothing (fail closed).
* ``PinnedNetworkBackend`` resolves the hostname at connection time, validates every resolved
  address, and connects to a validated IP. TLS still happens against the original hostname
  (SNI and certificate verification are unchanged) because only the TCP target is replaced.
"""

import asyncio
import ipaddress
import re
import socket
import ssl
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpcore
import httpx

from app.core.clientip import IPAddress, IPNetwork

_HOSTNAME_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

_ALWAYS_DENIED = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",  # link-local, includes the 169.254.169.254 metadata service
        "100.100.100.200/32",  # Alibaba Cloud metadata
        "192.0.0.192/32",  # Oracle Cloud metadata
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fe80::/10",
        "fd00:ec2::254/128",  # AWS IPv6 metadata
        "ff00::/8",
    )
)


DEFAULT_ALLOWED_NETWORKS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
)


class TargetNotAllowedError(httpcore.ConnectError):
    """The firewall address violates the target policy (raised at connect time)."""


class InvalidBaseUrlError(ValueError):
    """base_url is not an acceptable firewall URL. Messages are safe to return to users."""


def parse_base_url(raw: str, max_length: int) -> str:
    """Return the canonical ``https://host[:port]`` or raise InvalidBaseUrlError."""
    value = raw.strip()
    if not value or len(value) > max_length:
        raise InvalidBaseUrlError(f"base_url must be 1-{max_length} characters")
    if any(ord(c) < 0x21 or ord(c) > 0x7E for c in value) or "\\" in value:
        raise InvalidBaseUrlError("base_url contains invalid characters")
    parts = urlsplit(value)
    if parts.scheme.lower() != "https":
        raise InvalidBaseUrlError("base_url must use https")
    if "@" in parts.netloc:
        raise InvalidBaseUrlError("base_url must not contain credentials")
    if parts.path not in {"", "/"} or parts.query or parts.fragment or "?" in value or "#" in value:
        raise InvalidBaseUrlError("base_url must not contain a path, query or fragment")
    try:
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise InvalidBaseUrlError("base_url has an invalid host or port") from None
    if not host:
        raise InvalidBaseUrlError("base_url must contain a host")
    host = host.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(_HOSTNAME_LABEL.match(lbl) for lbl in host.split(".")):
            raise InvalidBaseUrlError("base_url has an invalid host name") from None
        rendered = host
    else:
        rendered = f"[{ip}]" if ip.version == 6 else str(ip)
    if port is not None and not 1 <= port <= 65535:
        raise InvalidBaseUrlError("base_url has an invalid port")
    result = f"https://{rendered}" + (f":{port}" if port is not None and port != 443 else "")
    if len(result) > max_length:
        raise InvalidBaseUrlError(f"base_url must be at most {max_length} characters")
    return result


def split_host(base_url: str) -> tuple[str, int]:
    parts = urlsplit(base_url)
    return parts.hostname or "", parts.port or 443


def _unmap(ip: IPAddress) -> IPAddress:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


@dataclass(frozen=True)
class TargetPolicy:
    allowed_networks: Sequence[IPNetwork] = tuple(
        ipaddress.ip_network(n) for n in DEFAULT_ALLOWED_NETWORKS
    )
    denied_networks: Sequence[IPNetwork] = ()
    own_hostnames: frozenset[str] = field(default_factory=frozenset)

    @staticmethod
    def own_names(extra: Iterable[str] = ()) -> frozenset[str]:
        names = {"localhost", "localhost.localdomain", *(h.lower().rstrip(".") for h in extra)}
        try:
            names.add(socket.gethostname().lower())
        except OSError:  # pragma: no cover
            pass
        return frozenset(n for n in names if n and n != "*")

    def ip_allowed(self, raw: IPAddress) -> bool:
        ip = _unmap(raw)
        if any(ip.version == n.version and ip in n for n in _ALWAYS_DENIED):
            return False
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            return False
        if any(ip.version == n.version and ip in n for n in self.denied_networks):
            return False
        return any(ip.version == n.version and ip in n for n in self.allowed_networks)

    def host_allowed(self, host: str) -> bool:
        """Syntactic check on the configured host (literal IP or name)."""
        name = host.lower().rstrip(".").strip("[]")
        try:
            return self.ip_allowed(ipaddress.ip_address(name))
        except ValueError:
            return name not in self.own_hostnames

    def filter_resolved(self, addresses: Iterable[str]) -> list[str]:
        """Return the resolved addresses that are acceptable; raises if none (or any is bad:
        a name that resolves to a mix of allowed and denied targets is refused outright)."""
        parsed: list[IPAddress] = []
        for a in addresses:
            try:
                parsed.append(ipaddress.ip_address(a.split("%", 1)[0]))
            except ValueError:
                raise TargetNotAllowedError("Resolved address is invalid") from None
        if not parsed:
            raise TargetNotAllowedError("Host did not resolve")
        if not all(self.ip_allowed(ip) for ip in parsed):
            raise TargetNotAllowedError("Firewall address is not permitted by policy")
        return [str(ip) for ip in parsed]


async def resolve(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise httpcore.ConnectError("Name resolution failed") from None
    seen: dict[str, None] = {}
    for info in infos:
        seen[str(info[4][0])] = None
    return list(seen)


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Resolve, validate and connect to the validated IP. httpcore passes the ORIGINAL host to
    ``start_tls`` afterwards, so SNI and hostname verification stay on the configured name."""

    def __init__(
        self, policy: TargetPolicy, inner: httpcore.AsyncNetworkBackend | None = None
    ) -> None:
        self._policy = policy
        self._inner = inner or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - signature fixed by httpcore
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if not self._policy.host_allowed(host):
            raise TargetNotAllowedError("Firewall address is not permitted by policy")
        try:
            addresses = [str(ipaddress.ip_address(host.strip("[]")))]
        except ValueError:
            addresses = await resolve(host, port)
        validated = self._policy.filter_resolved(addresses)
        last: Exception | None = None
        for address in validated:
            try:
                return await self._inner.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        raise last or httpcore.ConnectError("No usable address")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 - signature fixed by httpcore
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise TargetNotAllowedError("Unix sockets are not permitted")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class PinnedTransport(httpx.AsyncHTTPTransport):
    """httpx 0.28 transport whose connection pool uses ``PinnedNetworkBackend``.
    (httpx exposes no public hook for a network backend, so the pool is rebuilt; covered by a
    test so an httpx upgrade that breaks it fails loudly.)"""

    def __init__(self, *, ssl_context: ssl.SSLContext, policy: TargetPolicy) -> None:
        super().__init__(verify=ssl_context, trust_env=False, http2=False)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=10,
            max_keepalive_connections=5,
            keepalive_expiry=5.0,
            http1=True,
            http2=False,
            network_backend=PinnedNetworkBackend(policy),
        )
