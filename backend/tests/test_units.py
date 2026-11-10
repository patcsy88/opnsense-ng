"""Pure unit tests (no database): client IP, target policy, URL parsing, passwords, crypto, TLS."""

import io
import ipaddress
import logging
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import cast

import httpcore
import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.auth.security import (
    PasswordPolicyError,
    bind_csrf,
    hash_password,
    needs_rehash,
    normalise_username,
    validate_password,
    validate_username,
)
from app.core.clientip import resolve_client_ip
from app.core.config import Settings
from app.core.crypto import CredentialCipher, CredentialDecryptionError
from app.core.logging import (
    MAX_KNOWN_SECRETS,
    _known_secrets,
    configure_logging,
    register_secret,
)
from app.opnsense.netpolicy import (
    InvalidBaseUrlError,
    PinnedNetworkBackend,
    TargetNotAllowedError,
    TargetPolicy,
    parse_base_url,
)
from app.opnsense.tls import InvalidCaBundleError, build_ssl_context, normalise_ca_bundle

NETS = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("192.168.1.5/32")]


# ---- H1 client IP -------------------------------------------------------------------------
def test_untrusted_peer_cannot_spoof_xff() -> None:
    assert resolve_client_ip("203.0.113.9", "1.2.3.4", NETS) == "203.0.113.9"
    assert resolve_client_ip("203.0.113.9", "1.2.3.4", []) == "203.0.113.9"


def test_trusted_peer_uses_rightmost_untrusted() -> None:
    assert resolve_client_ip("10.0.0.2", "198.51.100.7", NETS) == "198.51.100.7"
    # client-supplied junk on the left is ignored; the proxy-appended entry is right-most
    assert resolve_client_ip("10.0.0.2", "6.6.6.6, 198.51.100.7", NETS) == "198.51.100.7"
    assert resolve_client_ip("10.0.0.2", "198.51.100.7, 10.0.0.9", NETS) == "198.51.100.7"


def test_trusted_peer_without_or_with_bad_header_falls_back() -> None:
    assert resolve_client_ip("10.0.0.2", None, NETS) == "10.0.0.2"
    assert resolve_client_ip("10.0.0.2", "not-an-ip", NETS) == "10.0.0.2"
    assert resolve_client_ip("10.0.0.2", "10.0.0.7, 10.0.0.9", NETS) == "10.0.0.7"
    assert resolve_client_ip(None, "1.1.1.1", NETS) == "unknown"


# ---- M1 URL + policy ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw",
    [
        "http://fw.test",
        "https://user:pw@fw.test",
        "https://fw.test/path",
        "https://fw.test/?q=1",
        "https://fw.test/#f",
        "https://fw.test?x",
        "https://fw.test:99999",
        "https://fw.test:abc",
        "ftp://fw.test",
        "https://",
        "https://fw .test",
        "https://-bad.test",
        "https://fw.test\\@evil.test",
        "https://" + "a" * 600 + ".test",
        "",
    ],
)
def test_base_url_rejected(raw: str) -> None:
    with pytest.raises(InvalidBaseUrlError):
        parse_base_url(raw, 500)


def test_base_url_canonical() -> None:
    assert parse_base_url("HTTPS://FW.Example.test/", 500) == "https://fw.example.test"
    assert parse_base_url("https://10.1.2.3:8443", 500) == "https://10.1.2.3:8443"
    assert parse_base_url("https://fw.test:443", 500) == "https://fw.test"
    assert parse_base_url("https://[2001:db8::1]:444", 500) == "https://[2001:db8::1]:444"


@pytest.mark.parametrize(
    "ip",
    ["127.0.0.1", "127.1.2.3", "::1", "169.254.169.254", "169.254.1.1", "fe80::1", "0.0.0.0", "::",  # noqa: S104
     "::ffff:127.0.0.1", "::ffff:169.254.169.254", "224.0.0.1", "100.100.100.200", "fd00:ec2::254"],
)  # fmt: skip
def test_policy_always_denies(ip: str) -> None:
    assert not TargetPolicy().ip_allowed(ipaddress.ip_address(ip))
    assert not TargetPolicy(allowed_networks=[ipaddress.ip_network("0.0.0.0/0")]).ip_allowed(
        ipaddress.ip_address(ip)
    )


def test_policy_private_allowed_by_default_and_configurable() -> None:
    assert TargetPolicy().ip_allowed(ipaddress.ip_address("192.168.1.1"))
    assert TargetPolicy().ip_allowed(ipaddress.ip_address("203.0.113.5"))
    deny = TargetPolicy(denied_networks=[ipaddress.ip_network("10.0.0.0/8")])
    assert not deny.ip_allowed(ipaddress.ip_address("10.1.1.1"))
    allow = TargetPolicy(allowed_networks=[ipaddress.ip_network("192.168.0.0/16")])
    assert allow.ip_allowed(ipaddress.ip_address("192.168.9.9"))
    assert not allow.ip_allowed(ipaddress.ip_address("10.1.1.1"))


def test_policy_own_hostnames_and_literals() -> None:
    p = TargetPolicy(own_hostnames=TargetPolicy.own_names(["manager.example.com"]))
    assert not p.host_allowed("localhost")
    assert not p.host_allowed("Manager.Example.com.")
    assert not p.host_allowed("127.0.0.1")
    assert not p.host_allowed("[::1]")
    assert p.host_allowed("fw.example.net")


def test_filter_resolved_rejects_mixed_answers() -> None:
    p = TargetPolicy()
    assert p.filter_resolved(["192.168.1.1"]) == ["192.168.1.1"]
    with pytest.raises(TargetNotAllowedError):
        p.filter_resolved(["192.168.1.1", "127.0.0.1"])
    with pytest.raises(TargetNotAllowedError):
        p.filter_resolved([])


class _FakeBackend(httpcore.AsyncNetworkBackend):
    def __init__(self) -> None:
        self.connected: list[tuple[str, int]] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.connected.append((host, port))
        return cast("httpcore.AsyncNetworkStream", object())

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise AssertionError

    async def sleep(self, seconds: float) -> None:
        return None


async def test_pinned_backend_rebinding(monkeypatch: pytest.MonkeyPatch) -> None:
    """Name passes an earlier check, then resolves to loopback at connect time -> refused;
    a good answer is connected to by IP (not by name)."""
    answers = {"fw.example.test": ["192.168.1.10"]}

    async def fake_resolve(host: str, port: int) -> list[str]:
        return answers[host]

    monkeypatch.setattr("app.opnsense.netpolicy.resolve", fake_resolve)
    inner = _FakeBackend()
    backend = PinnedNetworkBackend(TargetPolicy(), inner)
    await backend.connect_tcp("fw.example.test", 443)
    assert inner.connected == [("192.168.1.10", 443)]
    answers["fw.example.test"] = ["127.0.0.1"]  # rebinding
    with pytest.raises(TargetNotAllowedError):
        await backend.connect_tcp("fw.example.test", 443)
    answers["fw.example.test"] = ["93.184.216.34", "169.254.169.254"]
    with pytest.raises(TargetNotAllowedError):
        await backend.connect_tcp("fw.example.test", 443)
    with pytest.raises(TargetNotAllowedError):
        await backend.connect_tcp("169.254.169.254", 443)
    assert len(inner.connected) == 1


def test_pinned_transport_builds_with_current_httpx() -> None:
    from app.opnsense.netpolicy import PinnedTransport

    t = PinnedTransport(ssl_context=build_ssl_context(verify_tls=True, ca_bundle_pem=None),
                        policy=TargetPolicy())  # fmt: skip
    assert isinstance(t._pool._network_backend, PinnedNetworkBackend)


def test_client_does_not_trust_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.opnsense.client import OPNsenseClient

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent")
    c = OPNsenseClient(base_url="https://fw.example.test", api_key="k", api_secret="s")
    assert c._http._trust_env is False
    assert not c._http._mounts


# ---- M2 CA bundle -------------------------------------------------------------------------
def _cert_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fw.example.test")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_ca_bundle_validation() -> None:
    pem = _cert_pem()
    assert normalise_ca_bundle(pem).startswith("-----BEGIN CERTIFICATE-----")
    assert normalise_ca_bundle(pem + pem).count("BEGIN CERTIFICATE") == 2
    key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    for bad in ("", "hello", pem + key.decode(), key.decode(),
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
                "x" * 70_000):  # fmt: skip
        with pytest.raises(InvalidCaBundleError):
            normalise_ca_bundle(bad)
    ctx = build_ssl_context(verify_tls=True, ca_bundle_pem=pem)
    assert ctx.verify_mode.name == "CERT_REQUIRED" and ctx.check_hostname
    assert build_ssl_context(verify_tls=False, ca_bundle_pem=None).verify_mode.name == "CERT_NONE"


# ---- L2 passwords / usernames, L7 rehash, CSRF HMAC ---------------------------------------
def test_password_policy() -> None:
    assert validate_password("a" * 12) == "a" * 12
    assert validate_password("p" * 128)
    for bad in ("short", "a" * 11, "a" * 129, " " + "a" * 12, "a" * 12 + " ", "a" * 12 + "\n"):
        with pytest.raises(PasswordPolicyError):
            validate_password(bad)
    assert validate_password("inner spaces are fine")


def test_username_normalisation() -> None:
    assert normalise_username("  Alice ") == "alice"
    assert validate_username("Alice.Smith@x") == "alice.smith@x"
    for bad in ("", "-x", "a b", "a" * 65, "ü"):
        with pytest.raises(ValueError):
            validate_username(bad)


def test_needs_rehash() -> None:
    from argon2 import PasswordHasher

    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("x" * 12)
    assert needs_rehash(weak)
    assert not needs_rehash(hash_password("x" * 12))


def test_csrf_binding_is_keyed() -> None:
    assert bind_csrf("t", "k" * 32) != bind_csrf("t", "j" * 32)
    assert bind_csrf("t", "k" * 32) == bind_csrf("t", "k" * 32)


# ---- L3 settings --------------------------------------------------------------------------
def _env(monkeypatch: pytest.MonkeyPatch, **extra: str) -> None:
    base = {
        "DATABASE_URL": "postgresql://x/y",
        "SESSION_SECRET": "s" * 40,
        "CREDENTIAL_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "SESSION_TTL_MINUTES": "30",
    }
    for k, v in {**base, **extra}.items():
        monkeypatch.setenv(k, v)


def test_cookie_secure_false_requires_dev_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch, COOKIE_SECURE="false")
    with pytest.raises(ValueError):
        Settings(_env_file=None)
    _env(monkeypatch, COOKIE_SECURE="false", DEV_MODE="true")
    assert Settings(_env_file=None).cookie_secure is False


def test_list_settings_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch, TRUSTED_PROXIES="10.0.0.0/8, 192.168.1.1", ALLOWED_HOSTS="a.test,b.test",
         ALLOWED_ORIGINS="https://A.test", ALLOW_INSECURE_TLS="true")  # fmt: skip
    s = Settings(_env_file=None)
    assert s.trusted_proxies == ["10.0.0.0/8", "192.168.1.1/32"]
    assert s.allowed_hosts == ["a.test", "b.test"] and s.allowed_origins == ["https://a.test"]
    assert s.allow_insecure_tls is True
    _env(monkeypatch, TRUSTED_PROXIES="nonsense")
    with pytest.raises(ValueError):
        Settings(_env_file=None)
    _env(monkeypatch, TRUSTED_PROXIES="", ALLOWED_HOSTS="*")
    with pytest.raises(ValueError):
        Settings(_env_file=None)


def test_defaults_are_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    for k in ("TRUSTED_PROXIES", "ALLOW_INSECURE_TLS", "ALLOWED_HOSTS", "ENABLE_DOCS"):
        monkeypatch.delenv(k, raising=False)
    s = Settings(_env_file=None)
    assert s.trusted_proxies == [] and s.allow_insecure_tls is False
    assert s.session_idle_timeout_minutes == 30 and s.max_sessions_per_user == 5


# ---- L6 crypto binding, L5 logging --------------------------------------------------------
def test_ciphertext_bound_to_context() -> None:
    c = CredentialCipher(Fernet.generate_key().decode())
    token = c.encrypt("value-123456", "fw1:api_key")
    assert c.decrypt(token, "fw1:api_key") == "value-123456"
    for other in ("fw2:api_key", "fw1:api_secret"):
        with pytest.raises(CredentialDecryptionError):
            c.decrypt(token, other)
    legacy = c.encrypt("old-value-1234")  # unbound, pre-existing rows still decrypt
    assert c.decrypt(legacy, "fw1:api_key") == "old-value-1234"


def test_known_secrets_bounded_and_stdlib_redacted() -> None:
    _known_secrets.clear()
    for i in range(MAX_KNOWN_SECRETS + 50):
        register_secret(f"secret-value-{i:06d}")
    assert len(_known_secrets) == MAX_KNOWN_SECRETS
    stream = io.StringIO()
    configure_logging(stream)
    register_secret("stdlib-leak-value")
    handler = logging.StreamHandler(stream)
    handler.addFilter(
        __import__("app.core.logging", fromlist=["RedactingFilter"]).RedactingFilter()
    )
    lg = logging.getLogger("uvicorn.error")
    lg.addHandler(handler)
    try:
        lg.error("boom %s Bearer abcdef123456", "stdlib-leak-value")
    finally:
        lg.removeHandler(handler)
    out = stream.getvalue()
    assert "stdlib-leak-value" not in out and "abcdef123456" not in out
