"""Application settings, loaded from the environment. Missing values fail fast at startup."""

import ipaddress
import json
from functools import lru_cache
from typing import Annotated, Any
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from app.core.crypto import CredentialCipher
from app.opnsense.netpolicy import DEFAULT_ALLOWED_NETWORKS

# Comma separated in the environment (``A,B``); a JSON list is accepted too.
CsvList = Annotated[list[str], NoDecode]

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _split_csv(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("["):
            return json.loads(text)
        return [part.strip() for part in text.split(",") if part.strip()]
    return value


def _networks(values: list[str], name: str) -> list[str]:
    out: list[str] = []
    for item in values:
        try:
            out.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            raise ValueError(f"{name}: {item!r} is not an IP address or CIDR") from None
    return out


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        extra="ignore", case_sensitive=False, hide_input_in_errors=True
    )

    database_url: str
    # Keys the HMAC that binds the CSRF token to the server-side session.
    session_secret: SecretStr = Field(min_length=32)
    credential_encryption_key: SecretStr
    session_ttl_minutes: int = Field(gt=0, le=60 * 24 * 30)
    session_idle_timeout_minutes: int = Field(default=30, gt=0)
    max_sessions_per_user: int = Field(default=5, ge=1, le=100)
    # Audit records older than this may be purged by an admin (ADR-0011). Never automatic.
    audit_retention_days: int = Field(default=365, ge=90, le=3650)
    # Roles that must use TOTP (ADR-0012). Empty makes MFA optional for everyone.
    mfa_required_roles: CsvList = ["admin", "network_admin", "security_admin", "read_only"]

    cookie_secure: bool = True
    # Explicit development switch; the only way to run with COOKIE_SECURE=false.
    dev_mode: bool = False
    login_rate_limit: str = "5/minute"
    default_rate_limit: str = "120/minute"
    enable_docs: bool = False

    # Per-username login backoff (DB backed): after N consecutive failures, lock for
    # base * 2^(failures-N) seconds, capped at max.
    login_lockout_threshold: int = Field(default=5, ge=1)
    login_lockout_base_seconds: int = Field(default=30, ge=1)
    login_lockout_max_seconds: int = Field(default=900, ge=1)

    # Networking / HTTP boundary
    trusted_proxies: CsvList = []
    allowed_hosts: CsvList = ["localhost", "127.0.0.1"]
    allowed_origins: CsvList = []

    # Firewall target policy. Loopback, link-local, unspecified, multicast and cloud
    # metadata addresses are always denied. Targets must be inside ALLOWED_FIREWALL_NETWORKS,
    # which defaults to private ranges only (RFC1918 + IPv6 ULA). Setting it REPLACES the
    # default (list the private ranges too if they are still needed); empty = default.
    allowed_firewall_networks: CsvList = list(DEFAULT_ALLOWED_NETWORKS)
    denied_firewall_networks: CsvList = []
    allow_insecure_tls: bool = False
    # Optional GeoLite2-Country .mmdb for country labels on blocked source addresses.
    geoip_db_path: str = ""

    opnsense_connect_timeout_s: float = Field(default=5.0, gt=0)
    opnsense_read_timeout_s: float = Field(default=15.0, gt=0)
    opnsense_max_retries: int = Field(default=2, ge=0, le=5)
    opnsense_backoff_base_s: float = Field(default=0.25, ge=0)

    @field_validator(
        "trusted_proxies",
        "allowed_hosts",
        "allowed_origins",
        "allowed_firewall_networks",
        "denied_firewall_networks",
        "mfa_required_roles",
        mode="before",
    )
    @classmethod
    def _csv(cls, value: Any) -> Any:
        return _split_csv(value)

    @field_validator("trusted_proxies")
    @classmethod
    def _valid_proxies(cls, value: list[str]) -> list[str]:
        return _networks(value, "TRUSTED_PROXIES")

    @field_validator("allowed_firewall_networks")
    @classmethod
    def _valid_allowed_nets(cls, value: list[str]) -> list[str]:
        if not value:  # an empty variable must never widen the policy
            return list(DEFAULT_ALLOWED_NETWORKS)
        return _networks(value, "ALLOWED_FIREWALL_NETWORKS")

    @field_validator("denied_firewall_networks")
    @classmethod
    def _valid_denied_nets(cls, value: list[str]) -> list[str]:
        return _networks(value, "DENIED_FIREWALL_NETWORKS")

    @field_validator("mfa_required_roles")
    @classmethod
    def _valid_mfa_roles(cls, value: list[str]) -> list[str]:
        known = {"admin", "network_admin", "security_admin", "read_only"}
        roles = [r.strip().lower() for r in value]
        unknown = [r for r in roles if r not in known]
        if unknown:
            raise ValueError("MFA_REQUIRED_ROLES: unknown role")
        return roles

    @field_validator("allowed_hosts")
    @classmethod
    def _valid_hosts(cls, value: list[str]) -> list[str]:
        hosts = [h.strip().lower() for h in value]
        if not hosts or any(h in {"", "*"} for h in hosts):
            raise ValueError("ALLOWED_HOSTS must list explicit hostnames (no bare '*')")
        return hosts

    @field_validator("allowed_origins")
    @classmethod
    def _valid_origins(cls, value: list[str]) -> list[str]:
        out: list[str] = []
        for item in value:
            parts = urlsplit(item)
            if (
                parts.scheme not in {"http", "https"}
                or not parts.netloc
                or parts.path
                not in {
                    "",
                    "/",
                }
            ):
                raise ValueError("ALLOWED_ORIGINS entries must look like https://host[:port]")
            out.append(f"{parts.scheme}://{parts.netloc}".lower())
        return out

    @field_validator("credential_encryption_key")
    @classmethod
    def _valid_fernet_keys(cls, value: SecretStr) -> SecretStr:
        CredentialCipher(value.get_secret_value())  # raises ValueError without echoing the key
        return value

    @model_validator(mode="after")
    def _secure_cookies_required(self) -> Settings:
        if not self.cookie_secure and not self.dev_mode:
            raise ValueError("COOKIE_SECURE=false is only allowed together with DEV_MODE=true")
        return self

    @property
    def trusted_proxy_networks(self) -> list[IPNetwork]:
        return [ipaddress.ip_network(n) for n in self.trusted_proxies]


@lru_cache
def get_settings() -> Settings:
    return Settings()  # values come from the environment
