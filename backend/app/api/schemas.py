import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.db.models import BASE_URL_MAX_LENGTH
from app.opnsense.errors import ConnectionStatus
from app.opnsense.netpolicy import InvalidBaseUrlError, parse_base_url
from app.opnsense.normalise import AliasInfo, InterfaceInfo, RuleInfo, SystemStatus
from app.opnsense.tls import CA_BUNDLE_MAX_BYTES, InvalidCaBundleError, normalise_ca_bundle


def _check_base_url(value: str) -> str:
    try:
        return parse_base_url(value, BASE_URL_MAX_LENGTH)
    except InvalidBaseUrlError as exc:
        raise ValueError(str(exc)) from None


def _check_ca(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    try:
        return normalise_ca_bundle(value)
    except InvalidCaBundleError as exc:
        raise ValueError(str(exc)) from None


class FirewallCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    # Strings are validated by parse_base_url (https, host, optional port only).
    base_url: str = Field(min_length=1, max_length=BASE_URL_MAX_LENGTH)
    api_key: SecretStr = Field(min_length=1, max_length=512)
    api_secret: SecretStr = Field(min_length=1, max_length=512)
    verify_tls: bool = True
    ca_bundle_pem: str | None = Field(default=None, max_length=CA_BUNDLE_MAX_BYTES)

    @field_validator("base_url")
    @classmethod
    def _url(cls, value: str) -> str:
        return _check_base_url(value)

    @field_validator("ca_bundle_pem")
    @classmethod
    def _ca(cls, value: str | None) -> str | None:
        return _check_ca(value)


class FirewallUpdate(BaseModel):
    """Partial update; omitted fields are unchanged. ``ca_bundle_pem=""`` removes the bundle."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=100)
    base_url: str | None = Field(default=None, min_length=1, max_length=BASE_URL_MAX_LENGTH)
    api_key: SecretStr | None = Field(default=None, min_length=1, max_length=512)
    api_secret: SecretStr | None = Field(default=None, min_length=1, max_length=512)
    verify_tls: bool | None = None
    ca_bundle_pem: str | None = Field(default=None, max_length=CA_BUNDLE_MAX_BYTES)

    @field_validator("base_url")
    @classmethod
    def _url(cls, value: str | None) -> str | None:
        return None if value is None else _check_base_url(value)

    @field_validator("ca_bundle_pem")
    @classmethod
    def _ca(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            return ""
        return _check_ca(value)


class FirewallOut(BaseModel):
    """Credentials and the CA bundle contents are intentionally absent."""

    id: uuid.UUID
    name: str
    base_url: str
    verify_tls: bool
    has_ca_bundle: bool
    created_at: datetime


class FirewallOption(BaseModel):
    """Selector entry for any signed-in role: no URL, TLS settings or certificate details."""

    id: uuid.UUID
    name: str


class InterfacesOut(BaseModel):
    firewall_id: uuid.UUID
    interfaces: list[InterfaceInfo]
    registry_verified: bool


class AliasesOut(BaseModel):
    firewall_id: uuid.UUID
    aliases: list[AliasInfo]
    truncated: bool
    registry_verified: bool


class RulesOut(BaseModel):
    firewall_id: uuid.UUID
    rules: list[RuleInfo]
    truncated: bool
    registry_verified: bool


class ConnectivityOut(BaseModel):
    firewall_id: uuid.UUID
    ok: bool
    # Admins: detailed ConnectionStatus value. Other roles: "reachable" / "unreachable" only.
    status: ConnectionStatus | str
    message: str
    registry_verified: bool


class SystemStatusOut(BaseModel):
    firewall_id: uuid.UUID
    status: SystemStatus
    registry_verified: bool
