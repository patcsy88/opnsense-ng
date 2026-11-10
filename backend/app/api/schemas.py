import uuid
from datetime import datetime
from typing import Annotated

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, SecretStr, UrlConstraints

from app.opnsense.errors import ConnectionStatus
from app.opnsense.normalise import SystemStatus

HttpsUrl = Annotated[AnyHttpUrl, UrlConstraints(allowed_schemes=["https"])]


class FirewallCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    base_url: HttpsUrl
    api_key: SecretStr = Field(min_length=1, max_length=512)
    api_secret: SecretStr = Field(min_length=1, max_length=512)
    verify_tls: bool = True


class FirewallOut(BaseModel):
    """Credentials are intentionally absent."""

    id: uuid.UUID
    name: str
    base_url: str
    verify_tls: bool
    created_at: datetime


class ConnectivityOut(BaseModel):
    firewall_id: uuid.UUID
    ok: bool
    status: ConnectionStatus
    message: str


class SystemStatusOut(BaseModel):
    firewall_id: uuid.UUID
    status: SystemStatus
