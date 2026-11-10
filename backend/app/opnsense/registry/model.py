import enum

from pydantic import BaseModel, ConfigDict, Field


class HttpMethod(enum.StrEnum):
    GET = "GET"
    POST = "POST"


class UnknownOperationError(KeyError):
    """The operation id is not in the registry."""


class UnsupportedOperationError(Exception):
    """The operation is registered but explicitly marked unsupported."""


class Operation(BaseModel):
    """One declared OPNsense capability. Immutable."""

    model_config = ConfigDict(frozen=True)

    operation_id: str = Field(pattern=r"^[a-z][a-z0-9_.]*$")
    method: HttpMethod
    endpoint: str = Field(pattern=r"^/api/[A-Za-z0-9_/]+$")  # fixed path, never user supplied
    required_privilege: str  # OPNsense ACL privilege the API key needs (documentation/diagnostics)
    read_only: bool
    apply_required: bool = False
    min_version: str | None = None
    required_plugin: str | None = None
    supported: bool = True
    # True only after the endpoint/privilege were confirmed against a real (lab) OPNsense.
    verified: bool = False
    notes: str = ""
