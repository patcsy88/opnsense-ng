import enum
import re

from pydantic import BaseModel, ConfigDict, Field, model_validator


class HttpMethod(enum.StrEnum):
    GET = "GET"
    POST = "POST"


class ResponseKind(enum.StrEnum):
    json = "json"
    sse = "sse"  # long-running event stream; only sampled in a bounded way


class UnknownOperationError(KeyError):
    """The operation id is not in the registry."""


class UnsupportedOperationError(Exception):
    """The operation is registered but explicitly marked unsupported."""


_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ALLOWED_PARAMS = frozenset({"uuid"})
_ALLOWED_QUERY = frozenset({"limit", "digest"})
_QUERY_VALUE = re.compile(r"^[A-Za-z0-9]{1,64}$")


class Operation(BaseModel):
    """One declared OPNsense capability. Immutable."""

    model_config = ConfigDict(frozen=True)

    operation_id: str = Field(pattern=r"^[a-z][a-z0-9_.]*$")
    method: HttpMethod
    # Fixed path, never user supplied. The only variable part is a declared trailing {uuid} slot.
    endpoint: str = Field(pattern=r"^/api/[A-Za-z0-9_/]+(/\{uuid\}(/[01])?)?$")
    path_params: tuple[str, ...] = ()
    # Declared query parameter names (GET only). Values are checked to be short alphanumerics.
    query_params: tuple[str, ...] = ()
    required_privilege: str  # OPNsense ACL privilege the API key needs (documentation/diagnostics)
    read_only: bool
    response_kind: ResponseKind = ResponseKind.json
    apply_required: bool = False
    min_version: str | None = None
    required_plugin: str | None = None
    supported: bool = True
    # True only after the endpoint/privilege were confirmed against a real (lab) OPNsense.
    verified: bool = False
    notes: str = ""

    @model_validator(mode="after")
    def _check_path_params(self) -> Operation:
        declared = set(self.path_params)
        if not declared <= _ALLOWED_PARAMS or ("{uuid}" in self.endpoint) != ("uuid" in declared):
            raise ValueError("endpoint placeholders and path_params must match")
        if self.query_params and (
            not set(self.query_params) <= _ALLOWED_QUERY or self.method is not HttpMethod.GET
        ):
            raise ValueError("query_params must be declared names on a GET operation")
        return self

    def check_query(self, query: dict[str, str] | None) -> dict[str, str]:
        given = query or {}
        if not set(given) <= set(self.query_params):
            raise ValueError(f"{self.operation_id} does not accept those query parameters")
        for name, value in given.items():
            if not isinstance(value, str) or not _QUERY_VALUE.match(value):
                raise ValueError(f"Invalid value for query parameter {name}")
        return dict(given)

    def resolve_endpoint(self, params: dict[str, str] | None = None) -> str:
        """Fill the declared slots. Values must be canonical lowercase UUIDs, nothing else."""
        given = params or {}
        if set(given) != set(self.path_params):
            raise ValueError(f"{self.operation_id} needs path parameters {self.path_params}")
        endpoint = self.endpoint
        for name, value in given.items():
            if not isinstance(value, str) or not _UUID.match(value):
                raise ValueError(f"Invalid value for path parameter {name}")
            endpoint = endpoint.replace("{" + name + "}", value)
        return endpoint
