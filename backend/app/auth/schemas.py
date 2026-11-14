import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.auth.security import PASSWORD_MAX_LENGTH, USERNAME_MAX_LENGTH, normalise_username
from app.db.models import Role


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=USERNAME_MAX_LENGTH)
    # Login accepts anything up to the policy maximum (older passwords may predate the policy).
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)

    @field_validator("username")
    @classmethod
    def _normalise(cls, value: str) -> str:
        return normalise_username(value)


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    role: Role
    mfa_enabled: bool = False
    # True while the user's role requires MFA and they have not enrolled: the session is
    # restricted to the enrolment endpoints (ADR-0012).
    mfa_enrolment_required: bool = False
    must_change_password: bool = False


class LoginResponse(BaseModel):
    """Either a signed-in user, or ``mfa_required`` with a challenge and no session."""

    user: UserOut | None = None
    csrf_token: str | None = None
    mfa_required: bool = False
    challenge: str | None = None


class MfaLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge: str = Field(min_length=1, max_length=100)
    code: str = Field(min_length=1, max_length=32)


class LogoutAllResponse(BaseModel):
    revoked: int
