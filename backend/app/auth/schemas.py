import uuid

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import Role


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    role: Role


class LoginResponse(BaseModel):
    user: UserOut
    csrf_token: str
