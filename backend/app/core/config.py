"""Application settings, loaded from the environment. Missing values fail fast at startup."""

from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.crypto import CredentialCipher


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        extra="ignore", case_sensitive=False, hide_input_in_errors=True
    )

    database_url: str
    session_secret: SecretStr = Field(min_length=32)
    credential_encryption_key: SecretStr
    session_ttl_minutes: int = Field(gt=0, le=60 * 24 * 30)

    cookie_secure: bool = True
    login_rate_limit: str = "5/minute"
    default_rate_limit: str = "120/minute"
    enable_docs: bool = False

    opnsense_connect_timeout_s: float = Field(default=5.0, gt=0)
    opnsense_read_timeout_s: float = Field(default=15.0, gt=0)
    opnsense_max_retries: int = Field(default=2, ge=0, le=5)
    opnsense_backoff_base_s: float = Field(default=0.25, ge=0)

    @field_validator("credential_encryption_key")
    @classmethod
    def _valid_fernet_keys(cls, value: SecretStr) -> SecretStr:
        CredentialCipher(value.get_secret_value())  # raises ValueError without echoing the key
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()  # values come from the environment
