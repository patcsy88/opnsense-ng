import io
import json

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.core.config import Settings
from app.core.crypto import CredentialCipher, CredentialDecryptionError
from app.core.logging import configure_logging, get_logger, register_secret


def test_settings_fail_fast_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "DATABASE_URL",
        "SESSION_SECRET",
        "CREDENTIAL_ENCRYPTION_KEY",
        "SESSION_TTL_MINUTES",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_reject_invalid_fernet_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_KEY", "not-a-key")
    with pytest.raises(ValidationError) as exc:
        Settings(_env_file=None)
    assert "not-a-key" not in str(exc.value)


def test_cipher_roundtrip_and_rotation() -> None:
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    token = CredentialCipher(old).encrypt("s3cret-value")
    assert "s3cret-value" not in token
    assert CredentialCipher(f"{new},{old}").decrypt(token) == "s3cret-value"
    with pytest.raises(CredentialDecryptionError):
        CredentialCipher(new).decrypt(token)


def test_log_redaction() -> None:
    stream = io.StringIO()
    configure_logging(stream)
    register_secret("super-secret-literal")
    get_logger("t").info(
        "event super-secret-literal",
        password="hunter2hunter2",
        nested={"api_key": "abc"},
        ok="fine",
    )
    out = stream.getvalue()
    assert "hunter2" not in out and "super-secret-literal" not in out and "abc" not in out
    assert json.loads(out)["ok"] == "fine"
