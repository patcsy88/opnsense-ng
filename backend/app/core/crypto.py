"""Fernet-based encryption for firewall credentials at rest."""

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

_PREFIX = "v1:"


class CredentialDecryptionError(Exception):
    """Stored ciphertext could not be decrypted (wrong key, corrupted data or wrong binding)."""


class CredentialCipher:
    """Encrypts/decrypts strings. Accepts a comma-separated key list to support rotation:
    the first key encrypts, all keys can decrypt.

    With a ``context`` (e.g. ``"<firewall id>:api_key"``) the context is placed inside the
    authenticated Fernet payload, so a ciphertext copied to another row or field fails to
    decrypt. Values written before binding existed (no ``v1:`` marker) are still accepted
    when no mismatch can be detected; re-save the firewall to bind them."""

    def __init__(self, keys: str) -> None:
        parts = [k.strip() for k in keys.split(",") if k.strip()]
        if not parts:
            raise ValueError("CREDENTIAL_ENCRYPTION_KEY is empty")
        try:
            self._fernet = MultiFernet([Fernet(k.encode()) for k in parts])
        except ValueError, TypeError:
            raise ValueError("CREDENTIAL_ENCRYPTION_KEY must be valid Fernet key(s)") from None

    def encrypt(self, plaintext: str, context: str | None = None) -> str:
        payload = f"{_PREFIX}{context}:{plaintext}" if context is not None else plaintext
        return self._fernet.encrypt(payload.encode()).decode()

    def decrypt(self, token: str, context: str | None = None) -> str:
        try:
            payload = self._fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            raise CredentialDecryptionError("Unable to decrypt stored credential") from None
        if context is None:
            return payload
        if payload.startswith(_PREFIX):
            expected = f"{_PREFIX}{context}:"
            if not payload.startswith(expected):
                raise CredentialDecryptionError("Stored credential is bound to another record")
            return payload.removeprefix(expected)
        return payload  # legacy, unbound value
