"""Fernet-based encryption for firewall credentials at rest."""

from cryptography.fernet import Fernet, InvalidToken, MultiFernet


class CredentialDecryptionError(Exception):
    """Stored ciphertext could not be decrypted (wrong key or corrupted data)."""


class CredentialCipher:
    """Encrypts/decrypts strings. Accepts a comma-separated key list to support rotation:
    the first key encrypts, all keys can decrypt."""

    def __init__(self, keys: str) -> None:
        parts = [k.strip() for k in keys.split(",") if k.strip()]
        if not parts:
            raise ValueError("CREDENTIAL_ENCRYPTION_KEY is empty")
        try:
            self._fernet = MultiFernet([Fernet(k.encode()) for k in parts])
        except ValueError, TypeError:
            raise ValueError("CREDENTIAL_ENCRYPTION_KEY must be valid Fernet key(s)") from None

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            raise CredentialDecryptionError("Unable to decrypt stored credential") from None
