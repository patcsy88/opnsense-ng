"""Password hashing, password/username policy and token helpers."""

import hashlib
import hmac
import re
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128
USERNAME_MAX_LENGTH = 64
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._@-]*$")

_hasher = PasswordHasher()
# Used to equalise timing when the user does not exist.
_DUMMY_HASH = _hasher.hash("not-a-real-password")


class PasswordPolicyError(ValueError):
    """The password violates the policy. The message is safe to show to the user."""


def validate_password(password: str) -> str:
    """Shared password policy (CLI, future change-password endpoint): 12..128 characters, no
    leading or trailing whitespace. Returns the password unchanged or raises."""
    if len(password) < PASSWORD_MIN_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters")
    if len(password) > PASSWORD_MAX_LENGTH:
        raise PasswordPolicyError(f"Password must be at most {PASSWORD_MAX_LENGTH} characters")
    if password != password.strip():
        raise PasswordPolicyError("Password must not start or end with whitespace")
    return password


def normalise_username(username: str) -> str:
    """Canonical form used for storage and lookup."""
    return username.strip().lower()


def validate_username(username: str) -> str:
    """For account creation: returns the normalised username or raises ValueError."""
    name = normalise_username(username)
    if not name or len(name) > USERNAME_MAX_LENGTH or not _USERNAME_RE.fullmatch(name):
        raise ValueError(
            "Username must be 1-64 characters: lowercase letters, digits and . _ @ - "
            "(starting with a letter or digit)"
        )
    return name


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except VerificationError, InvalidHashError:
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when the stored hash uses weaker parameters than the current hasher."""
    return _hasher.check_needs_rehash(password_hash)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def bind_csrf(csrf_token: str, secret: str) -> str:
    """Server-side value stored for a session's CSRF token: HMAC-SHA256 keyed with
    SESSION_SECRET, so a database leak alone cannot be used to forge the binding."""
    return hmac.new(secret.encode(), csrf_token.encode(), hashlib.sha256).hexdigest()


def tokens_match(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
