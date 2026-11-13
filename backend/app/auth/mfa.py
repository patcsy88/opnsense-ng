"""MFA service: secrets, login challenges, recovery codes and code checking (ADR-0012).
Nothing here logs or audits a code, a secret or a challenge value."""

import hashlib
import secrets
import uuid
from datetime import timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, delete, func, select, update
from sqlalchemy.orm import Session

from app.auth import totp
from app.auth.security import hash_token, new_token
from app.core.config import Settings
from app.core.crypto import CredentialCipher, CredentialDecryptionError
from app.db.models import MfaChallenge, MfaRecoveryCode, User, utcnow

CHALLENGE_TTL = timedelta(minutes=5)
CHALLENGE_MAX_ATTEMPTS = 5
RECOVERY_CODE_COUNT = 10
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_RECOVERY_LENGTH = 16


def cipher(settings: Settings) -> CredentialCipher:
    return CredentialCipher(settings.credential_encryption_key.get_secret_value())


def _context(user_id: uuid.UUID) -> str:
    return f"{user_id}:mfa"


def store_secret(db: Session, settings: Settings, user: User, secret: str) -> None:
    user.mfa_secret_encrypted = cipher(settings).encrypt(secret, _context(user.id))
    user.mfa_enabled = False
    user.mfa_last_step = None


def load_secret(settings: Settings, user: User) -> str | None:
    if not user.mfa_secret_encrypted:
        return None
    try:
        return cipher(settings).decrypt(user.mfa_secret_encrypted, _context(user.id))
    except CredentialDecryptionError:
        return None


def is_required(settings: Settings, role: str) -> bool:
    return role in settings.mfa_required_roles


def _rowcount(result: object) -> int:
    return int(cast("CursorResult[Any]", result).rowcount or 0)


def accept_step(db: Session, user: User, step: int) -> bool:
    """Record ``step`` as used. Atomic, so one code cannot win two concurrent logins."""
    result = db.execute(
        update(User)
        .where(User.id == user.id, (User.mfa_last_step.is_(None)) | (User.mfa_last_step < step))
        .values(mfa_last_step=step)
    )
    return _rowcount(result) == 1


def normalise_recovery(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


def _recovery_hash(code: str) -> str:
    return hashlib.sha256(normalise_recovery(code).encode()).hexdigest()


def _format_recovery(raw: str) -> str:
    return "-".join(raw[i : i + 4] for i in range(0, len(raw), 4))


def replace_recovery_codes(db: Session, user: User) -> list[str]:
    """Delete the user's codes and create a fresh set. Returns the plain codes (shown once)."""
    db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    plain: list[str] = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(_RECOVERY_LENGTH))
        plain.append(_format_recovery(raw))
        db.add(MfaRecoveryCode(user_id=user.id, code_hash=_recovery_hash(raw)))
    return plain


def recovery_remaining(db: Session, user_id: uuid.UUID) -> int:
    return int(
        db.execute(
            select(func.count())
            .select_from(MfaRecoveryCode)
            .where(MfaRecoveryCode.user_id == user_id, MfaRecoveryCode.used_at.is_(None))
        ).scalar_one()
    )


def clear_mfa(db: Session, user: User) -> None:
    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    user.mfa_last_step = None
    db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    db.execute(delete(MfaChallenge).where(MfaChallenge.user_id == user.id))


def check_code(
    db: Session, settings: Settings, user: User, code: str, *, allow_recovery: bool = True
) -> str | None:
    """Verify a TOTP code or a recovery code for an enabled (or pending) user. Returns
    ``"totp"`` or ``"recovery"`` on success, else None. A TOTP step is accepted only once."""
    candidate = code.strip().replace(" ", "")
    if len(candidate) == totp.DIGITS and candidate.isdigit():
        secret = load_secret(settings, user)
        if secret is None:
            return None
        step = totp.matching_step(secret, candidate)
        if step is not None and accept_step(db, user, step):
            return "totp"
        return None
    if not candidate or not allow_recovery:
        return None
    used = db.execute(
        update(MfaRecoveryCode)
        .where(
            MfaRecoveryCode.user_id == user.id,
            MfaRecoveryCode.code_hash == _recovery_hash(candidate),
            MfaRecoveryCode.used_at.is_(None),
        )
        .values(used_at=utcnow())
    )
    return "recovery" if _rowcount(used) == 1 else None


def create_challenge(db: Session, user: User) -> str:
    """Issue a challenge, replacing any earlier one for the user. Returns the raw token."""
    db.execute(delete(MfaChallenge).where(MfaChallenge.user_id == user.id))
    token = new_token()
    now = utcnow()
    db.add(
        MfaChallenge(user_id=user.id, token_hash=hash_token(token), expires_at=now + CHALLENGE_TTL)
    )
    return token


def consume_challenge(db: Session, challenge_id: uuid.UUID) -> bool:
    """Delete the challenge; True only for the single caller that removed it."""
    return _rowcount(db.execute(delete(MfaChallenge).where(MfaChallenge.id == challenge_id))) == 1
