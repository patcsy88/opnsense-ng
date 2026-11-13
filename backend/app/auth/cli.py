"""User administration CLI.

    python -m app.auth.cli create <username> <role>   (password read from a prompt)
    python -m app.auth.cli cleanup-sessions
    python -m app.auth.cli set-password <username>    (also revokes that user's sessions)
    python -m app.auth.cli reset-mfa <username>       (clears MFA and revokes sessions)

For backwards compatibility ``python -m app.auth.cli <username> <role>`` still creates a user.
"""

import getpass
import sys

from sqlalchemy import select

from app import audit
from app.auth import mfa
from app.auth.security import (
    PasswordPolicyError,
    hash_password,
    validate_password,
    validate_username,
)
from app.auth.sessions import cleanup_expired, revoke_user_sessions
from app.core.config import get_settings
from app.db.models import Role, User
from app.db.session import make_engine, make_sessionmaker


def _prompt_password() -> str:
    password = getpass.getpass("Password: ")
    try:
        validate_password(password)
    except PasswordPolicyError as exc:
        sys.exit(str(exc))
    if password != getpass.getpass("Repeat: "):
        sys.exit("Passwords do not match")
    return password


def _create(username: str, role: Role, password: str) -> None:
    engine = make_engine(get_settings().database_url)
    with make_sessionmaker(engine)() as db:
        db.add(User(username=username, role=role, password_hash=hash_password(password)))
        db.commit()
    engine.dispose()


def change_password(username: str, password: str) -> int:
    """Set a new password and revoke every session of that user. Returns revoked sessions."""
    validate_password(password)
    engine = make_engine(get_settings().database_url)
    try:
        with make_sessionmaker(engine)() as db:
            user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
            if user is None:
                raise LookupError("no such user")
            user.password_hash = hash_password(password)
            revoked = revoke_user_sessions(db, user.id)
            db.commit()
            return revoked
    finally:
        engine.dispose()


def reset_mfa(username: str) -> int:
    """Clear a user's MFA (secret, recovery codes, challenges), revoke their sessions and record
    it in the audit log. Returns revoked sessions. This is the lost-device recovery path."""
    engine = make_engine(get_settings().database_url)
    try:
        with make_sessionmaker(engine)() as db:
            user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
            if user is None:
                raise LookupError("no such user")
            mfa.clear_mfa(db, user)
            revoked = revoke_user_sessions(db, user.id)
            audit.add(
                db,
                action="mfa.cli_reset",
                outcome=audit.OUTCOME_SUCCESS,
                user_id=user.id,
                username=user.username,
                detail={"sessions_revoked": revoked},
            )
            db.commit()
            return revoked
    finally:
        engine.dispose()


def cleanup_sessions() -> int:
    settings = get_settings()
    engine = make_engine(settings.database_url)
    try:
        with make_sessionmaker(engine)() as db:
            removed = cleanup_expired(db, settings)
            db.commit()
            return removed
    finally:
        engine.dispose()


def main() -> None:
    args = sys.argv[1:]
    if args[:1] == ["cleanup-sessions"] and len(args) == 1:
        print(f"Removed {cleanup_sessions()} expired session(s)")
        return
    if args[:1] == ["set-password"] and len(args) == 2:
        try:
            revoked = change_password(validate_username(args[1]), _prompt_password())
        except (LookupError, ValueError) as exc:
            sys.exit(str(exc))
        print(f"Password updated; {revoked} session(s) revoked")
        return
    if args[:1] == ["reset-mfa"] and len(args) == 2:
        try:
            revoked = reset_mfa(validate_username(args[1]))
        except (LookupError, ValueError) as exc:
            sys.exit(str(exc))
        print(f"MFA cleared; {revoked} session(s) revoked. The user must enrol again at next login")
        return
    if args[:1] == ["create"]:
        args = args[1:]
    if len(args) != 2:
        sys.exit(
            "usage: python -m app.auth.cli create <username> <role> | cleanup-sessions"
            " | set-password <username> | reset-mfa <username>"
        )
    try:
        username = validate_username(args[0])
        role = Role(args[1])
    except ValueError as exc:
        sys.exit(str(exc))
    _create(username, role, _prompt_password())
    print(f"Created user {username} ({role.value})")


if __name__ == "__main__":
    main()
