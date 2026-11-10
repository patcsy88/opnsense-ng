"""Bootstrap a user: ``python -m app.auth.cli <username> <role>`` (password read from a prompt)."""

import getpass
import sys

from app.auth.security import hash_password
from app.core.config import get_settings
from app.db.models import Role, User
from app.db.session import make_engine, make_sessionmaker


def _create(username: str, role: Role, password: str) -> None:
    engine = make_engine(get_settings().database_url)
    with make_sessionmaker(engine)() as db:
        db.add(User(username=username, role=role, password_hash=hash_password(password)))
        db.commit()
    engine.dispose()


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("usage: python -m app.auth.cli <username> <role>")
    role = Role(sys.argv[2])
    password = getpass.getpass("Password: ")
    if len(password) < 12:
        sys.exit("Password must be at least 12 characters")
    if password != getpass.getpass("Repeat: "):
        sys.exit("Passwords do not match")
    _create(sys.argv[1], role, password)
    print(f"Created user {sys.argv[1]} ({role.value})")


if __name__ == "__main__":
    main()
