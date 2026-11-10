from alembic import context
from sqlalchemy import create_engine

from app.core.config import get_settings
from app.db import models  # noqa: F401  (register tables)
from app.db.base import Base
from app.db.session import to_sync_url

target_metadata = Base.metadata


def _url() -> str:
    return to_sync_url(get_settings().database_url)


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url())
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
