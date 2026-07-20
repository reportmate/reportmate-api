"""Alembic environment.

The database URL comes from the application's own ``DATABASE_URL`` (and SSL
choice from ``DB_SSL``), so there is a single source of truth and no
credentials live in the repo. The engine uses the pg8000 driver, matching the
runtime.
"""

from __future__ import annotations

import os
import ssl

from alembic import context
from sqlalchemy import create_engine

# Raw-SQL migrations (no ORM models), so there is no target metadata to
# autogenerate against.
target_metadata = None


def _sqlalchemy_url() -> str:
    raw = os.environ.get(
        "DATABASE_URL", "postgresql://reportmate:password@localhost:5432/reportmate"
    )
    if raw.startswith("postgresql://"):
        raw = "postgresql+pg8000://" + raw[len("postgresql://") :]
    elif raw.startswith("postgres://"):
        raw = "postgresql+pg8000://" + raw[len("postgres://") :]
    # Drop any query string (e.g. ?sslmode=require); SSL is handled below.
    return raw.split("?", 1)[0]


def _connect_args() -> dict:
    db_ssl = os.getenv("DB_SSL", "true").lower() not in ("false", "0", "no", "disable")
    return {"ssl_context": ssl.create_default_context()} if db_ssl else {}


def run_migrations_offline() -> None:
    context.configure(
        url=_sqlalchemy_url(), target_metadata=target_metadata, literal_binds=True
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_sqlalchemy_url(), connect_args=_connect_args(), future=True)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
