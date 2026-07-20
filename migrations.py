"""Run Alembic migrations programmatically.

Called from the application lifespan on startup so the schema is brought to
head before the app serves traffic — replacing the previous ad-hoc
``_ensure_performance_indexes`` DDL loop (which swallowed every exception and
was untracked). Migrations are versioned in ``alembic/versions`` and recorded
in the ``alembic_version`` table.

The baseline migration is idempotent, so running it against the existing
production database is a series of no-ops.
"""

from __future__ import annotations

import os

from alembic import command
from alembic.config import Config

_HERE = os.path.dirname(os.path.abspath(__file__))


def run_migrations() -> None:
    cfg = Config(os.path.join(_HERE, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_HERE, "alembic"))
    command.upgrade(cfg, "head")
