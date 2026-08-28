"""Archive table for usage_history baseline resets

``usage_history`` accumulates client-sent window deltas, so a client-side
counting defect is written into the table permanently: the rows cannot be
recomputed from anything the server still holds. Correcting such a defect
therefore needs the affected rows removed, not repaired.

Deleting them outright would also destroy the only record of what was
reported, which is what a later "why did the April number change" question
needs. This table receives a verbatim copy first.

It is deliberately not a partition or a foreign-key child of usage_history:
archived rows must survive independently of anything that happens to the live
table, and must never be picked up by a reporting query. Retaining the
original ``id`` keeps a copy traceable to the row it came from, but the
archive has its own key because the same row can be archived more than once
(a reset re-run over an overlapping range).

``archived_at`` and ``reason`` record which reset produced a batch, so
several resets can share the table and still be told apart.

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-28
"""

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS usage_history_archive (
        archive_id BIGSERIAL PRIMARY KEY,
        id BIGINT,
        device_id TEXT NOT NULL,
        date DATE NOT NULL,
        app_name TEXT NOT NULL,
        publisher TEXT NOT NULL DEFAULT '',
        launches INTEGER NOT NULL DEFAULT 0,
        total_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
        active_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
        foreground_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
        users JSONB NOT NULL DEFAULT '[]'::jsonb,
        updated_at TIMESTAMPTZ,
        archived_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        reason TEXT NOT NULL DEFAULT ''
    )""",
    # Answering "what did we report for this device/app before the reset" is
    # the whole point of keeping the rows, so index the way that is asked.
    "CREATE INDEX IF NOT EXISTS idx_usage_history_archive_device_date "
    "ON usage_history_archive(device_id, date DESC)",
    "CREATE INDEX IF NOT EXISTS idx_usage_history_archive_app_date "
    "ON usage_history_archive(app_name, date DESC)",
    "CREATE INDEX IF NOT EXISTS idx_usage_history_archive_archived_at "
    "ON usage_history_archive(archived_at DESC)",
]


def _tolerant(stmt: str) -> str:
    # Same pattern as 0001/0003: swallow only "table does not exist" so a fresh
    # database (module tables are created by ingestion) migrates cleanly.
    body = stmt.replace("'", "''")
    return (
        "DO $$ BEGIN "
        f"EXECUTE '{body}'; "
        "EXCEPTION WHEN undefined_table THEN NULL; "
        "END $$;"
    )


def upgrade() -> None:
    for stmt in _STATEMENTS:
        op.execute(_tolerant(stmt))


def downgrade() -> None:
    # Dropping the archive would destroy the copies it exists to preserve, so
    # the downgrade removes only the indexes. Removing the table is a manual,
    # deliberate act.
    for stmt in [
        "DROP INDEX IF EXISTS idx_usage_history_archive_device_date",
        "DROP INDEX IF EXISTS idx_usage_history_archive_app_date",
        "DROP INDEX IF EXISTS idx_usage_history_archive_archived_at",
    ]:
        op.execute(_tolerant(stmt))
