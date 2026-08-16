"""Dashboard performance: precomputed install issue counts + events type index

Two changes behind the consolidated /api/v1/dashboard endpoint:

1. ``installs`` gains four integer columns (cimian_errors, cimian_warnings,
   munki_errors, munki_warnings) holding per-device issue counts. They are
   written by the ingestion path whenever an installs module lands, and
   backfilled here with the exact JSONB expressions the dashboard previously
   evaluated per request (~2s per call). The dashboard stats query becomes a
   plain aggregate over these columns.

2. ``events`` gains a composite (event_type, timestamp DESC) index so the
   per-type recent-events fetch is five bounded index scans instead of a
   window function over the whole table (~1.4M rows, ~3s per call).

Statements on ingestion-owned tables use the same undefined_table-tolerant
wrapper as the baseline migration, so a fresh database (where those tables do
not exist yet) migrates cleanly.

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-16
"""

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


_STATEMENTS = [
    "ALTER TABLE installs ADD COLUMN IF NOT EXISTS cimian_errors INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE installs ADD COLUMN IF NOT EXISTS cimian_warnings INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE installs ADD COLUMN IF NOT EXISTS munki_errors INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE installs ADD COLUMN IF NOT EXISTS munki_warnings INTEGER NOT NULL DEFAULT 0",
    # Backfill with the same status-matching rules the dashboard used at read
    # time (statistics.py), so precomputed counts agree with historical output.
    """UPDATE installs SET
        cimian_errors = (
            SELECT COUNT(*) FROM jsonb_array_elements(
                CASE WHEN jsonb_typeof(data->'cimian'->'items') = 'array'
                     THEN data->'cimian'->'items' ELSE '[]'::jsonb END) item
            WHERE LOWER(item->>'currentStatus') ~ '(error|failed|problem|install-error)'
               OR LOWER(item->>'currentStatus') = 'needs_reinstall'
        ),
        cimian_warnings = (
            SELECT COUNT(*) FROM jsonb_array_elements(
                CASE WHEN jsonb_typeof(data->'cimian'->'items') = 'array'
                     THEN data->'cimian'->'items' ELSE '[]'::jsonb END) item
            WHERE LOWER(item->>'currentStatus') ~ '(warning|needs-attention)'
        ),
        munki_errors = (
            SELECT COUNT(*) FROM jsonb_array_elements(
                CASE WHEN jsonb_typeof(data->'munki'->'items') = 'array'
                     THEN data->'munki'->'items' ELSE '[]'::jsonb END) item
            WHERE LOWER(item->>'status') ~ '(error|failed)'
        ),
        munki_warnings = (
            SELECT COUNT(*) FROM jsonb_array_elements(
                CASE WHEN jsonb_typeof(data->'munki'->'items') = 'array'
                     THEN data->'munki'->'items' ELSE '[]'::jsonb END) item
            WHERE LOWER(item->>'status') ~ 'warning'
        )""",
    "CREATE INDEX IF NOT EXISTS idx_events_type_timestamp_desc ON events(event_type, timestamp DESC)",
]


def _tolerant(stmt: str) -> str:
    # Same pattern as 0001: swallow only "table does not exist" so a fresh
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
    for stmt in [
        "DROP INDEX IF EXISTS idx_events_type_timestamp_desc",
        "ALTER TABLE installs DROP COLUMN IF EXISTS cimian_errors",
        "ALTER TABLE installs DROP COLUMN IF EXISTS cimian_warnings",
        "ALTER TABLE installs DROP COLUMN IF EXISTS munki_errors",
        "ALTER TABLE installs DROP COLUMN IF EXISTS munki_warnings",
    ]:
        op.execute(_tolerant(stmt))
