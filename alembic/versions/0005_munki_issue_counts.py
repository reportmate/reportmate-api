"""Recompute the Munki dashboard counters with item and run-level fields.

Migration 0003 counted a Munki warning only when an item's status contained
"warning", which MunkiReport-style statuses never do. Munki problems arrive on
the item as lastWarning / lastError / currentStatus (newer clients) or on the
run as warningItems / errorItems (or the legacy semicolon-joined strings).
Ingest now counts them that way; this recomputes every stored row once so the
dashboard does not wait for each device's next check-in.

Revision ID: 0005
Revises: 0004
"""

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

_MUNKI_ITEMS = (
    "CASE WHEN jsonb_typeof(data->'munki'->'items') = 'array' "
    "THEN data->'munki'->'items' ELSE '[]'::jsonb END"
)


def _run_level(key: str, legacy_key: str) -> str:
    # Structured arrays win; fall back to the semicolon-joined legacy string.
    return (
        f"CASE WHEN jsonb_typeof(data->'munki'->'{key}') = 'array' THEN "
        f"  (SELECT COUNT(*) FROM jsonb_array_elements(data->'munki'->'{key}') e "
        f"   WHERE COALESCE(e->>'message', e->>'name', '') <> '') "
        f"WHEN COALESCE(data->'munki'->>'{legacy_key}', '') <> '' THEN "
        f"  (SELECT COUNT(*) FROM unnest(string_to_array(data->'munki'->>'{legacy_key}', ';')) p "
        f"   WHERE btrim(p) <> '') "
        f"ELSE 0 END"
    )


_BACKFILL = f"""UPDATE installs SET
    munki_errors = COALESCE(NULLIF((
        SELECT COUNT(*) FROM jsonb_array_elements({_MUNKI_ITEMS}) item
        WHERE LOWER(COALESCE(item->>'status', '')) ~ '(error|failed)'
           OR LOWER(COALESCE(item->>'currentStatus', '')) = 'error'
           OR COALESCE(item->>'lastError', '') <> ''
    ), 0), {_run_level('errorItems', 'errors')}),
    munki_warnings = COALESCE(NULLIF((
        SELECT COUNT(*) FROM jsonb_array_elements({_MUNKI_ITEMS}) item
        WHERE LOWER(COALESCE(item->>'status', '')) ~ 'warning'
           OR LOWER(COALESCE(item->>'currentStatus', '')) = 'warning'
           OR (COALESCE(item->>'lastWarning', '') <> '' AND COALESCE(item->>'lastError', '') = '')
    ), 0), {_run_level('warningItems', 'warnings')})
WHERE data ? 'munki'"""


def _tolerant(stmt: str) -> str:
    body = stmt.replace("'", "''")
    return (
        "DO $$ BEGIN "
        f"EXECUTE '{body}'; "
        "EXCEPTION WHEN undefined_table THEN NULL; "
        "END $$;"
    )


def upgrade() -> None:
    op.execute(_tolerant(_BACKFILL))


def downgrade() -> None:
    # The counters are derived data; 0003's rules are what ingest wrote before.
    pass
