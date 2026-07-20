"""Baseline: app-owned tables + performance indexes

Captures exactly what the app previously created at startup in
``_ensure_performance_indexes`` (swallowed-exception DDL). All statements are
idempotent, so this is safe both on the existing production database (every
object already exists → no-ops) and on a fresh database.

Index creations on the collection-module tables (events, installs, hardware,
…) are wrapped so a missing table is tolerated: those tables are created by
the ingestion path, not here — historically the startup DDL swallowed the
"relation does not exist" error, and this preserves that behavior precisely
(catching only undefined_table).

Revision ID: 0001
Revises:
Create Date: 2026-07-20
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


# Tables this service fully owns — created here unconditionally (idempotent).
_APP_TABLES = [
    """CREATE TABLE IF NOT EXISTS usage_history (
        id BIGSERIAL PRIMARY KEY,
        device_id TEXT NOT NULL,
        date DATE NOT NULL,
        app_name TEXT NOT NULL,
        publisher TEXT NOT NULL DEFAULT '',
        launches INTEGER NOT NULL DEFAULT 0,
        total_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
        active_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
        foreground_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
        users JSONB NOT NULL DEFAULT '[]'::jsonb,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(device_id, date, app_name)
    )""",
    "ALTER TABLE usage_history ADD COLUMN IF NOT EXISTS active_seconds DOUBLE PRECISION NOT NULL DEFAULT 0",
    "ALTER TABLE usage_history ADD COLUMN IF NOT EXISTS foreground_seconds DOUBLE PRECISION NOT NULL DEFAULT 0",
    """CREATE TABLE IF NOT EXISTS idempotency_keys (
        key TEXT PRIMARY KEY,
        device_id TEXT,
        first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )""",
    """CREATE TABLE IF NOT EXISTS app_settings (
        id BIGSERIAL PRIMARY KEY,
        scope TEXT NOT NULL DEFAULT 'org',
        principal TEXT NOT NULL DEFAULT '',
        value JSONB NOT NULL DEFAULT '{}'::jsonb,
        schema_version INTEGER NOT NULL DEFAULT 1,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_by TEXT,
        UNIQUE(scope, principal)
    )""",
    """CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by TEXT,
        last_used TIMESTAMPTZ
    )""",
    """CREATE TABLE IF NOT EXISTS api_key_audit (
        id BIGSERIAL PRIMARY KEY,
        key_id TEXT,
        action TEXT NOT NULL,
        actor TEXT,
        detail JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )""",
]

# Indexes on tables this service owns (created just above) — plain and safe.
_APP_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_idempotency_first_seen ON idempotency_keys(first_seen)",
    "CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(active)",
    "CREATE INDEX IF NOT EXISTS idx_api_key_audit_key ON api_key_audit(key_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_usage_history_device_date ON usage_history(device_id, date DESC)",
    "CREATE INDEX IF NOT EXISTS idx_usage_history_app_date ON usage_history(app_name, date DESC)",
    "CREATE INDEX IF NOT EXISTS idx_usage_history_date ON usage_history(date)",
]

# Indexes on the collection-module tables, which are created by the ingestion
# path rather than here. Tolerate a not-yet-existing table.
_MODULE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp_desc ON events(timestamp DESC)",
    "CREATE INDEX IF NOT EXISTS idx_events_device_id ON events(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_installs_device_id ON installs(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_inventory_device_id ON inventory(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_system_device_id ON system(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_hardware_device_id ON hardware(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_network_device_id ON network(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_devices_serial ON devices(serial_number)",
    "CREATE INDEX IF NOT EXISTS idx_devices_archived ON devices(archived)",
    "CREATE INDEX IF NOT EXISTS idx_security_device_id ON security(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_profiles_device_id ON profiles(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_management_device_id ON management(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_applications_device_id ON applications(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_applications_data_gin ON applications USING gin(data)",
    "CREATE INDEX IF NOT EXISTS idx_peripherals_device_id ON peripherals(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_identity_device_id ON identity(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_applications_device_updated ON applications(device_id, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_installs_device_updated ON installs(device_id, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_security_device_updated ON security(device_id, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_hardware_device_updated ON hardware(device_id, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_network_device_updated ON network(device_id, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_management_device_updated ON management(device_id, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_profiles_device_updated ON profiles(device_id, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_system_device_updated ON system(device_id, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_inventory_device_updated ON inventory(device_id, updated_at DESC)",
]


def _tolerant(stmt: str) -> str:
    # Run the DDL inside a PL/pgSQL block that swallows only "table does not
    # exist"; every other error still aborts the migration.
    body = stmt.replace("'", "''")
    return (
        "DO $$ BEGIN "
        f"EXECUTE '{body}'; "
        "EXCEPTION WHEN undefined_table THEN NULL; "
        "END $$;"
    )


def upgrade() -> None:
    for stmt in _APP_TABLES + _APP_INDEXES:
        op.execute(stmt)
    for stmt in _MODULE_INDEXES:
        op.execute(_tolerant(stmt))


def downgrade() -> None:
    # Baseline: no downgrade (these objects predate migration tracking and
    # dropping them would be destructive to production).
    pass
