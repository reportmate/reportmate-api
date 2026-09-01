"""logs module: one row per device holding the Managed*/logs survey

The ``logs`` module carries, per management-tool log root on the endpoint
(``C:\\ProgramData\\Managed*\\logs`` on Windows, ``/Library/Managed */logs``
on macOS), the file inventory, the latest session summary and a capped tail
of the primary log. It is stored like every other module: one JSONB row per
device, replaced on each check-in.

The table is shaped exactly like ``management`` so the shared ingest loop in
``routers/events.py`` needs no special case. The foreign key matches the
other module tables (defined in the infrastructure schema, not here), so a
device delete cascades into this table too.

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-01
"""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """CREATE TABLE IF NOT EXISTS logs (
            id SERIAL PRIMARY KEY,
            device_id VARCHAR(255) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            data JSONB NOT NULL,
            collected_at TIMESTAMPTZ DEFAULT NOW(),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            CONSTRAINT unique_logs_per_device UNIQUE(device_id)
        )"""
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_logs_device_updated ON logs(device_id, updated_at DESC)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS logs")
