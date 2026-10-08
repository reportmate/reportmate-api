"""Hold extension data: what outside systems attach to a device by serial

Modules are collected on the device and each has its own table. Extensions
are the server-side counterpart -- an MDM audit, a vendor risk score -- that
an integration writes against a serial number. They share one generic table
keyed by (device_id, extension_name), so a new extension needs no migration.

device_id holds devices.id, as every module table does. There is no foreign
key: the devices table is created by the ingestion path rather than by a
migration, so it cannot be relied on to exist when this runs, and device
deletion clears these rows explicitly the same way it clears the module
tables.

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-07
"""

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """CREATE TABLE IF NOT EXISTS extension_data (
            id BIGSERIAL PRIMARY KEY,
            device_id TEXT NOT NULL,
            extension_name TEXT NOT NULL,
            data JSONB NOT NULL,
            source TEXT,
            collected_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (device_id, extension_name)
        )"""
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_extension_data_name "
        "ON extension_data (extension_name)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS extension_data")
