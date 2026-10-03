"""Hold each device's state as an asset inventory system reports it

ReportMate only sees check-ins, so a device sitting on a shelf looks exactly
like one that has gone missing. An asset inventory system knows the
difference: whether the device is checked out to someone, stored in a room,
or on its way out. This table holds that answer, written in bulk by the
inventory side, keyed by serial number in upper case so it joins regardless
of how a client reported the serial.

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-03
"""

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """CREATE TABLE IF NOT EXISTS device_inventory_state (
            serial_number TEXT PRIMARY KEY,
            state TEXT NOT NULL
                CHECK (state IN ('checked_out', 'storage', 'decommissioning')),
            storage_location TEXT,
            lease_number TEXT,
            asset_tag TEXT,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )"""
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_device_inventory_state_state "
        "ON device_inventory_state (state)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS device_inventory_state")
