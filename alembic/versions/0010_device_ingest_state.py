"""Track successful check-ins by server acceptance time

``devices.last_seen`` is the client's collection timestamp. A retry carries
the same timestamp as the upload that disconnected, so it cannot prove that
the server accepted a later attempt. Keep that transport fact separately and
in server time so rejected-upload classification follows what the API actually
received.

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-16
"""

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """CREATE TABLE IF NOT EXISTS device_ingest_state (
            device_id TEXT PRIMARY KEY,
            last_accepted_at TIMESTAMPTZ NOT NULL
        )"""
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS device_ingest_state")
