"""Drop the logs table: log surveys live in the management module

Revision 0006 introduced a standalone ``logs`` table for the management-tool
log survey. The survey is a section of the management module instead
(``management.logs``), so the table is never written. Drop it.

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-01
"""

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP TABLE IF EXISTS logs")


def downgrade() -> None:
    op.execute(
        """CREATE TABLE IF NOT EXISTS logs (
            id SERIAL PRIMARY KEY,
            device_id VARCHAR(255) NOT NULL,
            data JSONB NOT NULL,
            collected_at TIMESTAMPTZ DEFAULT NOW(),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            CONSTRAINT unique_logs_per_device UNIQUE(device_id)
        )"""
    )
