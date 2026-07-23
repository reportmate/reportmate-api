"""ingest_failures: persist rejected device check-ins

Devices send their full identity (serial, UUID, hostname) in the same request
as their credentials, so the server knows exactly which machine failed auth or
validation — but until now every rejection was a stdout log line and nothing
else. This table gives failed registrations/check-ins a durable, queryable
home so a device that is trying-but-failing to register is visible in the
product instead of only in container logs.

Deliberately standalone: no FK to ``devices`` — the whole point is recording
machines that are NOT (yet) in ``devices``.

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-23
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """CREATE TABLE IF NOT EXISTS ingest_failures (
            id BIGSERIAL PRIMARY KEY,
            occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            failure_type VARCHAR(20) NOT NULL,
            reason VARCHAR(50) NOT NULL,
            detail TEXT,
            status_code INTEGER,
            endpoint VARCHAR(200),
            client_ip VARCHAR(64),
            user_agent VARCHAR(400),
            serial_number VARCHAR(255),
            device_uuid VARCHAR(255),
            device_name VARCHAR(255),
            platform VARCHAR(32),
            client_version VARCHAR(64)
        )"""
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_ingest_failures_occurred"
        " ON ingest_failures(occurred_at DESC)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_ingest_failures_serial"
        " ON ingest_failures(serial_number)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_ingest_failures_reason"
        " ON ingest_failures(reason)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS ingest_failures")
