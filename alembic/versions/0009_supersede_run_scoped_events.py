"""Allow a managed-software run to report more than one event per module

Install events accumulated forever: a device that hit a transient catalog
failure kept that error event, and the warnings that followed from it, next to
every clean run after it -- so the dashboard reported a device as erroring hours
after the problem had gone. Ingest now clears a device's installs events when a
fresh run arrives, and a run reports its outcome as up to three events (a
success, an error and a warning) under the one module_id.

The partial unique index admitted a single row per (device_id, module_id), which
was enough for the lone os_update event it was built for but rejects the second
event of a run. It is replaced with a plain index, which is what the per-device
delete wants anyway.

No backfill: the stale rows already in the table are cleared per device by that
delete on the device's next check-in, which is at most an hour away. Rewriting
them here instead would mean a table-wide UPDATE and DELETE inside the startup
lifespan, on a server whose p95 read IOPS already exceeds what is provisioned.

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-07
"""

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_events_device_module_upsert")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_device_module "
        "ON events(device_id, module_id) WHERE module_id IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_events_device_module")
    # The unique index admits one row per (device, module), so a run that
    # reported both a success and a warning has to lose one before it can be
    # recreated. Going back is lossy.
    op.execute(
        """
        DELETE FROM events e
        USING (
            SELECT device_id, module_id, MAX(id) AS keep
            FROM events
            WHERE module_id IS NOT NULL
            GROUP BY device_id, module_id
        ) newest
        WHERE e.device_id = newest.device_id
          AND e.module_id = newest.module_id
          AND e.id <> newest.keep
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_device_module_upsert "
        "ON events(device_id, module_id) WHERE module_id IS NOT NULL"
    )
