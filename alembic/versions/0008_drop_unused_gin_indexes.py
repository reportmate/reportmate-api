"""Drop the never-scanned GIN indexes on the module JSONB columns

Every module table carries a GIN index over its whole ``data`` JSONB column,
created by the baseline schema for ad-hoc containment queries that nothing
in the API issues. Measured on 2026-09-02 in production: twelve such indexes
hold 73 GB of a 77 GB database and pg_stat_user_indexes reports idx_scan = 0
for every one of them since statistics began. They are also where the
~1 GB/day growth lives -- each device check-in rewrites its module rows and
the GIN entries with them -- which is what projected the storage lock that
took the API read-only on 2026-07-16.

The heaps themselves total under 2 GB. Dropping the indexes reclaims the
space and removes the growth; the rows and every query path are untouched
because no plan ever used them. usage_history has no GIN index and is not
touched.

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-02
"""
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

# (index name, table) -- kept so downgrade can recreate the same definitions.
UNUSED_GIN_INDEXES = [
    ("idx_applications_data_gin", "applications"),
    ("idx_management_data_gin", "management"),
    ("idx_hardware_data_gin", "hardware"),
    ("idx_profiles_data_gin", "profiles"),
    ("idx_installs_data_gin", "installs"),
    ("idx_security_data_gin", "security"),
    ("idx_system_data_gin", "system"),
    ("idx_inventory_data_gin", "inventory"),
    ("idx_network_data_gin", "network"),
    ("idx_peripherals_data_gin", "peripherals"),
    ("idx_displays_data_gin", "displays"),
    ("idx_printers_data_gin", "printers"),
]


def upgrade() -> None:
    # A plain DROP INDEX is a catalog change plus file unlink: it takes an
    # ACCESS EXCLUSIVE lock on the table for milliseconds and needs no
    # rebuild, so it is safe inside the migration transaction at startup.
    for index_name, _table in UNUSED_GIN_INDEXES:
        op.execute(f"DROP INDEX IF EXISTS {index_name}")


def downgrade() -> None:
    for index_name, table in UNUSED_GIN_INDEXES:
        op.execute(
            f"CREATE INDEX IF NOT EXISTS {index_name} ON {table} USING gin(data)"
        )
