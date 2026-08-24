"""The usage upsert executed against a real PostgreSQL.

Every other usage test exercises the pure helpers (`_usage_entry_numbers`,
`_usage_entry_date`) and never runs the statement. That gap shipped a
statement-level type error to production: `LEAST(%s, %s)` sends two
parameters with no type OID, pg8000 leaves the type to the server, function
resolution picks text because it has nothing to resolve against, and the
insert dies with 42804 against a double precision column. Unit tests over
the helpers all passed while fleet-wide utilization collection was dead.

So these tests execute `USAGE_UPSERT_SQL` itself -- imported, not copied, so
it cannot drift from the statement the router runs -- through the same driver
the app uses. Skipped without TEST_DATABASE_URL; CI provides one.
"""

import json
import os

import pytest

from routers.events import USAGE_DAY_SECONDS_CAP, USAGE_UPSERT_SQL

_TEST_DB = os.getenv("TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not _TEST_DB, reason="TEST_DATABASE_URL not set; skipping live-DB usage upsert tests"
)


def _params(serial, date, app, *, launches=0, total=0.0, active=0.0, foreground=0.0,
            publisher="", users=()):
    """Bind in exactly the order the router binds."""
    return (
        serial, date, app, publisher,
        launches, total,
        active, USAGE_DAY_SECONDS_CAP,
        foreground, USAGE_DAY_SECONDS_CAP,
        json.dumps(list(users)),
        USAGE_DAY_SECONDS_CAP,
        USAGE_DAY_SECONDS_CAP,
        USAGE_DAY_SECONDS_CAP,
        USAGE_DAY_SECONDS_CAP,
    )


@pytest.fixture
def conn():
    from urllib.parse import urlparse

    import pg8000

    u = urlparse(_TEST_DB)
    c = pg8000.connect(
        host=u.hostname,
        port=u.port or 5432,
        database=u.path.lstrip("/"),
        user=u.username,
        password=u.password,
    )
    cur = c.cursor()
    # usage_history keys on device_id -> devices.id, so the parent row has to
    # exist before the upsert will take.
    cur.execute("CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY)")
    cur.execute(
        """CREATE TABLE IF NOT EXISTS usage_history (
               id SERIAL PRIMARY KEY,
               device_id TEXT NOT NULL,
               date DATE NOT NULL,
               app_name TEXT NOT NULL,
               publisher TEXT DEFAULT '',
               launches INTEGER NOT NULL DEFAULT 0,
               total_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
               active_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
               foreground_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
               users JSONB DEFAULT '[]'::jsonb,
               updated_at TIMESTAMPTZ DEFAULT NOW(),
               UNIQUE (device_id, date, app_name))"""
    )
    c.commit()
    yield c
    cur.execute("DELETE FROM usage_history WHERE device_id LIKE 'TEST-%'")
    c.commit()
    c.close()


def _read(conn, serial, app):
    cur = conn.cursor()
    cur.execute(
        "SELECT launches, total_seconds, active_seconds, foreground_seconds, users"
        " FROM usage_history WHERE device_id = %s AND app_name = %s",
        (serial, app),
    )
    return cur.fetchone()


def test_upsert_stores_a_row(conn):
    # The regression this file exists for: before the ::double precision casts
    # this raised 42804 and no usage row was ever written, for any device.
    cur = conn.cursor()
    cur.execute(USAGE_UPSERT_SQL,
                _params("TEST-A", "2026-08-24", "Maya",
                        launches=3, total=900.5, active=120.25, foreground=240.5))
    at_ceiling = cur.fetchone()[0]
    conn.commit()

    assert at_ceiling is False
    launches, total, active, foreground, _ = _read(conn, "TEST-A", "Maya")
    assert (launches, total, active, foreground) == (3, 900.5, 120.25, 240.5)


def test_second_window_accumulates(conn):
    # Clients send window deltas, not cumulative totals, so the same day's
    # second POST must add rather than replace.
    cur = conn.cursor()
    cur.execute(USAGE_UPSERT_SQL, _params("TEST-B", "2026-08-24", "Photoshop",
                                          launches=1, total=100.0, active=50.0,
                                          foreground=60.0))
    cur.fetchone()
    cur.execute(USAGE_UPSERT_SQL, _params("TEST-B", "2026-08-24", "Photoshop",
                                          launches=2, total=200.0, active=25.0,
                                          foreground=30.0))
    cur.fetchone()
    conn.commit()

    launches, total, active, foreground, _ = _read(conn, "TEST-B", "Photoshop")
    assert (launches, total, active, foreground) == (3, 300.0, 75.0, 90.0)


def test_active_and_foreground_hold_at_the_daily_ceiling(conn):
    # One machine cannot supply more than 24h of human attention in a day.
    # total_seconds is summed process lifetime and stays uncapped.
    cur = conn.cursor()
    cur.execute(USAGE_UPSERT_SQL,
                _params("TEST-C", "2026-08-24", "Firefox",
                        total=200000.0, active=80000.0, foreground=80000.0))
    cur.fetchone()
    cur.execute(USAGE_UPSERT_SQL,
                _params("TEST-C", "2026-08-24", "Firefox",
                        total=200000.0, active=80000.0, foreground=80000.0))
    at_ceiling = cur.fetchone()[0]
    conn.commit()

    _, total, active, foreground, _ = _read(conn, "TEST-C", "Firefox")
    assert at_ceiling is True
    assert active == USAGE_DAY_SECONDS_CAP
    assert foreground == USAGE_DAY_SECONDS_CAP
    assert total == 400000.0


def test_single_window_over_the_ceiling_is_capped_on_insert(conn):
    # The cap has to hold on the INSERT arm too, not only on conflict --
    # that arm is where the LEAST() parameters are untyped.
    cur = conn.cursor()
    cur.execute(USAGE_UPSERT_SQL,
                _params("TEST-D", "2026-08-24", "Blender",
                        active=90000.0, foreground=90000.0))
    conn.commit()

    _, _, active, foreground, _ = _read(conn, "TEST-D", "Blender")
    assert active == USAGE_DAY_SECONDS_CAP
    assert foreground == USAGE_DAY_SECONDS_CAP


def test_users_merge_without_duplicates(conn):
    cur = conn.cursor()
    cur.execute(USAGE_UPSERT_SQL, _params("TEST-E", "2026-08-24", "Slack",
                                          users=["alice", "bob"]))
    cur.fetchone()
    cur.execute(USAGE_UPSERT_SQL, _params("TEST-E", "2026-08-24", "Slack",
                                          users=["bob", "carol", ""]))
    cur.fetchone()
    conn.commit()

    users = _read(conn, "TEST-E", "Slack")[4]
    if isinstance(users, str):
        users = json.loads(users)
    assert sorted(users) == ["alice", "bob", "carol"]
