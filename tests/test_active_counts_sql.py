"""The active-vs-total device and user split, executed against real PostgreSQL.

`ARRAY_AGG(DISTINCT x) FILTER (WHERE ...)` is the whole mechanism here, and two
of its properties only show up against a server: the filtered aggregate returns
NULL rather than an empty array when nothing matches, and DISTINCT inside a
filtered aggregate has to be accepted at all. Asserting on Python-side mocks
would prove neither -- which is exactly how a type error in this same file's
sibling INSERT reached production and dropped eight days of fleet data.

Skipped without TEST_DATABASE_URL; CI provides one.
"""

import os

import pytest

_TEST_DB = os.getenv("TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not _TEST_DB, reason="TEST_DATABASE_URL not set; skipping live-DB active-count tests"
)

# The shape the endpoint relies on, reduced to the two aggregates under test.
QUERY = """
SELECT
    uh.app_name,
    ARRAY_AGG(DISTINCT uh.device_id)                                       AS devices,
    ARRAY_AGG(DISTINCT uh.device_id)
        FILTER (WHERE COALESCE(uh.active_seconds, 0) > 0)                  AS active_devices
FROM usage_history uh
WHERE uh.device_id LIKE 'ACT-%'
GROUP BY uh.app_name
ORDER BY uh.app_name
"""

USERS_QUERY = """
SELECT uh.app_name,
       ARRAY_AGG(DISTINCT u) AS users,
       ARRAY_AGG(DISTINCT u)
           FILTER (WHERE COALESCE(uh.active_seconds, 0) > 0) AS active_users
FROM usage_history uh
CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(uh.users, '[]'::jsonb)) AS u
WHERE uh.device_id LIKE 'ACT-%'
  AND u IS NOT NULL AND u <> ''
GROUP BY uh.app_name
ORDER BY uh.app_name
"""


@pytest.fixture
def conn():
    import json
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
    cur.execute("DELETE FROM usage_history WHERE device_id LIKE 'ACT-%'")

    # A background service: it ran everywhere, nobody used it. This is the
    # Houdini/Chrome shape that made "229 users" a meaningless seat count.
    for i in range(4):
        cur.execute(
            "INSERT INTO usage_history (device_id, date, app_name, total_seconds,"
            " active_seconds, users) VALUES (%s, %s, %s, %s, %s, %s::jsonb)",
            (f"ACT-BG{i}", "2026-08-24", "Daemon", 9000.0, 0.0,
             json.dumps([f"user{i}"])),
        )
    # A real application: ran on three devices, actually used on one.
    cur.execute(
        "INSERT INTO usage_history (device_id, date, app_name, total_seconds,"
        " active_seconds, users) VALUES (%s, %s, %s, %s, %s, %s::jsonb)",
        ("ACT-R1", "2026-08-24", "Maya", 500.0, 300.0, json.dumps(["alice"])),
    )
    for d in ("ACT-R2", "ACT-R3"):
        cur.execute(
            "INSERT INTO usage_history (device_id, date, app_name, total_seconds,"
            " active_seconds, users) VALUES (%s, %s, %s, %s, %s, %s::jsonb)",
            (d, "2026-08-24", "Maya", 500.0, 0.0, json.dumps(["bob"])),
        )
    c.commit()
    yield c
    cur.execute("DELETE FROM usage_history WHERE device_id LIKE 'ACT-%'")
    c.commit()
    c.close()


def _by_app(conn, sql):
    cur = conn.cursor()
    cur.execute(sql)
    return {r[0]: (r[1], r[2]) for r in cur.fetchall()}


def test_background_only_app_has_zero_active_devices(conn):
    # The regression this exists for. deviceCount says 4, which read as seats
    # would have the university buying four licences for a daemon.
    devices, active_devices = _by_app(conn, QUERY)["Daemon"]

    assert len(devices) == 4
    # FILTER yields NULL, not an empty array, when nothing matches -- the
    # calling code must coalesce, so pin the NULL rather than hiding it.
    assert active_devices is None


def test_real_app_separates_used_from_merely_running(conn):
    devices, active_devices = _by_app(conn, QUERY)["Maya"]

    assert len(devices) == 3
    assert active_devices == ["ACT-R1"]


def test_users_split_the_same_way(conn):
    rows = _by_app(conn, USERS_QUERY)

    daemon_users, daemon_active = rows["Daemon"]
    assert len(daemon_users) == 4
    assert daemon_active is None

    maya_users, maya_active = rows["Maya"]
    assert sorted(maya_users) == ["alice", "bob"]
    # bob's device ran Maya without ever using it, so bob is not a seat.
    assert maya_active == ["alice"]


def test_single_active_user_is_not_the_same_as_single_user(conn):
    # Maya has two users but one active user. isSingleUser would say False
    # while isSingleActiveUser says True -- and the second is the one a
    # single-seat licence claim rests on.
    maya_users, maya_active = _by_app(conn, USERS_QUERY)["Maya"]

    assert len(maya_users) == 2
    assert len(maya_active or []) == 1
