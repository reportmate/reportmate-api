"""The updates report query against real PostgreSQL.

Seeds a Windows and a macOS SAMPLE device with the system-module shapes the
clients send, plus an archived device, and checks that the query projects only
the update arrays and that the report shapes them into per-update rows.

Skipped without TEST_DATABASE_URL; CI provides one.
"""

import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

import pytest

_TEST_DB = os.getenv("TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not _TEST_DB, reason="TEST_DATABASE_URL not set; skipping live-DB updates tests"
)

SCHEMA = "system_updates_test"
NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

WINDOWS = {
    "collectedAt": NOW,
    "operatingSystem": {"name": "Windows 11 Enterprise"},
    "pendingWindowsUpdates": [
        {
            "title": "Security Update (KB5000001)",
            "kbNumber": "KB5000001",
            "category": "Security Updates",
            "severity": "Important",
            "cves": ["CVE-2026-0001"],
        }
    ],
    "pendingWindowsUpdatesCount": 1,
    "updates": [
        {"id": "KB5000002", "title": "Update", "installDate": "2026-06-01T00:00:00"}
    ],
    "services": [{"name": "unrelated"}],
}
MACOS = {"operatingSystem": {"name": "macOS"}, "pendingAppleUpdates": []}


def _connect(search_path=True):
    import pg8000

    pg8000.paramstyle = "pyformat"
    u = urlparse(_TEST_DB)
    conn = pg8000.connect(
        host=u.hostname,
        port=u.port or 5432,
        database=u.path.lstrip("/"),
        user=u.username,
        password=u.password,
    )
    if search_path:
        conn.cursor().execute(f"SET search_path TO {SCHEMA}")
    return conn


@pytest.fixture(scope="module")
def db():
    conn = _connect(search_path=False)
    conn.autocommit = True
    cur = conn.cursor()
    for stmt in [
        f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE",
        f"CREATE SCHEMA {SCHEMA}",
        f"SET search_path TO {SCHEMA}",
        """CREATE TABLE devices (id TEXT PRIMARY KEY, serial_number TEXT UNIQUE, name TEXT, platform TEXT,
               archived BOOLEAN NOT NULL DEFAULT FALSE, last_seen TIMESTAMPTZ)""",
        "CREATE TABLE system (device_id TEXT UNIQUE, data JSONB, collected_at TIMESTAMPTZ DEFAULT NOW())",
        "CREATE TABLE inventory (device_id TEXT UNIQUE, data JSONB)",
        "CREATE TABLE network (device_id TEXT UNIQUE, data JSONB)",
        "CREATE TABLE device_inventory_state (serial_number TEXT PRIMARY KEY, state TEXT)",
    ]:
        cur.execute(stmt)
    for serial, platform, data, archived in (
        ("SAMPLE1", "Windows", WINDOWS, False),
        ("SAMPLE2", "macOS", MACOS, False),
        ("SAMPLE3", "macOS", MACOS, True),
    ):
        cur.execute(
            "INSERT INTO devices (id, serial_number, name, platform, archived, last_seen) VALUES (%s, %s, %s, %s, %s, NOW())",
            (serial, serial, serial, platform, archived),
        )
        cur.execute(
            "INSERT INTO system (device_id, data) VALUES (%s, %s::jsonb)",
            (serial, json.dumps(data)),
        )
    conn.close()
    yield
    conn = _connect(search_path=False)
    conn.autocommit = True
    conn.cursor().execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")
    conn.close()


def _rows(platform="", include_archived=False):
    from dependencies import load_sql

    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        load_sql("devices/system_updates"),
        {"platform": platform, "include_archived": include_archived},
    )
    rows = [
        r[0] if isinstance(r[0], dict) else json.loads(r[0]) for r in cur.fetchall()
    ]
    conn.close()
    return rows


def test_query_projects_update_arrays_and_scope(db):
    rows = _rows()
    assert [r["serialNumber"] for r in rows] == ["SAMPLE1", "SAMPLE2"]
    assert "services" not in rows[0]
    assert rows[0]["pendingWindowsUpdatesCount"] == 1
    assert rows[0]["installedUpdates"][0]["id"] == "KB5000002"
    assert rows[1]["pendingAppleUpdates"] == []
    assert rows[1]["collectedAt"]
    assert [
        r["serialNumber"] for r in _rows(platform="macos", include_archived=True)
    ] == ["SAMPLE2", "SAMPLE3"]


def test_report_shapes_seeded_rows(db):
    from routers.system_updates import shape_updates

    result = shape_updates(
        _rows(),
        keys=set(),
        cves=set(),
        states=set(),
        freshness="all",
        max_age_hours=24,
        platform="",
        search="",
        security_only=False,
        deferred="all",
        reboot_required=False,
        min_age_days=0,
        limit=100,
        offset=0,
        now=datetime.now(timezone.utc),
    )
    assert sorted((r["serialNumber"], r["state"], r["kb"]) for r in result["rows"]) == [
        ("SAMPLE1", "pending", "KB5000001"),
        ("SAMPLE2", "none", None),
    ]
