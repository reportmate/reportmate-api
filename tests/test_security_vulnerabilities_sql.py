"""Fleet vulnerability and detection queries, against real PostgreSQL.

Seeds one Windows device with MSRC entries and detections, one macOS device
with SOFA entries, and one device with no security module, then checks that
both queries return every scoped device with its lists exactly as stored,
including a malformed list as null rather than an error.

Skipped without TEST_DATABASE_URL; CI provides one.
"""

import json
import os
from urllib.parse import urlparse

import pytest

_TEST_DB = os.getenv("TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not _TEST_DB,
    reason="TEST_DATABASE_URL not set; skipping live-DB vulnerability tests",
)

SCHEMA = "security_vulnerabilities_test"
WINDOWS = {
    "securityCves": [
        {
            "cve": "CVE-2026-10001",
            "status": "Unpatched",
            "severity": "Important",
            "kbArticle": "KB1000001",
        }
    ],
    "detections": [
        {
            "source": "WindowsDefender",
            "threatName": "Example threat",
            "detectedAt": "2026-01-01T00:00:00Z",
        }
    ],
}
MAC = {
    "unpatchedCVEs": [
        {
            "cve": "CVE-2026-10001",
            "os_version": "26.1",
            "patched_version": "26.2",
            "actively_exploited": "true",
        }
    ],
    "unpatchedCVEsTotal": 1,
    "unpatchedCVEsTruncated": False,
    "detections": {"unexpected": "object"},
}


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
        """CREATE TABLE devices (id TEXT PRIMARY KEY, device_id TEXT, serial_number TEXT UNIQUE, name TEXT,
               platform TEXT, archived BOOLEAN NOT NULL DEFAULT FALSE, last_seen TIMESTAMPTZ)""",
        "CREATE TABLE security (id SERIAL PRIMARY KEY, device_id TEXT UNIQUE, data JSONB, collected_at TIMESTAMPTZ DEFAULT NOW())",
        "CREATE TABLE system (id SERIAL PRIMARY KEY, device_id TEXT UNIQUE, data JSONB)",
        "CREATE TABLE inventory (id SERIAL PRIMARY KEY, device_id TEXT UNIQUE, data JSONB)",
        "CREATE TABLE device_inventory_state (serial_number TEXT PRIMARY KEY, state TEXT)",
    ]:
        cur.execute(stmt)
    for serial, platform, data in (
        ("TESTSERIAL01", "Windows", WINDOWS),
        ("TESTSERIAL02", "macOS", MAC),
        ("TESTSERIAL03", "macOS", None),
    ):
        cur.execute(
            "INSERT INTO devices (id, device_id, serial_number, name, platform, last_seen) VALUES (%s, %s, %s, %s, %s, NOW())",
            (serial, serial, serial, serial, platform),
        )
        if data is not None:
            cur.execute(
                "INSERT INTO security (device_id, data) VALUES (%s, %s::jsonb)",
                (serial, json.dumps(data)),
            )
        cur.execute(
            "INSERT INTO inventory (device_id, data) VALUES (%s, %s::jsonb)",
            (serial, json.dumps({"deviceName": f"{serial}-NAME", "usage": "Assigned"})),
        )
    cur.execute(
        "INSERT INTO device_inventory_state (serial_number, state) VALUES ('TESTSERIAL01', 'checked_out')"
    )
    conn.close()
    yield
    conn = _connect(search_path=False)
    conn.autocommit = True
    conn.cursor().execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")
    conn.close()


def _rows(kind, platform=""):
    from dependencies import load_sql

    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        load_sql(f"devices/security_{kind}"),
        {"platform": platform, "include_archived": False},
    )
    rows = [
        row[0] if isinstance(row[0], dict) else json.loads(row[0])
        for row in cur.fetchall()
    ]
    conn.close()
    return {row["serialNumber"]: row for row in rows}


def test_vulnerability_rows_keep_each_platform_list(db):
    rows = _rows("vulnerabilities")
    assert set(rows) == {"TESTSERIAL01", "TESTSERIAL02", "TESTSERIAL03"}
    assert (
        rows["TESTSERIAL01"]["windowsCves"] == WINDOWS["securityCves"]
        and rows["TESTSERIAL01"]["macCves"] is None
    )
    assert (
        rows["TESTSERIAL02"]["macCves"] == MAC["unpatchedCVEs"]
        and rows["TESTSERIAL02"]["windowsCves"] is None
    )
    assert rows["TESTSERIAL02"]["macCvesTruncated"] is False
    assert rows["TESTSERIAL01"]["macCvesTruncated"] is None
    assert rows["TESTSERIAL03"]["hasSecurity"] is False
    assert rows["TESTSERIAL01"]["inventoryState"] == "checked_out"
    assert rows["TESTSERIAL01"]["collectedAt"]


def test_platform_scope(db):
    assert set(_rows("vulnerabilities", "macos")) == {"TESTSERIAL02", "TESTSERIAL03"}


def test_detection_rows_null_a_malformed_list(db):
    rows = _rows("detections")
    assert rows["TESTSERIAL01"]["detections"] == WINDOWS["detections"]
    assert rows["TESTSERIAL02"]["detections"] is None
    assert rows["TESTSERIAL03"]["detections"] is None
