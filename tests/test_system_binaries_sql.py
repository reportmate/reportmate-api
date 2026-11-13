"""The binaries report queries against real PostgreSQL.

Seeds a macOS and a Windows SAMPLE device with the binaries arrays the clients
send, plus a device that has not reported binaries yet. Skipped without
TEST_DATABASE_URL; CI provides one.
"""

import json
import os
from urllib.parse import urlparse

import pytest

_TEST_DB = os.getenv("TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(not _TEST_DB, reason="TEST_DATABASE_URL not set; skipping live-DB binaries tests")

SCHEMA = "system_binaries_test"

MACOS = {
    "operatingSystem": {"name": "macOS"},
    "binaries": [
        {"name": "httpd", "category": "server", "path": "/usr/sbin/httpd", "source": "os",
         "version": "2.4.67", "versionSource": "binary", "running": True, "processCount": 5},
        {"name": "node", "category": "runtime", "path": "/opt/homebrew/bin/node", "source": "homebrew",
         "resolvedPath": "/opt/homebrew/Cellar/node/22.1.0/bin/node", "package": "node", "version": "22.1.0", "running": False},
        "not an object",
    ],
}
WINDOWS = {
    "operatingSystem": {"name": "Windows 11 Enterprise"},
    "binaries": [
        {"name": "httpd", "category": "server", "path": "C:\\Apache24\\bin\\httpd.exe", "source": "unknown",
         "version": "2.4.62", "versionSource": "fileVersion", "running": False, "serviceName": "Apache2.4"},
    ],
}
NOT_REPORTED = {"operatingSystem": {"name": "macOS"}}


def _connect(search_path=True):
    import pg8000

    pg8000.paramstyle = "pyformat"
    u = urlparse(_TEST_DB)
    conn = pg8000.connect(host=u.hostname, port=u.port or 5432, database=u.path.lstrip("/"),
                          user=u.username, password=u.password)
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
    for serial, platform, data in (("SAMPLE1", "macOS", MACOS), ("SAMPLE2", "Windows", WINDOWS), ("SAMPLE3", "macOS", NOT_REPORTED)):
        cur.execute("INSERT INTO devices (id, serial_number, name, platform, last_seen) VALUES (%s, %s, %s, %s, NOW())",
                    (serial, serial, serial, platform))
        cur.execute("INSERT INTO system (device_id, data) VALUES (%s, %s::jsonb)", (serial, json.dumps(data)))
    conn.close()
    yield
    conn = _connect(search_path=False)
    conn.autocommit = True
    conn.cursor().execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")
    conn.close()


SCOPE = {"platform": "", "include_archived": False, "usages": [], "catalogs": [], "areas": [], "fleets": [],
         "locations": [], "rooms": [], "inventory_states": []}


def _run(name, params):
    from dependencies import load_sql

    conn = _connect()
    cur = conn.cursor()
    cur.execute(load_sql("devices/system_report_scope") + load_sql(f"devices/{name}"), params)
    rows = cur.fetchall()
    conn.close()
    return rows


def _devices(**params):
    rows = _run("system_binaries", {**SCOPE, "binary_keys": [], "categories": [], "running_only": False, **params})
    return {d["serialNumber"]: d for d in (r[0] if isinstance(r[0], dict) else json.loads(r[0]) for r in rows)}


def test_selected_binary_is_projected_per_device(db):
    devices = _devices(binary_keys=["httpd"])
    assert set(devices) == {"SAMPLE1", "SAMPLE2", "SAMPLE3"}
    assert devices["SAMPLE3"]["inventoryAvailable"] is False and devices["SAMPLE3"]["items"] == []
    mac = devices["SAMPLE1"]["items"]
    assert [(i["key"], i["version"], i["running"], i["processCount"]) for i in mac] == [("httpd", "2.4.67", True, 5)]
    assert devices["SAMPLE2"]["items"][0]["serviceName"] == "Apache2.4"


def test_categories_and_running_select_fleet_wide(db):
    assert [i["name"] for i in _devices(categories=["runtime"])["SAMPLE1"]["items"]] == ["node"]
    running = _devices(running_only=True)
    assert [i["name"] for i in running["SAMPLE1"]["items"]] == ["httpd"]
    assert running["SAMPLE2"]["items"] == []


def test_options_list_binary_names_with_device_counts(db):
    rows = _run("system_binaries_options", SCOPE)
    binaries = {(kind, value): devices for kind, value, _label, devices in rows if kind == "binary"}
    assert binaries == {("binary", "httpd"): 2, ("binary", "node"): 1}
