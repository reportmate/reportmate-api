"""Device status is derived from last_seen, the same way on every endpoint.

The stored devices.status column is written once at enrollment and never
updated, so the device list and detail endpoints must not return it. The
database is mocked (CI has none).
"""

from datetime import datetime, timedelta, timezone

import pytest

from device_status import (
    IDLE_AFTER_SECONDS,
    OFFLINE_AFTER_SECONDS,
    derive_device_status,
)
from routers import devices, statistics

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "age, expected",
    [
        (timedelta(0), "online"),
        (timedelta(minutes=59), "online"),
        (timedelta(seconds=IDLE_AFTER_SECONDS), "online"),
        (timedelta(seconds=IDLE_AFTER_SECONDS + 1), "idle"),
        (timedelta(hours=23), "idle"),
        (timedelta(seconds=OFFLINE_AFTER_SECONDS), "idle"),
        (timedelta(seconds=OFFLINE_AFTER_SECONDS + 1), "offline"),
        (timedelta(days=60), "offline"),
    ],
)
def test_status_follows_last_seen_age(age, expected):
    assert derive_device_status(NOW - age, NOW) == expected


def test_naive_last_seen_is_read_as_utc():
    naive = (NOW - timedelta(days=3)).replace(tzinfo=None)
    assert derive_device_status(naive, NOW) == "offline"


def test_missing_last_seen_keeps_the_dashboard_default():
    assert derive_device_status(None, NOW) == "online"


def test_defaults_to_the_current_time():
    recent = datetime.now(timezone.utc) - timedelta(minutes=5)
    stale = datetime.now(timezone.utc) - timedelta(days=30)
    assert derive_device_status(recent) == "online"
    assert derive_device_status(stale) == "offline"


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.last_sql = ""

    def execute(self, sql, params=None):
        self.last_sql = " ".join(sql.split())
        self.conn.sql.append(self.last_sql)

    def fetchone(self):
        if self.last_sql.startswith("SELECT COUNT(*)"):
            return (len(self.conn.rows),)
        if "FROM devices" in self.last_sql and self.conn.device_row is not None:
            return self.conn.device_row
        return None

    def fetchall(self):
        return self.conn.rows


class FakeConn:
    def __init__(self, rows=None, device_row=None):
        self.rows = rows or []
        self.device_row = device_row
        self.sql = []

    def cursor(self):
        return FakeCursor(self)

    def close(self):
        pass


def _patch(monkeypatch, conn):
    monkeypatch.setattr(devices, "get_db_connection", lambda: conn)
    monkeypatch.setattr(devices, "cache_get", lambda *a, **k: None)
    monkeypatch.setattr(devices, "cache_set", lambda *a, **k: None)
    monkeypatch.setattr(devices, "add_pagination_headers", lambda *a, **k: None)
    monkeypatch.setattr(devices, "fetch_inventory_states", lambda *a, **k: {})


def _list_row(serial, last_seen):
    return (
        1,
        f"uuid-{serial}",
        serial,
        serial,
        last_seen,
        last_seen,
        None,
        None,
        "macOS",
        "macOS",
        "15.0",
        False,
        None,
        "macOS",
        None,
        None,
        None,
    )


def test_device_list_derives_status_instead_of_reading_the_column(monkeypatch):
    now = datetime.now(timezone.utc)
    conn = FakeConn(
        rows=[
            _list_row("FRESH", now - timedelta(minutes=5)),
            _list_row("QUIET", now - timedelta(hours=5)),
            _list_row("GONE", now - timedelta(days=40)),
        ]
    )
    _patch(monkeypatch, conn)

    payload = devices.get_all_devices(
        request=None, response=None, limit=None, offset=0, include_archived=False
    )

    status = {d["serialNumber"]: d["status"] for d in payload["devices"]}
    assert status == {"FRESH": "online", "QUIET": "idle", "GONE": "offline"}
    assert not any("d.status" in sql for sql in conn.sql)


def test_device_info_derives_status(monkeypatch):
    stale = datetime.now(timezone.utc) - timedelta(days=40)
    conn = FakeConn(
        device_row=(
            1,
            "uuid-1",
            "GONE",
            stale,
            stale,
            False,
            None,
            "1.0",
            "macOS",
        )
    )
    _patch(monkeypatch, conn)

    response = devices.get_device_info_fast("GONE")

    assert response["device"]["status"] == "offline"


def test_device_detail_derives_status(monkeypatch):
    stale = datetime.now(timezone.utc) - timedelta(hours=3)
    conn = FakeConn(
        device_row=(
            1,
            "uuid-1",
            "Name",
            "QUIET",
            stale,
            None,
            None,
            "macOS",
            "macOS",
            "15.0",
            "macOS",
            stale,
            False,
            None,
            "1.0",
        )
    )
    _patch(monkeypatch, conn)

    response = devices.get_device_by_serial("QUIET")

    assert response["device"]["status"] == "idle"


def test_dashboard_uses_the_same_helper():
    assert statistics.derive_device_status is derive_device_status
    assert devices.derive_device_status is derive_device_status
