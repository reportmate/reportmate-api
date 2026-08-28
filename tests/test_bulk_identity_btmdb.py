"""The btmdbHealth projection on the bulk identity endpoint.

The endpoint used to project only `status` and `sizeMB`. The consumer is a
fleet health alert that has to decide a severity and then say why, and the
three fields it needs to do that -- the client's own `statusMessage`, the
jetsam kill count that distinguishes "large" from "actually being killed", and
the local user count that predicts growth -- were dropped here.

The cost of that was not a missing field. It was that the alert had to re-fetch
every Mac in the estate individually to recover them, which is hundreds of
large per-device payloads on a schedule, to read five small numbers that this
query already had in hand.

Both key casings are accepted because the two clients have not always agreed on
which they emit, and a projection that silently prefers one is how a field
becomes null for half a fleet.
"""

import datetime

import pytest
from fastapi.testclient import TestClient

from dependencies import invalidate_caches

AUTH = {"X-Client-Passphrase": "test-passphrase"}

CAMEL = {
    "status": "warning",
    "sizeMB": 3.4,
    "statusMessage": "Database is larger than the jetsam ceiling",
    "jetsamKillsLast7Days": 2,
    "localUserCount": 118,
}

SNAKE = {
    "health_status": "warning",
    "size_mb": 3.4,
    "status_message": "Database is larger than the jetsam ceiling",
    "jetsam_kills_last_7_days": 2,
    "local_user_count": 118,
}


def make_row(btmdb):
    """One row in the shape bulk_identity.sql returns."""
    return (
        "SERIAL001",
        "uuid-1",
        datetime.datetime(2026, 8, 28, 12, 0, 0),
        "macOS",
        {"users": [], "groups": [], "btmdbHealth": btmdb},
        datetime.datetime(2026, 8, 28, 11, 0, 0),
        "Device 1",
        "device-1",
        "Shared",
        "Lab",
        "ROOM-1",
        "A00001",
        "IT",
        "",
        None,
    )


class FakeCursor:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, query, params=None):
        pass

    def fetchall(self):
        return self._rows

    def close(self):
        pass


class FakeConnection:
    def __init__(self, rows):
        self._rows = rows

    def cursor(self):
        return FakeCursor(self._rows)

    def close(self):
        pass


def client_for(btmdb, monkeypatch):
    import routers.fleet as fleet_router

    monkeypatch.setattr(fleet_router, "get_db_connection",
                        lambda: FakeConnection([make_row(btmdb)]))
    invalidate_caches()
    from main import app
    return TestClient(app)


def health(btmdb, monkeypatch):
    response = client_for(btmdb, monkeypatch).get("/api/v1/identity", headers=AUTH)
    assert response.status_code == 200
    return response.json()[0]["btmdbHealth"]


@pytest.fixture(autouse=True)
def _clean():
    invalidate_caches()
    yield
    invalidate_caches()


def test_the_whole_health_record_is_projected(monkeypatch):
    """All five fields, so a consumer never has to re-fetch the device."""
    assert health(CAMEL, monkeypatch) == {
        "status": "warning",
        "sizeMB": 3.4,
        "statusMessage": "Database is larger than the jetsam ceiling",
        "jetsamKillsLast7Days": 2,
        "localUserCount": 118,
    }


def test_snake_case_from_the_client_is_accepted(monkeypatch):
    """A projection that silently prefers one casing is how a field becomes
    null for half a fleet."""
    assert health(SNAKE, monkeypatch) == {
        "status": "warning",
        "sizeMB": 3.4,
        "statusMessage": "Database is larger than the jetsam ceiling",
        "jetsamKillsLast7Days": 2,
        "localUserCount": 118,
    }


def test_a_device_without_the_module_reports_none(monkeypatch):
    """Absent is not the same as healthy, and must not read as zero."""
    assert health({}, monkeypatch) is None


def test_missing_inner_fields_are_none_rather_than_absent(monkeypatch):
    """A consumer keying on these must find them, so it can tell an old client
    that never reported them from a device that reported a zero."""
    result = health({"status": "ok", "sizeMB": 1.2}, monkeypatch)
    assert result["statusMessage"] is None
    assert result["jetsamKillsLast7Days"] is None
    assert result["localUserCount"] is None
