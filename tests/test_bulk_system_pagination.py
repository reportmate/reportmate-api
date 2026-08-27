"""Pagination of the bulk system endpoint.

GET /api/v1/system used to pass its `limit` straight into the SQL and *also*
key its cache on it, then apply `offset` to the rows that came back. A client
paging at any size below the fleet total therefore read one page and got an
empty second page -- which, to that client, is indistinguishable from having
read the whole fleet. Consumers that page (the provisioning digest among them)
silently reported on the first page only.

These tests pin both halves of the fix: the query no longer truncates, and the
endpoint pages over the complete result set on the fresh and cached paths alike.
"""

import datetime

import pytest
from fastapi.testclient import TestClient

from dependencies import invalidate_caches, load_sql

AUTH = {"X-Client-Passphrase": "test-passphrase"}
FLEET = 12


def make_row(index: int):
    """One row in the shape bulk_system.sql returns."""
    serial = f"SERIAL{index:03d}"
    return (
        serial,
        f"uuid-{index}",
        datetime.datetime(2026, 8, 27, 12, 0, 0),
        {"operating_system": {"name": "Windows 11", "displayVersion": "25H2",
                              "installDate": "2026-08-25T20:07:17",
                              "lastInPlaceUpgrade": "2024-07-23T09:12:33",
                              "inPlaceUpgradeCount": 1}},
        datetime.datetime(2026, 8, 27, 11, 0, 0),
        f"Device {index}",
        f"device-{index}",
        "Shared",
        "Lab",
        "A3030",
        f"A{index:05d}",
        "IT",
        "",
    )


class FakeCursor:
    """Stands in for Postgres, and honours a LIMIT the way Postgres would.

    This matters: a stub that returned every row regardless would let the old
    truncating query pass these tests, which is precisely the failure being
    pinned.
    """

    def __init__(self, rows):
        self._rows = rows
        self.params = None

    def execute(self, query, params=None):
        self.params = params or {}
        if "%(limit)s" in query and self.params.get("limit") is not None:
            self._rows = self._rows[:self.params["limit"]]

    def fetchall(self):
        return self._rows

    def close(self):
        pass


class FakeConnection:
    def __init__(self, rows):
        self.cursors = []
        self._rows = rows

    def cursor(self):
        cursor = FakeCursor(self._rows)
        self.cursors.append(cursor)
        return cursor

    def close(self):
        pass


@pytest.fixture
def client(monkeypatch):
    import routers.fleet as fleet_router

    connections = []

    def connect():
        conn = FakeConnection([make_row(i) for i in range(FLEET)])
        connections.append(conn)
        return conn

    monkeypatch.setattr(fleet_router, "get_db_connection", connect)
    invalidate_caches()
    from main import app

    test_client = TestClient(app)
    test_client.connections = connections
    yield test_client
    invalidate_caches()


def serials(response):
    return [device["serialNumber"] for device in response.json()]


def test_sql_does_not_truncate():
    """The row set is bounded by the handler, never by the query."""
    statement = "\n".join(line for line in load_sql("devices/bulk_system").splitlines()
                          if not line.lstrip().startswith("--"))
    assert "LIMIT" not in statement.upper()
    assert "%(limit)s" not in statement


def test_query_is_not_given_a_limit(client):
    r = client.get("/api/v1/system?limit=5", headers=AUTH)
    assert r.status_code == 200
    assert client.connections[0].cursors[0].params == {"include_archived": False}


def test_offset_reaches_past_the_first_page(client):
    """The regression itself: the second page used to come back empty."""
    second = client.get("/api/v1/system?limit=5&offset=5", headers=AUTH)
    assert second.status_code == 200
    assert serials(second) == [f"SERIAL{i:03d}" for i in range(5, 10)]


def test_paging_covers_the_fleet_exactly_once(client):
    seen = []
    for offset in range(0, FLEET + 5, 5):
        page = serials(client.get(f"/api/v1/system?limit=5&offset={offset}",
                                  headers=AUTH))
        seen.extend(page)
        if len(page) < 5:
            break
    assert seen == [f"SERIAL{i:03d}" for i in range(FLEET)]
    assert len(seen) == len(set(seen)) == FLEET


def test_paging_is_consistent_on_the_cached_path(client):
    """Page one primes the cache; every later page is served from it."""
    first = serials(client.get("/api/v1/system?limit=5", headers=AUTH))
    assert first == [f"SERIAL{i:03d}" for i in range(5)]
    assert len(client.connections) == 1

    third = serials(client.get("/api/v1/system?limit=5&offset=10", headers=AUTH))
    assert third == [f"SERIAL{i:03d}" for i in range(10, FLEET)]
    assert len(client.connections) == 1, "cached path must not re-query"


def test_omitting_limit_returns_every_device(client):
    r = client.get("/api/v1/system", headers=AUTH)
    assert len(serials(r)) == FLEET


def test_total_count_lets_a_client_detect_a_short_read(client):
    """The signal a paging client needs to tell a short page from a truncated one."""
    first = client.get("/api/v1/system?limit=5", headers=AUTH)
    assert first.headers["X-Total-Count"] == str(FLEET)
    assert first.headers["X-Limit"] == "5"
    assert first.headers["X-Offset"] == "0"
    assert 'rel="next"' in first.headers["Link"]

    cached = client.get("/api/v1/system?limit=5&offset=5", headers=AUTH)
    assert cached.headers["X-Total-Count"] == str(FLEET)
    assert 'rel="prev"' in cached.headers["Link"]


def test_the_in_place_upgrade_marker_is_projected(client):
    """installDate moves for a wipe and a feature update alike; this says which."""
    device = client.get("/api/v1/system", headers=AUTH).json()[0]
    assert device["lastInPlaceUpgrade"] == "2024-07-23T09:12:33"
    assert device["inPlaceUpgradeCount"] == 1


def test_a_never_upgraded_machine_is_zero_not_missing(client, monkeypatch):
    """0 means the OS has never been upgraded over. None means the client has not
    reported the field yet. Collapsing the two would read an old client as proof of a
    clean install."""
    import routers.fleet as fleet_router

    def row_without_markers(index):
        row = list(make_row(index))
        row[3] = {"operating_system": {"name": "Windows 11", "inPlaceUpgradeCount": 0}}
        return tuple(row)

    monkeypatch.setattr(fleet_router, "get_db_connection",
                        lambda: FakeConnection([row_without_markers(0)]))
    invalidate_caches()
    device = client.get("/api/v1/system", headers=AUTH).json()[0]
    assert device["inPlaceUpgradeCount"] == 0
    assert device["lastInPlaceUpgrade"] is None


def test_a_client_that_has_not_reported_the_field_yet_is_null(client, monkeypatch):
    import routers.fleet as fleet_router

    def legacy_row(index):
        row = list(make_row(index))
        row[3] = {"operating_system": {"name": "Windows 11"}}
        return tuple(row)

    monkeypatch.setattr(fleet_router, "get_db_connection",
                        lambda: FakeConnection([legacy_row(0)]))
    invalidate_caches()
    device = client.get("/api/v1/system", headers=AUTH).json()[0]
    assert device["inPlaceUpgradeCount"] is None
    assert device["lastInPlaceUpgrade"] is None
