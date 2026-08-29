"""Pagination of the bulk hardware endpoint.

The same defect that was fixed on GET /api/v1/system was still live here: the
handler passed its `limit` straight into the SQL, keyed the cache on that limit,
and only then applied `offset` to the rows that came back. So the query returned
the first N devices and the slice took offset..offset+N *of those* -- meaning
any offset at or above the page size answered an empty list.

That is worse than an error, because to a paging client an empty page is what
the end of a list looks like. Measured against a live deployment: with a
page size of 500, the first page returned 500 records, every offset at or above
500 returned nothing, and a client paging at that size would have reported on
well under two thirds of the estate with no failure of any kind.

These tests pin both halves of the fix -- the query no longer truncates, and
the endpoint pages over the complete set on the fresh and cached paths alike --
plus the X-Total-Count header that lets a client tell a short page from a
truncated one.
"""

import datetime

import pytest
from fastapi.testclient import TestClient

from dependencies import invalidate_caches, load_sql

AUTH = {"X-Client-Passphrase": "test-passphrase"}
FLEET = 12


def make_row(index: int):
    """One row in the shape bulk_hardware.sql returns."""
    serial = f"SERIAL{index:03d}"
    return (
        serial,
        f"uuid-{index}",
        datetime.datetime(2026, 8, 27, 12, 0, 0),
        {
            "manufacturer": "Dell",
            "model": "OptiPlex",
            "processor": {"name": "i7", "cores": 8},
            "memory": {"totalPhysical": 17179869184},
            "storage": [{
                "name": "Drive C:",
                "type": "SSD",
                "capacity": 256060514304,
                "freeSpace": 12000000000,
                "isInternal": True,
                "interface": "NVMe",
            }],
        },
        datetime.datetime(2026, 8, 27, 11, 0, 0),
        {"operating_system": {"name": "Windows 11", "version": "10.0.26200"}},
        f"Device {index}",
        f"device-{index}",
        "Shared",
        "Lab",
        "ROOM-1",
        f"A{index:05d}",
        "IT",
        "",
        "192.0.2.10",
        [],
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
    statement = "\n".join(
        line for line in load_sql("devices/bulk_hardware").splitlines()
        if not line.lstrip().startswith("--")
    )
    assert "LIMIT" not in statement.upper()
    assert "%(limit)s" not in statement


def test_query_is_not_given_a_limit(client):
    r = client.get("/api/v1/hardware?limit=5", headers=AUTH)
    assert r.status_code == 200
    assert client.connections[0].cursors[0].params == {"include_archived": False}


def test_offset_reaches_past_the_first_page(client):
    """The regression itself: the second page used to come back empty."""
    second = client.get("/api/v1/hardware?limit=5&offset=5", headers=AUTH)
    assert second.status_code == 200
    assert serials(second) == [f"SERIAL{i:03d}" for i in range(5, 10)]


def test_paging_covers_the_fleet_exactly_once(client):
    seen = []
    for offset in range(0, FLEET + 5, 5):
        page = serials(client.get(f"/api/v1/hardware?limit=5&offset={offset}",
                                  headers=AUTH))
        seen.extend(page)
        if len(page) < 5:
            break
    assert seen == [f"SERIAL{i:03d}" for i in range(FLEET)]
    assert len(seen) == len(set(seen)) == FLEET


def test_paging_is_consistent_on_the_cached_path(client):
    """Page one primes the cache; every later page is served from it."""
    first = serials(client.get("/api/v1/hardware?limit=5", headers=AUTH))
    assert first == [f"SERIAL{i:03d}" for i in range(5)]
    assert len(client.connections) == 1

    third = serials(client.get("/api/v1/hardware?limit=5&offset=10", headers=AUTH))
    assert third == [f"SERIAL{i:03d}" for i in range(10, FLEET)]
    assert len(client.connections) == 1, "cached path must not re-query"


def test_the_cache_is_not_keyed_on_limit(client):
    """Keying on limit cached a *truncated* set under a key that said nothing
    about the truncation, so a later unlimited caller was served the short set."""
    client.get("/api/v1/hardware?limit=5", headers=AUTH)
    assert len(serials(client.get("/api/v1/hardware", headers=AUTH))) == FLEET
    assert len(client.connections) == 1


def test_omitting_limit_returns_every_device(client):
    r = client.get("/api/v1/hardware", headers=AUTH)
    assert len(serials(r)) == FLEET


def test_total_count_lets_a_client_detect_a_short_read(client):
    """The signal a paging client needs to tell a short page from a truncated one."""
    first = client.get("/api/v1/hardware?limit=5", headers=AUTH)
    assert first.headers["X-Total-Count"] == str(FLEET)
    assert first.headers["X-Limit"] == "5"
    assert first.headers["X-Offset"] == "0"
    assert 'rel="next"' in first.headers["Link"]

    cached = client.get("/api/v1/hardware?limit=5&offset=5", headers=AUTH)
    assert cached.headers["X-Total-Count"] == str(FLEET)
    assert 'rel="prev"' in cached.headers["Link"]


def test_storage_is_projected_for_the_alert_that_reads_it(client):
    """The storage alert needs capacity, freeSpace and the external-drive
    signals; slimming must not drop them."""
    device = client.get("/api/v1/hardware", headers=AUTH).json()[0]
    drive = device["storage"][0]
    assert drive["capacity"] == 256060514304
    assert drive["freeSpace"] == 12000000000
    assert drive["isInternal"] is True
    assert drive["interface"] == "NVMe"
    assert device["usage"] == "Shared"
