"""
usage_history integrity probe: the physical-bound checks that were run by hand
before September collection, as one endpoint a timer can call every day.
"""
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import main
from dependencies import verify_authentication


@pytest.fixture
def client():
    main.app.dependency_overrides[verify_authentication] = lambda: None
    try:
        yield TestClient(main.app)
    finally:
        main.app.dependency_overrides.pop(verify_authentication, None)


class FakeCursor:
    def __init__(self, results):
        self._results = list(results)
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((" ".join(sql.split()), params))

    def fetchone(self):
        return self._results.pop(0) if self._results else None

    def fetchall(self):
        return self._results.pop(0) if self._results else []

    def close(self):
        pass


class FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor

    def close(self):
        pass


def _run(client, results):
    cur = FakeCursor(results)
    with patch("routers.admin.get_db_connection", return_value=FakeConn(cur)):
        resp = client.get("/api/v1/admin/usage-history/integrity?days=7")
    return resp, cur


def test_clean_fleet_reports_clean_with_per_platform_shape(client):
    results = [
        [("macOS", 3690, 228, 0, 0, 0, 0), ("Windows", 4100, 306, 0, 0, 0, 0)],  # integrity
        [],                                                                       # over-ceiling device-days
        [("macOS", 228, 2160000.0, 1440000.0, 939), ("Windows", 306, 1742400.0, 784800.0, 173491)],
        (0, 0),                                                                   # anomalies
    ]
    resp, cur = _run(client, results)
    assert resp.status_code == 200
    body = resp.json()
    assert body["clean"] is True
    assert body["platforms"]["macOS"]["deviceDaysOverCeiling"] == 0
    day = body["platforms"]["macOS"]["lastCompleteDay"]
    assert day["devices"] == 228
    assert day["foregroundHoursPerDevice"] == 2.63
    assert day["activeHoursPerDevice"] == 1.75
    assert body["dateAnomalies"] == {"tooOld": 0, "inFuture": 0}
    assert len(cur.executed) == 4
    assert "foreground_seconds > uh.total_seconds" in cur.executed[0][0]


def test_ceiling_breach_and_anomalies_make_it_unclean(client):
    results = [
        [("macOS", 10, 2, 0, 1, 0, 0)],
        [("macOS", "SERIAL1", "2026-08-01", 150000.0, 3600.0)],
        [("macOS", 2, 7200.0, 3600.0, 4)],
        (9, 0),
    ]
    resp, _ = _run(client, results)
    body = resp.json()
    assert body["clean"] is False
    assert body["platforms"]["macOS"]["foregroundOverTotal"] == 1
    assert body["platforms"]["macOS"]["deviceDaysOverCeiling"] == 1
    assert body["deviceDaysOverCeiling"][0]["foregroundHours"] == 41.67
    assert body["dateAnomalies"]["tooOld"] == 9


def test_platform_seen_only_in_breaches_still_appears(client):
    results = [
        [],
        [("Windows", "WIN1", "2026-08-02", 90000.0, 0.0)],
        [],
        (0, 0),
    ]
    resp, _ = _run(client, results)
    body = resp.json()
    assert body["platforms"]["Windows"]["deviceDaysOverCeiling"] == 1
    assert body["clean"] is False
