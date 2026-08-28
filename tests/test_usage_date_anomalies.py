"""
usage_history date anomaly probe.

Rows dated outside the plausible range are invisible to every normal query --
the fleet and per-device usage endpoints both clamp their lookback to 548 days
-- while still being counted by aggregates that scan the whole table. This
probe is the only way to see them.
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
        self.closed = False

    def cursor(self):
        return self._cursor

    def close(self):
        self.closed = True


OLD_COUNTS = (9, 1, 3, "1976-04-03", "1976-04-03",
              "2026-08-14 02:11:00+00", "2026-08-14 02:11:00+00")
OLD_SAMPLE = [("SERIAL1", "1976-04-03", "Some App", 2, 120.0, 0.0, "2026-08-14 02:11:00+00")]
FUTURE_COUNTS = (0, 0, 0, None, None, None, None)
FUTURE_SAMPLE = []


def _results():
    return [OLD_COUNTS, OLD_SAMPLE, FUTURE_COUNTS, FUTURE_SAMPLE]


class TestProbe:
    def test_reports_both_buckets(self, client):
        cursor = FakeCursor(_results())
        with patch("routers.admin.get_db_connection", return_value=FakeConn(cursor)):
            body = client.get("/api/v1/admin/usage-history/date-anomalies").json()

        assert body["tooOld"]["rows"] == 9
        assert body["tooOld"]["earliestDate"] == "1976-04-03"
        assert body["inFuture"]["rows"] == 0

    def test_surfaces_when_the_rows_were_written(self, client):
        # The decisive field: it separates a historical mess a baseline reset
        # will clear from a fault still occurring that would repopulate it.
        cursor = FakeCursor(_results())
        with patch("routers.admin.get_db_connection", return_value=FakeConn(cursor)):
            body = client.get("/api/v1/admin/usage-history/date-anomalies").json()

        assert body["tooOld"]["lastWritten"].startswith("2026-08-14")
        assert body["tooOld"]["sample"][0]["updatedAt"].startswith("2026-08-14")
        assert body["tooOld"]["sample"][0]["deviceId"] == "SERIAL1"

    def test_default_floor_matches_the_api_lookback_ceiling(self, client):
        # 548 days is the max lookback the usage endpoints accept, so anything
        # older is by definition unreachable through them.
        cursor = FakeCursor(_results())
        with patch("routers.admin.get_db_connection", return_value=FakeConn(cursor)):
            body = client.get("/api/v1/admin/usage-history/date-anomalies").json()

        from datetime import datetime, timedelta, timezone
        expected = (datetime.now(timezone.utc) - timedelta(days=548)).date()
        assert body["floorDate"] == str(expected)

    def test_an_explicit_floor_is_used(self, client):
        cursor = FakeCursor(_results())
        with patch("routers.admin.get_db_connection", return_value=FakeConn(cursor)):
            body = client.get(
                "/api/v1/admin/usage-history/date-anomalies?floor=2026-01-01"
            ).json()

        assert body["floorDate"] == "2026-01-01"
        assert cursor.executed[0][1] == (__import__("datetime").date(2026, 1, 1),)

    def test_it_only_reads(self, client):
        cursor = FakeCursor(_results())
        with patch("routers.admin.get_db_connection", return_value=FakeConn(cursor)):
            client.get("/api/v1/admin/usage-history/date-anomalies")

        for sql, _ in cursor.executed:
            assert sql.upper().startswith("SELECT")

    @pytest.mark.parametrize("bad", ["1976", "not-a-date", "2026-13-40"])
    def test_a_malformed_floor_is_rejected(self, client, bad):
        cursor = FakeCursor(_results())
        with patch("routers.admin.get_db_connection", return_value=FakeConn(cursor)):
            r = client.get(f"/api/v1/admin/usage-history/date-anomalies?floor={bad}")
        assert r.status_code == 400
