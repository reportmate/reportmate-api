"""
usage_history export: the read side of the off-database archive.
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
    """Serves rows keyset-style: each execute returns the next slice."""

    def __init__(self, rows, batch):
        self._rows = list(rows)
        self._batch = batch
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((" ".join(sql.split()), params))

    def fetchall(self):
        out, self._rows = self._rows[:self._batch], self._rows[self._batch:]
        return out

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


ROWS = [
    ("SERIAL1", "2026-09-01", "Google Chrome", "", 3, 59116.4, 10132.7, 10498.5, '["peimen"]', "2026-09-02 06:00:00+00"),
    ("SERIAL1", "2026-09-01", "Safari, with comma", "Apple", 0, 1.0, 0.5, 0.5, "[]", "2026-09-02 06:00:00+00"),
]


def test_streams_header_and_rows_as_csv(client):
    cur = FakeCursor(ROWS, batch=5000)
    conn = FakeConn(cur)
    with patch("routers.admin.get_db_connection", return_value=conn):
        resp = client.get("/api/v1/admin/usage-history/export?from=2026-09-01&to=2026-10-01")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert 'usage_history-2026-09-01-2026-10-01.csv' in resp.headers["content-disposition"]
    lines = resp.text.splitlines()
    assert lines[0] == "device_id,date,app_name,publisher,launches,total_seconds,active_seconds,foreground_seconds,users,updated_at"
    assert lines[1].startswith('SERIAL1,2026-09-01,Google Chrome,,3,59116.4,10132.7,10498.5,"[""peimen""]"')
    assert '"Safari, with comma"' in lines[2]
    assert len(cur.executed) == 1  # under one batch: no second query
    assert "(date, device_id, app_name) > (%s, %s, %s)" in cur.executed[0][0]
    assert conn.closed


def test_pages_by_keyset_until_a_short_batch(client, monkeypatch):
    import routers.admin as admin
    monkeypatch.setattr(admin, "EXPORT_BATCH", 2)
    rows = [("S1", "2026-09-01", f"App {i}", "", i, 1.0, 1.0, 1.0, "[]", "t") for i in range(5)]
    cur = FakeCursor(rows, batch=2)
    conn = FakeConn(cur)
    with patch("routers.admin.get_db_connection", return_value=conn):
        resp = client.get("/api/v1/admin/usage-history/export?from=2026-09-01&to=2026-10-01")
    assert resp.status_code == 200
    assert len(resp.text.splitlines()) == 6  # header + 5 rows
    # 2 + 2 + 1: the short third batch ends the loop; no fourth query.
    assert len(cur.executed) == 3
    # Each query resumes after the last row sent.
    assert cur.executed[1][1][2:5] == ("2026-09-01", "S1", "App 1")
    assert cur.executed[2][1][2:5] == ("2026-09-01", "S1", "App 3")
    assert conn.closed


def test_database_error_is_a_500_not_an_empty_200(client):
    class BrokenConn:
        def cursor(self):
            raise RuntimeError("boom")

        def close(self):
            pass

    with patch("routers.admin.get_db_connection", return_value=BrokenConn()):
        resp = client.get("/api/v1/admin/usage-history/export?from=2026-09-01&to=2026-10-01")
    assert resp.status_code == 500


def test_rejects_bad_or_inverted_range(client):
    assert client.get("/api/v1/admin/usage-history/export?from=2026-09&to=2026-10-01").status_code == 400
    assert client.get("/api/v1/admin/usage-history/export?from=2026-10-01&to=2026-09-01").status_code == 400
