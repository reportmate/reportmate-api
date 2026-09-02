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
    def __init__(self, rows):
        self._rows = list(rows)
        self.executed = []
        self.itersize = None

    def execute(self, sql, params=None):
        self.executed.append((" ".join(sql.split()), params))

    def fetchmany(self, n):
        out, self._rows = self._rows[:n], self._rows[n:]
        return out

    def close(self):
        pass


class FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor
        self.closed = False

    def cursor(self, name=None):
        self._cursor.name = name
        return self._cursor

    def close(self):
        self.closed = True


ROWS = [
    ("SERIAL1", "2026-09-01", "Google Chrome", "", 3, 59116.4, 10132.7, 10498.5, '["peimen"]', "2026-09-02 06:00:00+00"),
    ("SERIAL1", "2026-09-01", "Safari, with comma", "Apple", 0, 1.0, 0.5, 0.5, "[]", "2026-09-02 06:00:00+00"),
]


def test_streams_header_and_rows_as_csv(client):
    cur = FakeCursor(ROWS)
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
    assert cur.name == "usage_history_export"
    assert cur.executed[0][1] is not None
    assert "date >= %s AND date < %s" in cur.executed[0][0]
    assert conn.closed


def test_rejects_bad_or_inverted_range(client):
    assert client.get("/api/v1/admin/usage-history/export?from=2026-09&to=2026-10-01").status_code == 400
    assert client.get("/api/v1/admin/usage-history/export?from=2026-10-01&to=2026-09-01").status_code == 400
