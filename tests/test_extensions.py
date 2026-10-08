"""Extensions: the per-device and bulk writes, the read, the delete, and the names refused.

The router tests mock the database: a fake connection records the SQL it is
sent and serves canned rows. The upsert statement itself also runs against a
real Postgres when TEST_DATABASE_URL is set, because a mocked cursor cannot
catch a statement the server would reject.
"""

import json
import os
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import dependencies
from routers import extensions as mod


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.rowcount = 0
        self._result = []

    def execute(self, sql, params=None):
        flat = " ".join(sql.split())
        self.conn.calls.append((flat, params))
        if self.conn.fail:
            raise RuntimeError("relation does not exist")
        if flat.startswith("SELECT id FROM devices"):
            self._result = [(self.conn.device_id,)] if self.conn.device_id else []
        elif flat.startswith("SELECT id, serial_number FROM devices"):
            self._result = list(self.conn.devices)
        elif flat.startswith("SELECT e.data"):
            self._result = list(self.conn.rows)
        elif flat.startswith("DELETE"):
            self.rowcount = self.conn.deleted

    def executemany(self, sql, seq):
        self.conn.many.append((" ".join(sql.split()), list(seq)))

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return self._result


class FakeConn:
    def __init__(self, device_id="SER1", devices=(), rows=(), deleted=0, fail=False):
        self.device_id = device_id
        self.devices = devices
        self.rows = rows
        self.deleted = deleted
        self.fail = fail
        self.calls = []
        self.many = []
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", True, raising=False)
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")
    return TestClient(app)


def _use(monkeypatch, conn):
    monkeypatch.setattr(mod, "get_db_connection", lambda: conn)
    return conn


def _upserts(conn):
    return [c for c in conn.calls if c[0].startswith("INSERT INTO extension_data")]


# ── names ───────────────────────────────────────────────────────


@pytest.mark.parametrize("name", ["system", "Hardware", "installs"])
def test_core_module_names_are_refused(client, monkeypatch, name):
    conn = _use(monkeypatch, FakeConn())
    resp = client.post(f"/api/v1/device/SER1/extension/{name}", json={"data": {"a": 1}})
    assert resp.status_code == 400
    assert "core module" in resp.json()["detail"]
    assert conn.calls == []


@pytest.mark.parametrize("name", ["-lead", "has space", "x" * 65, "dot.ted"])
def test_malformed_names_are_refused(client, monkeypatch, name):
    _use(monkeypatch, FakeConn())
    resp = client.get(f"/api/v1/device/SER1/extension/{name}")
    assert resp.status_code == 400


def test_names_are_lower_cased():
    assert mod.validate_extension_name(" Intune-Audit ") == "intune-audit"


# ── per device ──────────────────────────────────────────────────


def test_write_upserts_against_the_resolved_device_id(client, monkeypatch):
    conn = _use(monkeypatch, FakeConn(device_id="SER1"))
    resp = client.post(
        "/api/v1/device/ser1/extension/mdm-audit",
        json={
            "data": {"compliant": True},
            "source": "mdm",
            "collectedAt": "2026-10-01T12:00:00Z",
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {"success": True, "serialNumber": "ser1", "extension": "mdm-audit"}
    (_sql, params), = _upserts(conn)
    assert params[0] == "SER1"
    assert params[1] == "mdm-audit"
    assert json.loads(params[2]) == {"compliant": True}
    assert params[3] == "mdm"
    assert params[4] == datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    assert conn.committed


def test_write_for_an_unknown_device_is_404_and_writes_nothing(client, monkeypatch):
    conn = _use(monkeypatch, FakeConn(device_id=None))
    resp = client.post("/api/v1/device/NOPE/extension/mdm-audit", json={"data": {}})
    assert resp.status_code == 404
    assert _upserts(conn) == []


def test_write_without_data_is_refused(client, monkeypatch):
    conn = _use(monkeypatch, FakeConn())
    assert client.post("/api/v1/device/SER1/extension/x", json={"source": "s"}).status_code == 422
    assert client.post("/api/v1/device/SER1/extension/x", json={"data": None}).status_code == 400
    assert _upserts(conn) == []


def test_collected_at_defaults_to_now(client, monkeypatch):
    conn = _use(monkeypatch, FakeConn())
    client.post("/api/v1/device/SER1/extension/x", json={"data": [1, 2]})
    (_sql, params), = _upserts(conn)
    assert params[4] is not None and params[4] == params[5]


def test_write_failure_rolls_back_and_hides_the_error(client, monkeypatch):
    conn = _use(monkeypatch, FakeConn(fail=True))
    resp = client.post("/api/v1/device/SER1/extension/x", json={"data": {}})
    assert resp.status_code == 500
    assert "relation" not in resp.json()["detail"]
    assert conn.rolled_back


def test_read_returns_the_document(client, monkeypatch):
    stamp = datetime(2026, 10, 1, tzinfo=timezone.utc)
    _use(monkeypatch, FakeConn(rows=[('{"score": 7}', "vendor", stamp, stamp)]))
    resp = client.get("/api/v1/device/SER1/extension/risk")
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"] == {"score": 7}
    assert body["source"] == "vendor"
    assert body["collectedAt"] == stamp.isoformat()


def test_read_of_missing_data_is_404(client, monkeypatch):
    _use(monkeypatch, FakeConn(rows=[]))
    assert client.get("/api/v1/device/SER1/extension/risk").status_code == 404


def test_delete_reports_the_rows_removed(client, monkeypatch):
    conn = _use(monkeypatch, FakeConn(deleted=1))
    resp = client.delete("/api/v1/device/SER1/extension/risk")
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 1
    sql, params = next(c for c in conn.calls if c[0].startswith("DELETE"))
    assert "extension_name = %s" in sql
    assert params == ("risk", "SER1", "SER1")
    assert conn.committed


# ── bulk ────────────────────────────────────────────────────────


def test_bulk_writes_known_devices_and_returns_unknown_serials(client, monkeypatch):
    conn = _use(monkeypatch, FakeConn(devices=[("ID-A", "A"), ("B", "B")]))
    resp = client.post(
        "/api/v1/extension/risk/bulk",
        json={
            "source": "vendor",
            "devices": [
                {"serialNumber": "A", "data": {"v": 1}},
                {"serialNumber": "B", "data": {"v": 2}, "source": "override"},
                {"serialNumber": "A", "data": {"v": 3}},
                {"serialNumber": "C", "data": {"v": 4}},
                {"serialNumber": " ", "data": {"v": 5}},
                {"serialNumber": "D", "data": None},
            ],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["written"] == 2
    assert body["unknownSerials"] == ["C"]
    assert body["skippedBad"] == 2
    _sql, rows = conn.many[0]
    by_id = {r[0]: r for r in rows}
    assert set(by_id) == {"ID-A", "B"}
    # The later entry for a serial wins; an entry's own source beats the batch's.
    assert json.loads(by_id["ID-A"][2]) == {"v": 3}
    assert by_id["ID-A"][3] == "vendor"
    assert by_id["B"][3] == "override"
    assert conn.committed


def test_bulk_over_the_cap_is_refused(client, monkeypatch):
    monkeypatch.setattr(mod, "MAX_DEVICES_PER_WRITE", 1)
    conn = _use(monkeypatch, FakeConn())
    resp = client.post(
        "/api/v1/extension/risk/bulk",
        json={"devices": [{"serialNumber": "A", "data": 1}, {"serialNumber": "B", "data": 2}]},
    )
    assert resp.status_code == 413
    assert conn.calls == []


def test_bulk_refuses_core_module_names(client, monkeypatch):
    _use(monkeypatch, FakeConn())
    resp = client.post("/api/v1/extension/security/bulk", json={"devices": []})
    assert resp.status_code == 400


# ── scopes ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "method,path,scope",
    [
        ("GET", "/api/v1/device/S/extension/x", "read"),
        ("POST", "/api/v1/device/S/extension/x", "ingest"),
        ("POST", "/api/v1/extension/x/bulk", "ingest"),
        ("DELETE", "/api/v1/device/S/extension/x", "admin"),
    ],
)
def test_routes_take_the_usual_scope(method, path, scope):
    assert dependencies._required_scope(method, path) == scope


# ── the statement, against a real server ────────────────────────

_TEST_DB = os.getenv("TEST_DATABASE_URL")


@pytest.mark.skipif(not _TEST_DB, reason="TEST_DATABASE_URL not set; skipping live-DB extension upsert")
def test_upsert_sql_inserts_then_replaces(monkeypatch):
    from urllib.parse import urlparse

    import pg8000

    from migrations import run_migrations

    monkeypatch.setenv("DATABASE_URL", _TEST_DB)
    monkeypatch.setenv("DB_SSL", "false")
    run_migrations()

    u = urlparse(_TEST_DB)
    conn = pg8000.connect(
        host=u.hostname,
        port=u.port or 5432,
        database=u.path.lstrip("/"),
        user=u.username,
        password=u.password,
    )
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM extension_data WHERE device_id = 'EXT-TEST'")
        now = datetime.now(timezone.utc)
        first = mod._upsert_params("EXT-TEST", "risk", {"v": 1}, "a", None, now)
        cur.execute(mod.EXTENSION_UPSERT_SQL, first)
        second = mod._upsert_params(
            "EXT-TEST", "risk", {"v": 2}, "b", datetime(2026, 1, 1, tzinfo=timezone.utc), now
        )
        cur.executemany(mod.EXTENSION_UPSERT_SQL, [second])
        cur.execute(
            "SELECT data, source, collected_at FROM extension_data "
            "WHERE device_id = 'EXT-TEST' AND extension_name = 'risk'"
        )
        rows = cur.fetchall()
        assert len(rows) == 1
        data, source, collected_at = rows[0]
        assert (json.loads(data) if isinstance(data, str) else data) == {"v": 2}
        assert source == "b"
        assert collected_at == datetime(2026, 1, 1, tzinfo=timezone.utc)
    finally:
        cur.execute("DELETE FROM extension_data WHERE device_id = 'EXT-TEST'")
        conn.commit()
        conn.close()
