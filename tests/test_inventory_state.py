"""Inventory state: the bulk write, the read overlay, and who it leaves out.

The database is mocked (CI has none): a fake connection records the SQL the
router sends and serves canned rows back.
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import dependencies
from routers import inventory_state as mod

ROOT = Path(__file__).resolve().parent.parent


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.rowcount = 0

    def execute(self, sql, params=None):
        self.conn.calls.append((" ".join(sql.split()), params))
        if self.conn.fail:
            raise RuntimeError("relation does not exist")
        if sql.lstrip().upper().startswith("DELETE"):
            self.rowcount = self.conn.deleted

    def executemany(self, sql, seq):
        self.conn.many.append((" ".join(sql.split()), list(seq)))

    def fetchall(self):
        return self.conn.rows


class FakeConn:
    def __init__(self, rows=None, fail=False, deleted=0):
        self.rows = rows or []
        self.fail = fail
        self.deleted = deleted
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
    monkeypatch.setattr(mod, "invalidate_caches", lambda: None)
    return conn


def test_write_upserts_one_row_per_upper_cased_serial(client, monkeypatch):
    conn = _use(monkeypatch, FakeConn())
    resp = client.put(
        "/api/v1/inventory-state",
        json={
            "devices": [
                {"serialNumber": " abc123 ", "state": "checked_out"},
                {
                    "serialNumber": "ABC123",
                    "state": "storage",
                    "storageLocation": "Room 9",
                    "leaseNumber": "L1",
                },
                {"serialNumber": "xyz", "state": "decommissioning"},
            ]
        },
    )
    assert resp.status_code == 200
    assert resp.json()["written"] == 2
    _sql, rows = conn.many[0]
    by_serial = {r[0]: r for r in rows}
    assert set(by_serial) == {"ABC123", "XYZ"}
    # The later entry for a serial wins.
    assert by_serial["ABC123"][1:4] == ("storage", "Room 9", "L1")
    assert conn.committed


def test_replace_clears_serials_left_out(client, monkeypatch):
    conn = _use(monkeypatch, FakeConn(deleted=3))
    resp = client.put(
        "/api/v1/inventory-state",
        json={
            "replace": True,
            "devices": [{"serialNumber": "A1", "state": "storage"}],
        },
    )
    assert resp.json()["cleared"] == 3
    delete_sql, params = next(c for c in conn.calls if c[0].startswith("DELETE"))
    assert "NOT (serial_number = ANY(%s))" in delete_sql
    assert params == (["A1"],)


def test_replace_with_nothing_is_refused(client, monkeypatch):
    conn = _use(monkeypatch, FakeConn())
    resp = client.put("/api/v1/inventory-state", json={"replace": True, "devices": []})
    assert resp.status_code == 400
    assert not conn.calls and not conn.many


def test_unknown_state_is_rejected(client, monkeypatch):
    _use(monkeypatch, FakeConn())
    resp = client.put(
        "/api/v1/inventory-state",
        json={
            "devices": [
                {"serialNumber": "A1", "state": "shelved"},
            ]
        },
    )
    assert resp.status_code == 422


def test_read_returns_states_and_counts(client, monkeypatch):
    when = datetime(2026, 10, 3, tzinfo=timezone.utc)
    _use(
        monkeypatch,
        FakeConn(
            rows=[
                ("A1", "storage", "Room 9", "L1", "T1", when),
                ("B2", "checked_out", None, None, "T2", when),
            ]
        ),
    )
    body = client.get("/api/v1/inventory-state").json()
    assert body["total"] == 2
    assert body["counts"] == {"checked_out": 1, "storage": 1, "decommissioning": 0}
    assert body["devices"]["A1"]["storageLocation"] == "Room 9"


def test_overlay_survives_a_missing_table():
    conn = FakeConn(fail=True)
    assert mod.fetch_inventory_states(conn) == {}
    assert conn.rolled_back


def test_is_stored():
    assert mod.is_stored({"state": "storage"})
    assert not mod.is_stored({"state": "checked_out"})
    assert not mod.is_stored(None)


def test_dashboard_leaves_stored_devices_out_of_counts():
    source = (ROOT / "routers" / "statistics.py").read_text()
    assert "st.state = 'storage'" in source, "install tiles must skip stored devices"
    assert '"storageDevices": storage_devices' in source
    assert '"totalDevices": len(devices) - storage_devices' in source


def test_device_payloads_carry_the_state():
    source = (ROOT / "routers" / "devices.py").read_text()
    assert 'device_info["inventoryState"] = inventory_state' in source
    assert '"inventoryState": inventory_state,' in source


def test_writes_need_admin_scope():
    assert dependencies._required_scope("PUT", "/api/v1/inventory-state") == "admin"
    assert dependencies._required_scope("GET", "/api/v1/inventory-state") == "read"
