"""Ingest-failure recording: rejected check-ins become queryable rows.

Auth and validation rejections on the ingest path must persist the identity
the device presented (serial/UUID/hostname travel in the same request as the
credentials), while scanner probes of non-ingest endpoints stay out of the
table. Recording is best-effort and must never change the rejection response.
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import dependencies
from dependencies import extract_ingest_identity, record_ingest_failure
from main import app

PAYLOAD = {
    "metadata": {
        "deviceId": "11111111-2222-3333-4444-555555555555",
        "serialNumber": "0F33V9G25083XX",
        "platform": "Windows",
        "clientVersion": "2026.07.21",
        "additional": {"deviceName": "LILYANNA-PC"},
    }
}

AUTH = {"X-Client-Passphrase": "test-passphrase"}


class RecordingCursor:
    def __init__(self, results=None):
        self.queries = []  # list of (sql, params)
        self._results = list(results or [])

    def execute(self, query, params=None):
        self.queries.append((query, params))

    def _next(self):
        return self._results.pop(0) if self._results else None

    def fetchone(self):
        nxt = self._next()
        return nxt

    def fetchall(self):
        nxt = self._next()
        return nxt if nxt is not None else []


class RecordingConnection:
    def __init__(self, results=None):
        self.cur = RecordingCursor(results)
        self.committed = False
        self.closed = False

    def cursor(self):
        return self.cur

    def commit(self):
        self.committed = True

    def rollback(self):
        pass

    def close(self):
        self.closed = True


def _inserts(conn):
    return [q for q in conn.cur.queries if "INSERT INTO ingest_failures" in q[0]]


# ---------------------------------------------------------------------------
# extract_ingest_identity
# ---------------------------------------------------------------------------

def test_identity_from_dict():
    ident = extract_ingest_identity(PAYLOAD)
    assert ident["serial_number"] == "0F33V9G25083XX"
    assert ident["device_uuid"] == "11111111-2222-3333-4444-555555555555"
    assert ident["device_name"] == "LILYANNA-PC"
    assert ident["platform"] == "Windows"
    assert ident["client_version"] == "2026.07.21"


def test_identity_from_bytes():
    import json

    ident = extract_ingest_identity(json.dumps(PAYLOAD).encode())
    assert ident["serial_number"] == "0F33V9G25083XX"


def test_identity_from_garbage_never_raises():
    assert extract_ingest_identity(b"not json{{{")["serial_number"] is None
    assert extract_ingest_identity(None)["serial_number"] is None
    assert extract_ingest_identity([1, 2])["serial_number"] is None
    assert extract_ingest_identity({"metadata": "nope"})["serial_number"] is None


def test_identity_values_truncated():
    ident = extract_ingest_identity(
        {"metadata": {"serialNumber": "S" * 999, "deviceId": "u"}}
    )
    assert len(ident["serial_number"]) == 255


# ---------------------------------------------------------------------------
# record_ingest_failure is best-effort
# ---------------------------------------------------------------------------

def test_recording_never_raises_when_db_down(monkeypatch):
    def boom():
        raise RuntimeError("db down")

    monkeypatch.setattr(dependencies, "get_db_connection", boom)
    # Must not raise
    record_ingest_failure(failure_type="auth", reason="invalid_passphrase")


# ---------------------------------------------------------------------------
# Auth rejections
# ---------------------------------------------------------------------------

def test_wrong_passphrase_on_ingest_records_identity(monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    conn = RecordingConnection(results=[(1,)])  # RETURNING id -> inserted
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.post(
        "/api/v1/events", json=PAYLOAD, headers={"X-Client-Passphrase": "wrong"}
    )
    assert resp.status_code == 401

    inserts = _inserts(conn)
    assert len(inserts) == 1
    params = inserts[0][1]
    assert "invalid_passphrase" in params
    assert "0F33V9G25083XX" in params
    assert "LILYANNA-PC" in params
    assert conn.committed


def test_missing_credentials_on_ingest_records(monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.post("/api/v1/events", json=PAYLOAD)
    assert resp.status_code == 401

    inserts = _inserts(conn)
    assert len(inserts) == 1
    assert "missing_credentials" in inserts[0][1]


def test_scanner_probe_of_get_endpoint_not_recorded(monkeypatch):
    """Unauthenticated GETs are scanner noise, not devices — keep them out."""
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    conn = RecordingConnection()
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.get("/api/v1/devices")
    assert resp.status_code == 401
    assert _inserts(conn) == []


def test_wrong_passphrase_on_get_recorded(monkeypatch):
    """A wrong passphrase is a misconfigured device wherever it appears."""
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.get("/api/v1/devices", headers={"X-Client-Passphrase": "wrong"})
    assert resp.status_code == 401

    inserts = _inserts(conn)
    assert len(inserts) == 1
    assert "invalid_passphrase" in inserts[0][1]


# ---------------------------------------------------------------------------
# Validation rejections
# ---------------------------------------------------------------------------

def test_sentinel_serial_records_validation_failure(monkeypatch):
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    payload = {
        "metadata": {**PAYLOAD["metadata"], "serialNumber": "To Be Filled By O.E.M."}
    }
    client = TestClient(app)
    resp = client.post("/api/v1/events", json=payload, headers=AUTH)
    assert resp.status_code == 400

    inserts = _inserts(conn)
    assert len(inserts) == 1
    params = inserts[0][1]
    assert "sentinel_serial" in params
    assert "To Be Filled By O.E.M." in params


def test_malformed_json_records(monkeypatch):
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.post(
        "/api/v1/events",
        content=b"this is not json",
        headers={**AUTH, "Content-Type": "application/json"},
    )
    assert resp.status_code == 400

    inserts = _inserts(conn)
    assert len(inserts) == 1
    assert "malformed_json" in inserts[0][1]


def test_invalid_payload_records_422(monkeypatch):
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.post("/api/v1/events", json={"nope": True}, headers=AUTH)
    assert resp.status_code == 422

    inserts = _inserts(conn)
    assert len(inserts) == 1
    assert "invalid_payload" in inserts[0][1]


# ---------------------------------------------------------------------------
# GET /api/v1/events/failures
# ---------------------------------------------------------------------------

def test_failures_endpoint_lists_rows(monkeypatch):
    import routers.events as events_router

    dependencies.invalidate_caches()
    now = datetime.now(timezone.utc)
    row = (
        7, now, "auth", "invalid_passphrase", "Client passphrase did not match",
        401, "/api/v1/events", "10.1.2.3", "ReportMate/2026.07.21",
        "0F33V9G25083XX", "1111", "LILYANNA-PC", "Windows", "2026.07.21",
    )
    conn = RecordingConnection(
        results=[
            (3,),                                  # count fetchone
            [("invalid_passphrase", 3, 1, now)],   # summary fetchall
            [row],                                 # list fetchall
        ]
    )
    monkeypatch.setattr(events_router, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.get(
        "/api/v1/events/failures?hours=167",
        headers={"X-Internal-Secret": "test-internal-secret"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 3
    assert body["summary"][0]["reason"] == "invalid_passphrase"
    assert body["summary"][0]["devices"] == 1
    f = body["failures"][0]
    assert f["serialNumber"] == "0F33V9G25083XX"
    assert f["deviceName"] == "LILYANNA-PC"
    assert f["reason"] == "invalid_passphrase"
    assert f["statusCode"] == 401
    assert f["ts"] == now.isoformat()


def test_failures_endpoint_requires_auth(monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    conn = RecordingConnection()
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)
    client = TestClient(app)
    assert client.get("/api/v1/events/failures").status_code == 401
