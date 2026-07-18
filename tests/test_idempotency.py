"""Idempotency-Key replay tests for POST /events."""

from fastapi.testclient import TestClient

from main import app

PAYLOAD = {
    "metadata": {
        "deviceId": "11111111-2222-3333-4444-555555555555",
        "serialNumber": "0F33V9G25083XX",
        "platform": "Windows",
        "collectionType": "Full",
    }
}

AUTH = {"X-Client-Passphrase": "test-passphrase"}


class ReplayCursor:
    """Cursor whose first execute is the idempotency insert losing the race."""

    def __init__(self):
        self.queries = []

    def execute(self, query, params=None):
        self.queries.append(query)

    def fetchone(self):
        return None


class ReplayConnection:
    def __init__(self):
        self.cur = ReplayCursor()
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return self.cur

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def test_replayed_key_is_acknowledged_without_reprocessing(monkeypatch):
    import routers.events as events_router

    conn = ReplayConnection()
    monkeypatch.setattr(events_router, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.post(
        "/api/v1/events",
        json=PAYLOAD,
        headers={**AUTH, "Idempotency-Key": "retry-abc-123"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "duplicate"
    assert body["idempotent"] is True
    assert body["serialNumber"] == "0F33V9G25083XX"

    assert len(conn.cur.queries) == 1
    assert "idempotency_keys" in conn.cur.queries[0]
    assert conn.rolled_back and conn.closed
