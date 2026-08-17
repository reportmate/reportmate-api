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
        "serialNumber": "TESTSERIAL0001",
        "platform": "Windows",
        "clientVersion": "2026.07.21",
        "additional": {"deviceName": "EXAMPLE-PC"},
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
    assert ident["serial_number"] == "TESTSERIAL0001"
    assert ident["device_uuid"] == "11111111-2222-3333-4444-555555555555"
    assert ident["device_name"] == "EXAMPLE-PC"
    assert ident["platform"] == "Windows"
    assert ident["client_version"] == "2026.07.21"


def test_identity_from_bytes():
    import json

    ident = extract_ingest_identity(json.dumps(PAYLOAD).encode())
    assert ident["serial_number"] == "TESTSERIAL0001"


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
    assert "TESTSERIAL0001" in params
    assert "EXAMPLE-PC" in params
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
        "TESTSERIAL0001", "1111", "EXAMPLE-PC", "Windows", "2026.07.21",
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
    assert f["serialNumber"] == "TESTSERIAL0001"
    assert f["deviceName"] == "EXAMPLE-PC"
    assert f["reason"] == "invalid_passphrase"
    assert f["statusCode"] == 401
    assert f["ts"] == now.isoformat()


def test_failures_endpoint_requires_auth(monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    conn = RecordingConnection()
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)
    client = TestClient(app)
    assert client.get("/api/v1/events/failures").status_code == 401


# ---------------------------------------------------------------------------
# Attribution: identity headers, originating IP, transport-vs-parse reasons
#
# The failures view shipped unable to name a single device: identity lived
# only in the body (so an unreadable body meant "unidentified"), the recorded
# address was the Container Apps ingress rather than the device, and every
# transport failure was labelled malformed_json. These cover all three.
# ---------------------------------------------------------------------------

IDENTITY_HEADERS = {
    "X-Device-Serial": "TESTSERIAL0001",
    "X-Device-Uuid": "11111111-2222-3333-4444-555555555555",
    "X-Device-Name": "EXAMPLE-PC",
    "X-Platform": "Windows",
    "X-Client-Version": "2026.07.21",
}


def test_identity_headers_attribute_an_unreadable_body(monkeypatch):
    """The whole point: a body that never parsed still names its device."""
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.post(
        "/api/v1/events",
        content=b"{truncated",
        headers={**AUTH, **IDENTITY_HEADERS, "Content-Type": "application/json"},
    )
    assert resp.status_code == 400

    params = _inserts(conn)[0][1]
    assert "TESTSERIAL0001" in params
    assert "EXAMPLE-PC" in params
    assert "Windows" in params


def test_body_identity_wins_over_headers(monkeypatch):
    """Headers are the fallback, not an override -- a spoofable header must
    not relabel a check-in whose body says otherwise."""
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.post(
        "/api/v1/events",
        json={"metadata": {**PAYLOAD["metadata"], "serialNumber": "-1"}},
        headers={**AUTH, "X-Device-Serial": "HEADERSERIAL"},
    )
    assert resp.status_code == 400

    params = _inserts(conn)[0][1]
    assert "-1" in params
    assert "HEADERSERIAL" not in params


def test_headers_fill_only_the_gaps(monkeypatch):
    """A body carrying a serial but no hostname still gets the hostname."""
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.post(
        "/api/v1/events",
        json={
            "metadata": {
                "deviceId": "11111111-2222-3333-4444-555555555555",
                "serialNumber": "-1",
                "platform": "macOS",
                "clientVersion": "2026.07.21",
            }
        },
        headers={**AUTH, "X-Device-Name": "STUDIO-MAC"},
    )
    assert resp.status_code == 400

    params = _inserts(conn)[0][1]
    assert "STUDIO-MAC" in params
    assert "macOS" in params


def test_originating_ip_recorded_not_ingress(monkeypatch):
    """Behind ingress every device shares a backend address; recording it
    made all 455 rejected check-ins look like four machines."""
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.post(
        "/api/v1/events",
        content=b"nope",
        headers={
            **AUTH,
            "Content-Type": "application/json",
            "X-Forwarded-For": "142.103.9.44, 100.100.1.25",
        },
    )
    assert resp.status_code == 400

    params = _inserts(conn)[0][1]
    assert "142.103.9.44" in params
    assert "100.100.1.25" not in params


def test_empty_body_is_not_called_malformed_json(monkeypatch):
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.post(
        "/api/v1/events",
        content=b"",
        headers={**AUTH, "Content-Type": "application/json"},
    )
    assert resp.status_code == 400

    params = _inserts(conn)[0][1]
    assert "empty_body" in params
    assert "malformed_json" not in params


def test_malformed_json_detail_carries_byte_counts(monkeypatch):
    """declared vs received is what separates a truncated upload from a
    client that genuinely serialized garbage."""
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.post(
        "/api/v1/events",
        content=b"{not json",
        headers={**AUTH, "Content-Type": "application/json"},
    )
    assert resp.status_code == 400

    detail = next(p for p in _inserts(conn)[0][1] if isinstance(p, str) and "declared=" in p)
    assert "declared=9" in detail
    assert "received=9" in detail


def test_client_disconnect_recorded_as_upload_aborted(monkeypatch):
    """An aborted upload is a network problem, not a serializer problem, and
    must not be filed under malformed_json."""
    from starlette.requests import ClientDisconnect

    import routers.events as events_router

    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    async def disconnecting_body(self):
        raise ClientDisconnect()

    monkeypatch.setattr(
        events_router.Request, "body", disconnecting_body, raising=False
    )

    client = TestClient(app)
    resp = client.post(
        "/api/v1/events",
        json=PAYLOAD,
        headers={**AUTH, **IDENTITY_HEADERS},
    )
    assert resp.status_code == 400

    params = _inserts(conn)[0][1]
    assert "upload_aborted" in params
    assert "TESTSERIAL0001" in params


# ---------------------------------------------------------------------------
# NUL sanitizing, throttle and server-error recording
#
# Postgres jsonb cannot hold a NUL code point anywhere in a string, and one
# unstorable character aborted the whole module write while the device still
# got a 200 -- 171 Windows machines carried a frozen identity module for a
# month that way. Throttle and server-error rejections were absent from the
# table entirely, which hid the largest rejection class from the view whose
# whole purpose is showing rejected check-ins.
# ---------------------------------------------------------------------------

NUL = chr(0)


def _tpm_payload(mfg="IFX"):
    return {
        "metadata": PAYLOAD["metadata"],
        "identity": {"tpmOwnership": {"manufacturerIdTxt": mfg + NUL, "owned": True}},
    }


def test_nul_is_stripped_from_strings():
    from routers.events import _strip_nul

    cleaned = _strip_nul({"a": "IFX" + NUL, "b": [{"c": "NTC" + NUL}]})
    assert cleaned == {"a": "IFX", "b": [{"c": "NTC"}]}


def test_nul_is_stripped_from_keys():
    from routers.events import _strip_nul

    assert _strip_nul({"k" + NUL: "v"}) == {"k": "v"}


def test_literal_backslash_u_text_is_not_mangled():
    """A naive replace over serialized JSON would corrupt the escaped-backslash
    form of this string; sanitizing the decoded values cannot."""
    from routers.events import _strip_nul

    assert _strip_nul({"x": "\\u0000"}) == {"x": "\\u0000"}


def test_non_string_scalars_survive():
    from routers.events import _strip_nul

    assert _strip_nul({"a": 1, "b": None, "c": True, "d": 1.5}) == {
        "a": 1, "b": None, "c": True, "d": 1.5,
    }


def test_tpm_nul_payload_is_accepted_and_recorded(monkeypatch):
    """The check-in must succeed -- the NUL is padding, and rejecting it would
    discard every other valid field alongside it."""
    conn = RecordingConnection(results=[(1,)] * 12)
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)
    import routers.events as events_router

    monkeypatch.setattr(events_router, "get_db_connection", lambda: conn)

    client = TestClient(app)
    resp = client.post("/api/v1/events", json=_tpm_payload(), headers=AUTH)
    assert resp.status_code == 200

    inserts = _inserts(conn)
    assert len(inserts) == 1
    params = inserts[0][1]
    assert "nul_in_payload" in params
    assert 200 in params
    assert "TESTSERIAL0001" in params


def test_no_nul_means_no_recording(monkeypatch):
    """The sanitizer must not report on the overwhelming majority of check-ins
    that carry no NUL at all."""
    conn = RecordingConnection(results=[(1,)] * 12)
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)
    import routers.events as events_router

    monkeypatch.setattr(events_router, "get_db_connection", lambda: conn)

    client = TestClient(app)
    clean = {
        "metadata": PAYLOAD["metadata"],
        "identity": {"tpmOwnership": {"manufacturerIdTxt": "INTC", "owned": True}},
    }
    resp = client.post("/api/v1/events", json=clean, headers=AUTH)
    assert resp.status_code == 200
    assert [q for q in _inserts(conn) if "nul_in_payload" in str(q[1])] == []


def test_rate_limited_ingest_is_recorded(monkeypatch):
    """Throttling was the largest rejection class and the only one the
    failures view could not see."""
    from rate_limit import GlobalRateLimitMiddleware

    conn = RecordingConnection(results=[(1,)] * 5)
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    GlobalRateLimitMiddleware.reset()
    for _ in range(120):
        GlobalRateLimitMiddleware._allow("dev:TESTSERIAL0001", 120)

    client = TestClient(app)
    resp = client.post(
        "/api/v1/events",
        json=PAYLOAD,
        headers={**AUTH, "X-Device-Serial": "TESTSERIAL0001"},
    )
    assert resp.status_code == 429

    inserts = _inserts(conn)
    assert len(inserts) == 1
    params = inserts[0][1]
    assert "rate_limited" in params
    assert "throttle" in params
    assert "TESTSERIAL0001" in params
    GlobalRateLimitMiddleware.reset()


def test_rate_limited_dashboard_traffic_is_not_recorded(monkeypatch):
    """Only devices belong in this table; dashboard throttling would bury them."""
    from rate_limit import GlobalRateLimitMiddleware

    conn = RecordingConnection()
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)
    GlobalRateLimitMiddleware.reset()
    for _ in range(120):
        GlobalRateLimitMiddleware._allow("dev:DASHBOARD1", 120)

    client = TestClient(app)
    resp = client.get(
        "/api/v1/health/live", headers={"X-Device-Serial": "DASHBOARD1"}
    )
    assert resp.status_code == 429
    assert _inserts(conn) == []
    GlobalRateLimitMiddleware.reset()
