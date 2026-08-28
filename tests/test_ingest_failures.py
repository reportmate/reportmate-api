"""Ingest-failure recording: rejected check-ins become queryable rows.

Auth and validation rejections on the ingest path must persist the identity
the device presented (serial/UUID/hostname travel in the same request as the
credentials), while scanner probes of non-ingest endpoints stay out of the
table. Recording is best-effort and must never change the rejection response.
"""

import gzip
import json
import zlib
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
        False,
    )
    conn = RecordingConnection(
        results=[
            (3,),                                  # count fetchone
            (3, 0, 0),                             # outcome counts fetchone
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
    assert f["outcome"] == "rejected"


# ---------------------------------------------------------------------------
# outcome: repaired check-ins are not failures
#
# nul_in_payload and usage_out_of_bounds are recorded at 200 -- the data was
# kept, the client defect is the news. At fleet scale that is thousands of
# rows a day, which buries the handful of devices that genuinely could not get
# in on a page that exists to surface exactly those. The split is derived from
# the recorded status so it reads correctly over rows written before it.
# ---------------------------------------------------------------------------

def _failures_conn(now, rows, count=None, counts=(0, 0, 0), summary=None):
    return RecordingConnection(
        results=[
            (len(rows) if count is None else count,),
            counts,
            summary if summary is not None else [],
            rows,
        ]
    )


def _row(reason, status, serial="TESTSERIAL0001", ts=None, retried=False):
    return (
        7, ts, "validation", reason, "detail", status,
        "/api/v1/events", "10.1.2.3", "ReportMate/2026.08.16",
        serial, "1111", "EXAMPLE-PC", "Windows", "2026.08.16",
        retried,
    )


def _outcome_params(conn):
    """Params of every query that actually carries the outcome predicate."""
    params = [q[1] for q in conn.cur.queries if "%(outcome)s" in q[0]]
    assert params, "no query carried the outcome predicate"
    return params


def test_failures_default_to_rejected_only(monkeypatch):
    import routers.events as events_router

    dependencies.invalidate_caches()
    now = datetime.now(timezone.utc)
    conn = _failures_conn(now, [_row("malformed_json", 400, ts=now)], counts=(9, 0, 300))
    monkeypatch.setattr(events_router, "get_db_connection", lambda: conn)

    resp = TestClient(app).get(
        "/api/v1/events/failures?hours=24",
        headers={"X-Internal-Secret": "test-internal-secret"},
    )
    body = resp.json()
    assert body["outcome"] == "rejected"
    # The caller asked for nothing, so the page must not be dominated by rows
    # whose check-in succeeded.
    assert all(p["outcome"] == "rejected" for p in _outcome_params(conn))


def test_accepted_outcome_is_reachable(monkeypatch):
    import routers.events as events_router

    dependencies.invalidate_caches()
    now = datetime.now(timezone.utc)
    conn = _failures_conn(now, [_row("nul_in_payload", 200, ts=now)], counts=(9, 0, 300))
    monkeypatch.setattr(events_router, "get_db_connection", lambda: conn)

    resp = TestClient(app).get(
        "/api/v1/events/failures?hours=24&outcome=accepted",
        headers={"X-Internal-Secret": "test-internal-secret"},
    )
    body = resp.json()
    assert body["outcome"] == "accepted"
    assert body["failures"][0]["outcome"] == "accepted"
    assert all(p["outcome"] == "accepted" for p in _outcome_params(conn))


def test_outcome_all_drops_the_filter(monkeypatch):
    import routers.events as events_router

    dependencies.invalidate_caches()
    now = datetime.now(timezone.utc)
    conn = _failures_conn(now, [_row("malformed_json", 400, ts=now)], counts=(9, 0, 300))
    monkeypatch.setattr(events_router, "get_db_connection", lambda: conn)

    TestClient(app).get(
        "/api/v1/events/failures?hours=24&outcome=all",
        headers={"X-Internal-Secret": "test-internal-secret"},
    )
    assert all(p["outcome"] is None for p in _outcome_params(conn))


def test_both_counts_are_always_present(monkeypatch):
    """The other side has to be one click away, not invisible."""
    import routers.events as events_router

    dependencies.invalidate_caches()
    now = datetime.now(timezone.utc)
    conn = _failures_conn(now, [_row("malformed_json", 400, ts=now)], counts=(9, 0, 2947))
    monkeypatch.setattr(events_router, "get_db_connection", lambda: conn)

    body = TestClient(app).get(
        "/api/v1/events/failures?hours=24",
        headers={"X-Internal-Secret": "test-internal-secret"},
    ).json()
    assert body["counts"] == {"rejected": 9, "retried": 0, "accepted": 2947}


def test_outcome_rejects_unknown_values(monkeypatch):
    import routers.events as events_router

    dependencies.invalidate_caches()
    monkeypatch.setattr(events_router, "get_db_connection", lambda: RecordingConnection())
    resp = TestClient(app).get(
        "/api/v1/events/failures?outcome=whatever",
        headers={"X-Internal-Secret": "test-internal-secret"},
    )
    assert resp.status_code == 422


def test_rows_are_classified_by_recorded_status(monkeypatch):
    """Derived, not stored -- so rows written before the split read correctly."""
    import routers.events as events_router

    dependencies.invalidate_caches()
    now = datetime.now(timezone.utc)
    rows = [_row("nul_in_payload", 200, ts=now), _row("rate_limited", 429, ts=now),
            _row("upload_aborted", None, ts=now)]
    conn = _failures_conn(now, rows, counts=(2, 0, 1))
    monkeypatch.setattr(events_router, "get_db_connection", lambda: conn)

    body = TestClient(app).get(
        "/api/v1/events/failures?hours=24&outcome=all",
        headers={"X-Internal-Secret": "test-internal-secret"},
    ).json()
    assert [f["outcome"] for f in body["failures"]] == ["accepted", "rejected", "rejected"]


def test_outcome_is_part_of_the_cache_key(monkeypatch):
    """Otherwise the first caller's view is served to the other tab."""
    import routers.events as events_router

    dependencies.invalidate_caches()
    now = datetime.now(timezone.utc)
    rejected = _failures_conn(now, [_row("malformed_json", 400, ts=now)], counts=(1, 0, 5))
    monkeypatch.setattr(events_router, "get_db_connection", lambda: rejected)
    first = TestClient(app).get(
        "/api/v1/events/failures?hours=24",
        headers={"X-Internal-Secret": "test-internal-secret"},
    ).json()

    accepted = _failures_conn(now, [_row("nul_in_payload", 200, ts=now)], counts=(1, 0, 5))
    monkeypatch.setattr(events_router, "get_db_connection", lambda: accepted)
    second = TestClient(app).get(
        "/api/v1/events/failures?hours=24&outcome=accepted",
        headers={"X-Internal-Secret": "test-internal-secret"},
    ).json()

    assert first["failures"][0]["reason"] == "malformed_json"
    assert second["failures"][0]["reason"] == "nul_in_payload"


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


# ---------------------------------------------------------------------------
# Retried transport failures
#
# The clients retry three times with backoff, so a dropped upload is normally
# resent down a fresh connection seconds later and the data lands. Counting
# the dropped attempt as a device that was turned away describes an outage
# that is not happening: 71 "rejected" check-ins in one 24h window were 71
# uploads that all completed on retry, on machines whose data was current to
# the minute. Only transport reasons qualify -- a malformed body or a bad
# passphrase is resent identically, so a later success says nothing about it.
# ---------------------------------------------------------------------------


def test_retried_rows_are_not_reported_as_rejected(monkeypatch):
    import routers.events as events_router

    dependencies.invalidate_caches()
    now = datetime.now(timezone.utc)
    rows = [_row("upload_aborted", 400, ts=now, retried=True),
            _row("upload_aborted", 400, ts=now, retried=False),
            _row("invalid_passphrase", 401, ts=now, retried=False)]
    conn = _failures_conn(now, rows, counts=(2, 1, 0))
    monkeypatch.setattr(events_router, "get_db_connection", lambda: conn)

    body = TestClient(app).get(
        "/api/v1/events/failures?hours=24&outcome=all",
        headers={"X-Internal-Secret": "test-internal-secret"},
    ).json()
    assert [f["outcome"] for f in body["failures"]] == [
        "retried", "rejected", "rejected"
    ]


def test_retried_outcome_is_reachable(monkeypatch):
    import routers.events as events_router

    dependencies.invalidate_caches()
    now = datetime.now(timezone.utc)
    conn = _failures_conn(
        now, [_row("upload_aborted", 400, ts=now, retried=True)], counts=(0, 1, 0)
    )
    monkeypatch.setattr(events_router, "get_db_connection", lambda: conn)

    body = TestClient(app).get(
        "/api/v1/events/failures?hours=24&outcome=retried",
        headers={"X-Internal-Secret": "test-internal-secret"},
    ).json()
    assert body["outcome"] == "retried"
    assert body["failures"][0]["outcome"] == "retried"
    assert all(p["outcome"] == "retried" for p in _outcome_params(conn))


def test_all_three_counts_are_always_present(monkeypatch):
    """A number the caller did not ask for is how they learn the other side
    exists; hiding retried would just move the misleading total."""
    import routers.events as events_router

    dependencies.invalidate_caches()
    now = datetime.now(timezone.utc)
    conn = _failures_conn(now, [_row("upload_aborted", 400, ts=now)], counts=(4, 71, 2947))
    monkeypatch.setattr(events_router, "get_db_connection", lambda: conn)

    body = TestClient(app).get(
        "/api/v1/events/failures?hours=24",
        headers={"X-Internal-Secret": "test-internal-secret"},
    ).json()
    assert body["counts"] == {"rejected": 4, "retried": 71, "accepted": 2947}


def test_only_transport_reasons_can_be_retried():
    """The predicate lives in SQL that no unit test can execute, and widening
    it would silently retire real rejections -- a bad passphrase followed by a
    successful check-in from the same machine is still a bad passphrase."""
    from dependencies import load_sql

    sql = load_sql("events/list_ingest_failures")
    retried = sql.split("AS retried")[0].rsplit("AS accepted", 1)[1]
    assert "upload_aborted" in retried
    assert "body_unreadable" in retried
    assert "empty_body" in retried
    assert "d.last_seen > f.occurred_at" in retried
    for still_a_failure in (
        "malformed_json", "invalid_passphrase", "invalid_api_key",
        "rate_limited", "invalid_payload", "internal_error",
    ):
        assert still_a_failure not in retried


# ---------------------------------------------------------------------------
# Compressed request bodies
#
# A full collection serializes to a megabyte or more of repetitive module
# JSON and the fleet posts tens of thousands a day, so accepting a compressed
# body is worth about eightfold on the wire -- and a body that spends less
# time in flight has a correspondingly smaller window in which the upload can
# be interrupted, which is the failure this endpoint records most often.
# Uncompressed clients must keep working throughout: the fleet updates over
# weeks, so both shapes are live at once for the whole rollout.
# ---------------------------------------------------------------------------

def _gzipped(raw: bytes) -> bytes:
    return gzip.compress(raw)


def test_gzipped_body_reaches_the_parser(monkeypatch):
    """Proved by the rejection changing: an undecoded gzip stream cannot parse
    as JSON, so reaching payload validation means the inflate ran first."""
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    resp = TestClient(app).post(
        "/api/v1/events",
        content=_gzipped(b'{"not": "an event submission"}'),
        headers={**AUTH, "Content-Type": "application/json",
                 "Content-Encoding": "gzip"},
    )
    assert resp.status_code == 422
    params = _inserts(conn)[0][1]
    assert "invalid_payload" in params
    assert "malformed_json" not in params
    assert "body_unreadable" not in params


def test_uncompressed_body_still_works(monkeypatch):
    """Both shapes are live for the whole rollout."""
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    resp = TestClient(app).post(
        "/api/v1/events",
        json={"not": "an event submission"},
        headers={**AUTH},
    )
    assert resp.status_code == 422
    assert "invalid_payload" in _inserts(conn)[0][1]


def test_compressed_detail_separates_wire_bytes_from_decoded_bytes(monkeypatch):
    """declared/received stay wire counts; substituting the decoded size would
    read as a body arriving eight times larger than it was declared."""
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    raw = b"{not json" * 200
    body = _gzipped(raw)
    resp = TestClient(app).post(
        "/api/v1/events",
        content=body,
        headers={**AUTH, "Content-Type": "application/json",
                 "Content-Encoding": "gzip"},
    )
    assert resp.status_code == 400
    detail = next(p for p in _inserts(conn)[0][1]
                  if isinstance(p, str) and "declared=" in p)
    assert f"declared={len(body)}" in detail
    assert f"received={len(body)}" in detail
    assert f"decompressed={len(raw)}" in detail
    assert "encoding=gzip" in detail


def test_zip_bomb_is_refused_during_the_inflate(monkeypatch):
    """A few hundred KB of zeroes inflates to gigabytes. Refusing after the
    fact would mean the container is already gone."""
    import routers.events as events_router

    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)
    monkeypatch.setattr(events_router, "MAX_DECOMPRESSED_BODY_BYTES", 1024)

    resp = TestClient(app).post(
        "/api/v1/events",
        content=_gzipped(b"\0" * 200_000),
        headers={**AUTH, "Content-Type": "application/json",
                 "Content-Encoding": "gzip"},
    )
    assert resp.status_code == 400
    params = _inserts(conn)[0][1]
    assert "body_unreadable" in params
    assert any(isinstance(p, str) and "ceiling" in p for p in params)


def test_truncated_gzip_stream_is_refused(monkeypatch):
    """A stream with no trailer is a dropped upload wearing a decode error's
    clothes -- the same story as a short uncompressed body."""
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    whole = _gzipped(json.dumps(PAYLOAD).encode())
    resp = TestClient(app).post(
        "/api/v1/events",
        content=whole[: len(whole) // 2],
        headers={**AUTH, "Content-Type": "application/json",
                 "Content-Encoding": "gzip"},
    )
    assert resp.status_code == 400
    assert "body_unreadable" in _inserts(conn)[0][1]


def test_unknown_content_encoding_is_refused(monkeypatch):
    """Guessing at an encoding we cannot decode would file the result under
    malformed_json and send whoever reads it after a serializer bug."""
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    resp = TestClient(app).post(
        "/api/v1/events",
        content=b'{"metadata": {}}',
        headers={**AUTH, "Content-Type": "application/json",
                 "Content-Encoding": "br"},
    )
    assert resp.status_code == 400
    params = _inserts(conn)[0][1]
    assert "body_unreadable" in params
    assert any(isinstance(p, str) and "unsupported Content-Encoding" in p
               for p in params)


def test_deflate_is_accepted_too(monkeypatch):
    conn = RecordingConnection(results=[(1,)])
    monkeypatch.setattr(dependencies, "get_db_connection", lambda: conn)

    resp = TestClient(app).post(
        "/api/v1/events",
        content=zlib.compress(b'{"not": "an event submission"}'),
        headers={**AUTH, "Content-Type": "application/json",
                 "Content-Encoding": "deflate"},
    )
    assert resp.status_code == 422
    assert "invalid_payload" in _inserts(conn)[0][1]
