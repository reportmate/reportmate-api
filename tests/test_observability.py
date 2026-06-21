"""Request correlation ids and the liveness/readiness split.

TestClient is used without a context manager so on_event startup (which opens
the database) does not fire; these run with no database available.
"""

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_request_id_is_generated_and_returned():
    resp = client.get("/")
    assert resp.status_code == 200
    rid = resp.headers.get("X-Request-ID")
    assert rid and len(rid) == 12


def test_inbound_request_id_is_propagated():
    resp = client.get("/", headers={"X-Request-ID": "trace-abc-123"})
    assert resp.headers.get("X-Request-ID") == "trace-abc-123"


def test_liveness_does_not_touch_the_database():
    # Must return 200 even with no database (this test has none).
    resp = client.get("/api/v1/health/live")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_readiness_reports_not_ready_without_database():
    resp = client.get("/api/v1/health/ready")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["database"] == "unavailable"
    # No internal error detail leaks out.
    assert "Traceback" not in str(body)
    assert "psycopg" not in str(body).lower()


def test_readiness_endpoint_in_schema():
    paths = app.openapi()["paths"]
    assert "/api/v1/health/live" in paths
    assert "/api/v1/health/ready" in paths
