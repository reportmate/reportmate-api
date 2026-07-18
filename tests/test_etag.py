"""Conditional GET (ETag) tests."""

from fastapi.testclient import TestClient

from main import app


def test_get_carries_weak_etag():
    client = TestClient(app)
    resp = client.get("/api/v1/health/live")
    assert resp.status_code == 200
    assert resp.headers.get("ETag", "").startswith('W/"')


def test_matching_if_none_match_returns_304():
    client = TestClient(app)
    first = client.get("/api/v1/health/live")
    etag = first.headers["ETag"]
    second = client.get("/api/v1/health/live", headers={"If-None-Match": etag})
    assert second.status_code == 304
    assert second.content == b""
    assert second.headers["ETag"] == etag


def test_mismatched_if_none_match_returns_full_body():
    client = TestClient(app)
    resp = client.get(
        "/api/v1/health/live", headers={"If-None-Match": 'W/"not-the-etag"'}
    )
    assert resp.status_code == 200
    assert resp.content


def test_non_200_responses_are_not_etagged():
    client = TestClient(app)
    resp = client.get("/api/v1/devices/hardware")
    assert resp.status_code in (401, 404)
    assert "ETag" not in resp.headers
