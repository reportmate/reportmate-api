"""Prometheus metrics tests."""

from fastapi.testclient import TestClient

import dependencies
from main import app

AUTH = {"X-Client-Passphrase": "test-passphrase"}


def test_metrics_requires_auth(monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    client = TestClient(app)
    assert client.get("/api/v1/metrics").status_code == 401


def test_metrics_exposes_prometheus_series(monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    client = TestClient(app)
    # Generate a request so a series exists, then scrape.
    client.get("/api/v1/health/live")
    resp = client.get("/api/v1/metrics", headers=AUTH)
    assert resp.status_code == 200
    body = resp.text
    assert "reportmate_http_requests_total" in body
    assert "reportmate_http_request_duration_seconds" in body
    assert "reportmate_http_requests_in_progress" in body


def test_request_is_counted_by_route_template(monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    client = TestClient(app)
    client.get("/api/v1/health/live")
    body = client.get("/api/v1/metrics", headers=AUTH).text
    # Label uses the route template, and the health probe is recorded.
    assert 'path="/health/live"' in body


def test_metrics_endpoint_not_self_counted(monkeypatch):
    # The scrape endpoint must not record a series for itself.
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    client = TestClient(app)
    body = client.get("/api/v1/metrics", headers=AUTH).text
    assert "/api/v1/metrics" not in body
