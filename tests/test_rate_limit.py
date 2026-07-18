"""Global rate-limit middleware tests.

The Limiter has always declared default_limits=["120/minute"], but without
SlowAPIMiddleware mounted the default never applied to anything. These tests
pin the mounted behavior: anonymous/per-IP callers get 429 past the default,
trusted internal callers bypass the default entirely.
"""

from fastapi.testclient import TestClient

import dependencies
from main import app
from rate_limit import GlobalRateLimitMiddleware


def test_default_limit_enforced_per_ip(monkeypatch):
    GlobalRateLimitMiddleware.reset()
    client = TestClient(app)
    codes = [client.get("/api/v1/health/live").status_code for _ in range(121)]
    assert codes[:120] == [200] * 120
    assert codes[120] == 429


def test_internal_secret_bypasses_default_limit(monkeypatch):
    GlobalRateLimitMiddleware.reset()
    monkeypatch.setattr(dependencies, "API_INTERNAL_SECRET", "test-internal-secret")
    client = TestClient(app)
    headers = {"X-Internal-Secret": "test-internal-secret"}
    codes = [
        client.get("/api/v1/health/live", headers=headers).status_code
        for _ in range(130)
    ]
    assert codes == [200] * 130


def test_wrong_internal_secret_still_limited(monkeypatch):
    GlobalRateLimitMiddleware.reset()
    monkeypatch.setattr(dependencies, "API_INTERNAL_SECRET", "test-internal-secret")
    client = TestClient(app)
    headers = {"X-Internal-Secret": "not-the-secret"}
    codes = [
        client.get("/api/v1/health/live", headers=headers).status_code
        for _ in range(121)
    ]
    assert codes[120] == 429


def test_429_carries_retry_information():
    GlobalRateLimitMiddleware.reset()
    client = TestClient(app)
    for _ in range(120):
        client.get("/api/v1/health/live")
    resp = client.get("/api/v1/health/live")
    assert resp.status_code == 429
    assert (
        "Retry-After" in resp.headers
        or "error" in resp.json()
        or "detail" in resp.json()
    )
