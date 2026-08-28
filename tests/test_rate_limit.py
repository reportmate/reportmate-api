"""Global rate-limit middleware tests.

The Limiter has always declared default_limits=["120/minute"], but without
SlowAPIMiddleware mounted the default never applied to anything. These tests
pin the mounted behavior across two buckets: a per-device allowance keyed on
the presented serial, and a per-address ceiling sized for the whole fleet.

The address ceiling is what a single-bucket design got wrong -- every campus
device shares one public egress, so a 120/min per-address limit was really a
120/min limit for ~370 machines. These tests pin that a device's own burst is
still bounded while the fleet's aggregate is not mistaken for one device's.
"""

from fastapi.testclient import TestClient

import dependencies
from main import app
from rate_limit import GlobalRateLimitMiddleware


import pytest


@pytest.fixture(autouse=True)
def _freeze_rate_limit_clock(monkeypatch):
    """Pin the window so multi-request tests are deterministic."""
    import rate_limit

    monkeypatch.setattr(rate_limit.time, "time", lambda: 1_000_000.0)


def test_per_device_limit_enforced(monkeypatch):
    """One device burst past its own allowance is still throttled."""
    GlobalRateLimitMiddleware.reset()
    client = TestClient(app)
    headers = {"X-Device-Serial": "TESTSERIAL0001"}
    codes = [
        client.get("/api/v1/health/live", headers=headers).status_code
        for _ in range(121)
    ]
    assert codes[:120] == [200] * 120
    assert codes[120] == 429


def test_one_device_does_not_throttle_another(monkeypatch):
    """The defect this replaces: two machines sharing an egress address shared
    an allowance, so one busy device silently starved every other."""
    GlobalRateLimitMiddleware.reset()
    client = TestClient(app)
    for _ in range(121):
        client.get("/api/v1/health/live", headers={"X-Device-Serial": "BUSYDEVICE1"})
    resp = client.get("/api/v1/health/live", headers={"X-Device-Serial": "QUIETDEV22"})
    assert resp.status_code == 200


def test_address_ceiling_admits_a_fleet_sized_burst(monkeypatch):
    """Fleet-wide traffic peaks at ~705/min through one campus egress; a
    per-address ceiling that rejects that is rejecting real check-ins."""
    GlobalRateLimitMiddleware.reset()
    client = TestClient(app)
    codes = [
        client.get(
            "/api/v1/health/live", headers={"X-Device-Serial": f"DEV{i:05d}"}
        ).status_code
        for i in range(800)
    ]
    assert codes == [200] * 800


def test_unkeyed_traffic_is_not_held_to_the_device_limit():
    """A client that sends no serial is governed by the address ceiling alone.
    This is what makes the fix a mitigation before the header-sending clients
    have finished rolling out."""
    GlobalRateLimitMiddleware.reset()
    client = TestClient(app)
    codes = [client.get("/api/v1/health/live").status_code for _ in range(130)]
    assert codes == [200] * 130


def test_address_bucket_counts_every_request():
    """A serial header is unauthenticated, so it must not buy an escape from
    the flood shield: distinct serials still accumulate on one address."""
    GlobalRateLimitMiddleware.reset()
    client = TestClient(app)
    for i in range(20):
        client.get("/api/v1/health/live", headers={"X-Device-Serial": f"SPOOF{i:04d}"})
    address_keys = {
        k: v for k, v in GlobalRateLimitMiddleware._counts.items() if k.startswith("ip:")
    }
    assert len(address_keys) == 1
    assert next(iter(address_keys.values())) == 20


def test_address_ceiling_rejects_past_its_limit():
    """The ceiling is real, exercised directly -- the middleware instance sits
    inside the built app stack where a test cannot reach its configuration."""
    GlobalRateLimitMiddleware.reset()
    verdicts = [GlobalRateLimitMiddleware._allow("ip:1.2.3.4", 5)[0] for _ in range(7)]
    assert verdicts == [True] * 5 + [False, False]


def test_buckets_are_independent():
    """Exhausting one device's allowance leaves the address budget intact for
    every other device behind the same egress."""
    GlobalRateLimitMiddleware.reset()
    for _ in range(200):
        GlobalRateLimitMiddleware._allow("dev:BUSY", 120)
    assert GlobalRateLimitMiddleware._allow("dev:QUIET", 120)[0] is True
    assert GlobalRateLimitMiddleware._allow("ip:1.2.3.4", 3000)[0] is True


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
    headers = {"X-Internal-Secret": "not-the-secret", "X-Device-Serial": "TESTSERIAL0001"}
    codes = [
        client.get("/api/v1/health/live", headers=headers).status_code
        for _ in range(121)
    ]
    assert codes[120] == 429


def test_429_carries_retry_information():
    GlobalRateLimitMiddleware.reset()
    client = TestClient(app)
    headers = {"X-Device-Serial": "TESTSERIAL0001"}
    for _ in range(120):
        client.get("/api/v1/health/live", headers=headers)
    resp = client.get("/api/v1/health/live", headers=headers)
    assert resp.status_code == 429
    assert (
        "Retry-After" in resp.headers
        or "error" in resp.json()
        or "detail" in resp.json()
    )


def test_no_per_route_slowapi_limit_on_ingestion():
    # The slowapi per-route limit on POST /events keyed on the ingress
    # connection IP (get_remote_address), not the client — collapsing the
    # whole fleet into ~2 shared buckets and mass-429'ing legitimate device
    # check-ins. It was removed; the global XFF-keyed middleware is the only
    # ingestion limiter now. No slowapi per-route limits should remain.
    import main  # noqa: F401 - registers routes

    from dependencies import limiter

    assert getattr(limiter, "_route_limits", {}) == {}
