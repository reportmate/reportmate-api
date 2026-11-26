"""App-level smoke tests + a regression guard for the /api/v1/<module> rename.

TestClient is used WITHOUT a context manager so the on_event startup handlers
(which open the database to ensure indexes) do not fire — these tests must run
with no database available.
"""

import re

from fastapi.testclient import TestClient

from main import app


def test_root_endpoint():
    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "ReportMate API"
    assert body["apiVersion"] == "v1"


def test_openapi_exposes_canonical_module_paths():
    paths = app.openapi()["paths"]
    for module in (
        "hardware",
        "applications",
        "network",
        "security",
        "system",
        "installs",
        "management",
        "inventory",
        "identity",
        "peripherals",
    ):
        assert f"/api/v1/{module}" in paths, f"missing canonical /api/v1/{module}"


def test_no_stale_nested_device_module_paths():
    # The migration renamed /api/v1/devices/<module> -> /api/v1/<module>.
    # The deprecated aliases are include_in_schema=False, so the published
    # schema must contain zero nested device-module routes.
    paths = app.openapi()["paths"]
    nested = [p for p in paths if re.match(r"^/api/v1/devices/[a-z]", p)]
    assert (
        nested == []
    ), f"stale nested device-module paths leaked into schema: {nested}"


def test_cors_preflight_allows_put_and_api_key_header(monkeypatch):
    origin = next(iter(
        m.kwargs["allow_origins"] for m in app.user_middleware if m.kwargs.get("allow_origins")
    ), None)
    if not origin:
        return
    client = TestClient(app)
    resp = client.options(
        "/settings",
        headers={
            "Origin": origin[0],
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "x-api-key",
        },
    )
    assert resp.status_code == 200
    assert "PUT" in resp.headers["access-control-allow-methods"]
    assert "x-api-key" in resp.headers["access-control-allow-headers"].lower()
