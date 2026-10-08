"""The shared client passphrase is read-only on the real routes.

The passphrase is provisioned to every managed endpoint, so it must not reach
the destructive or mutating routes. Scope is enforced inside
``verify_authentication`` before any handler runs, so these requests are
refused without touching the database.
"""

import asyncio

import dependencies
import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from main import app

PASSPHRASE = {"X-Client-Passphrase": "test-passphrase"}
API_PASSPHRASE = {"X-API-PASSPHRASE": "test-passphrase"}

DESTRUCTIVE = [
    ("delete", "/api/v1/device/TESTSERIAL01"),
    ("delete", "/api/v1/admin/installs/clear-errors"),
    ("delete", "/api/v1/admin/usage-history/cleanup"),
    ("delete", "/api/v1/admin/orphans"),
    ("patch", "/api/v1/device/TESTSERIAL01/archive"),
    ("patch", "/api/v1/device/TESTSERIAL01/unarchive"),
    ("post", "/api/v1/admin/installs/reclassify"),
    ("post", "/api/v1/admin/usage-history/reset-baseline"),
]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    return TestClient(app)


@pytest.mark.parametrize("headers", [PASSPHRASE, API_PASSPHRASE])
@pytest.mark.parametrize("method,path", DESTRUCTIVE)
def test_passphrase_cannot_reach_destructive_routes(client, method, path, headers):
    resp = getattr(client, method)(path, headers=headers)
    assert resp.status_code == 403
    assert "admin" in resp.json()["detail"]


def test_passphrase_cannot_ingest(client):
    resp = client.post("/api/v1/events", json={}, headers=PASSPHRASE)
    assert resp.status_code == 403
    assert "ingest" in resp.json()["detail"]


def test_passphrase_still_reads(client):
    resp = client.get("/api/v1/negotiate", headers=PASSPHRASE)
    assert resp.status_code not in (401, 403)


def test_invalid_api_key_falling_back_to_passphrase_is_read_only(client):
    headers = {"X-API-Key": "rm_bogus_notakey", **PASSPHRASE}
    assert client.get("/api/v1/negotiate", headers=headers).status_code not in (
        401,
        403,
    )
    assert (
        client.delete("/api/v1/device/TESTSERIAL01", headers=headers).status_code == 403
    )


def _resolve(**headers):
    """Run the auth dependency for a DELETE and return the resolved principal."""
    request = Request(
        {
            "type": "http",
            "method": "DELETE",
            "path": "/api/v1/device/TESTSERIAL01",
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 1234),
        }
    )
    args = dict(
        x_api_passphrase=None,
        x_client_passphrase=None,
        x_internal_secret=None,
        x_ms_client_principal_id=None,
        x_api_key=None,
        authorization=None,
        x_forwarded_for=None,
        user_agent="pytest",
    )
    args.update(headers)
    return asyncio.run(dependencies.verify_authentication(request, **args))


def test_internal_secret_keeps_admin(monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    auth = _resolve(x_internal_secret="test-internal-secret")
    assert auth["method"] == "internal_secret"
    assert set(auth["scopes"]) == set(dependencies.ALL_SCOPES)


def test_managed_identity_keeps_admin(monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    monkeypatch.setattr(dependencies, "TRUST_EASYAUTH_PRINCIPAL_HEADER", True)
    auth = _resolve(x_ms_client_principal_id="abc-123")
    assert auth["method"] == "managed_identity"
    assert set(auth["scopes"]) == set(dependencies.ALL_SCOPES)
