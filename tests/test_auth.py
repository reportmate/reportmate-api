"""Authentication dependency behaviour.

Exercised through a real FastAPI app + TestClient so the ``Header(None)``
defaults resolve the way they do in production (calling the dependency
directly would leave the Header sentinels in place).
"""

import dependencies
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from dependencies import verify_authentication


@pytest.fixture
def client():
    app = FastAPI()

    @app.get("/protected", dependencies=[Depends(verify_authentication)])
    def protected():
        return {"ok": True}

    return TestClient(app)


def test_no_credentials_rejected(client, monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    assert client.get("/protected").status_code == 401


def test_correct_passphrase_accepted(client, monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    monkeypatch.setattr(dependencies, "REPORTMATE_PASSPHRASE", "secret")
    resp = client.get("/protected", headers={"X-Client-Passphrase": "secret"})
    assert resp.status_code == 200


def test_api_passphrase_header_accepted(client, monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    monkeypatch.setattr(dependencies, "REPORTMATE_PASSPHRASE", "secret")
    resp = client.get("/protected", headers={"X-API-PASSPHRASE": "secret"})
    assert resp.status_code == 200


def test_wrong_passphrase_rejected(client, monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    monkeypatch.setattr(dependencies, "REPORTMATE_PASSPHRASE", "secret")
    resp = client.get("/protected", headers={"X-Client-Passphrase": "wrong"})
    assert resp.status_code == 401


def test_internal_secret_accepted(client, monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    monkeypatch.setattr(dependencies, "API_INTERNAL_SECRET", "int-secret")
    resp = client.get("/protected", headers={"X-Internal-Secret": "int-secret"})
    assert resp.status_code == 200


def test_wrong_internal_secret_rejected(client, monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    monkeypatch.setattr(dependencies, "API_INTERNAL_SECRET", "int-secret")
    resp = client.get("/protected", headers={"X-Internal-Secret": "nope"})
    assert resp.status_code == 401


def test_managed_identity_accepted(client, monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    resp = client.get("/protected", headers={"X-MS-CLIENT-PRINCIPAL-ID": "abc-123"})
    assert resp.status_code == 200


def test_disable_auth_bypasses_everything(client, monkeypatch):
    # Guards the development-only DISABLE_AUTH escape hatch: when set, an
    # unauthenticated request must succeed. (Hardening to forbid this in prod
    # is tracked separately.)
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", True)
    assert client.get("/protected").status_code == 200
