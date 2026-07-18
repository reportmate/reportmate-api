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


def test_managed_identity_rejected_by_default(client, monkeypatch):
    # The header is attacker-typable unless Azure Easy Auth fronts the app,
    # so without the explicit opt-in it must not authenticate anything.
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    resp = client.get("/protected", headers={"X-MS-CLIENT-PRINCIPAL-ID": "abc-123"})
    assert resp.status_code == 401


def test_managed_identity_accepted_with_optin(client, monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    monkeypatch.setattr(dependencies, "TRUST_EASYAUTH_PRINCIPAL_HEADER", True)
    resp = client.get("/protected", headers={"X-MS-CLIENT-PRINCIPAL-ID": "abc-123"})
    assert resp.status_code == 200


def test_principal_header_falls_through_to_passphrase(client, monkeypatch):
    # A caller sending both the untrusted header and a valid passphrase must
    # still authenticate via the passphrase path.
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    resp = client.get(
        "/protected",
        headers={
            "X-MS-CLIENT-PRINCIPAL-ID": "abc-123",
            "X-Client-Passphrase": "test-passphrase",
        },
    )
    assert resp.status_code == 200


def test_disable_auth_bypasses_everything(client, monkeypatch):
    # Guards the development-only DISABLE_AUTH escape hatch: when set, an
    # unauthenticated request must succeed. (Hardening to forbid this in prod
    # is tracked separately.)
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", True)
    assert client.get("/protected").status_code == 200


def test_negotiate_requires_authentication(client, monkeypatch):
    # The negotiate endpoint mints Web PubSub tokens for the live fleet event
    # stream; it must never answer anonymous callers.
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    from fastapi.testclient import TestClient

    from main import app

    api = TestClient(app)
    assert api.get("/api/v1/negotiate").status_code == 401
    authed = api.get(
        "/api/v1/negotiate", headers={"X-Client-Passphrase": "test-passphrase"}
    )
    assert authed.status_code != 401


def test_invalid_api_key_with_valid_passphrase_falls_through(client, monkeypatch):
    # The deployed Windows client sends both headers when both are configured;
    # a bad or stale API key must not lock out a device presenting a valid
    # passphrase (the apiv1-0056ae0 rollout proved it does otherwise).
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    resp = client.get(
        "/protected",
        headers={
            "X-API-Key": "rm_bogus_notakey",
            "X-Client-Passphrase": "test-passphrase",
        },
    )
    assert resp.status_code == 200


def test_invalid_api_key_alone_still_rejected(client, monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    resp = client.get("/protected", headers={"X-API-Key": "rm_bogus_notakey"})
    assert resp.status_code == 401


def test_invalid_api_key_with_wrong_passphrase_rejected(client, monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    resp = client.get(
        "/protected",
        headers={
            "X-API-Key": "rm_bogus_notakey",
            "X-Client-Passphrase": "wrong-passphrase",
        },
    )
    assert resp.status_code == 401
