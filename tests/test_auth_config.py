"""The public auth-config endpoint describes how to authenticate, with no secrets."""

from fastapi.testclient import TestClient

import oidc_auth
from main import app


def test_auth_config_lists_credentials_without_oidc(monkeypatch):
    monkeypatch.setattr(oidc_auth, "ENABLE_OIDC_AUTH", False)
    r = TestClient(app).get("/api/v1/auth/config")
    assert r.status_code == 200
    body = r.json()
    assert body["credentials"] == ["X-API-Key", "X-Client-Passphrase"]
    assert body["oidc"] == {"enabled": False, "issuers": [], "audience": None, "audiences": []}


def test_auth_config_advertises_the_oidc_audience(monkeypatch):
    monkeypatch.setattr(oidc_auth, "ENABLE_OIDC_AUTH", True)
    monkeypatch.setattr(oidc_auth, "OIDC_ISSUERS", ("https://login.example.test/tenant/v2.0",))
    monkeypatch.setattr(oidc_auth, "OIDC_AUDIENCES", ("api://00000000-0000-0000-0000-000000000000",))
    body = TestClient(app).get("/api/v1/auth/config").json()
    assert body["credentials"][0] == "Authorization: Bearer"
    assert body["oidc"]["enabled"] is True
    assert body["oidc"]["audience"] == "api://00000000-0000-0000-0000-000000000000"
    assert body["oidc"]["issuers"] == ["https://login.example.test/tenant/v2.0"]
    assert "secret" not in str(body).lower()


def test_auth_config_needs_no_credential():
    r = TestClient(app).get("/api/v1/auth/config")
    assert r.status_code == 200


def test_401_detail_matches_auth_config(monkeypatch):
    import dependencies

    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    monkeypatch.setattr(oidc_auth, "ENABLE_OIDC_AUTH", True)
    monkeypatch.setattr(oidc_auth, "OIDC_ISSUERS", ("https://login.example.test/tenant/v2.0",))
    monkeypatch.setattr(oidc_auth, "OIDC_AUDIENCES", ("api://sample",))
    r = TestClient(app).get("/api/v1/devices")
    assert r.status_code == 401
    assert "Authorization: Bearer" in r.json()["detail"]
    assert "/api/v1/auth/config" in r.json()["detail"]

    monkeypatch.setattr(oidc_auth, "ENABLE_OIDC_AUTH", False)
    r = TestClient(app).get("/api/v1/devices")
    assert r.status_code == 401
    assert "Bearer" not in r.json()["detail"]
