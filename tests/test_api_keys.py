"""Per-client API keys: key helpers, verification, and scope enforcement.

The database is mocked (CI has none) by monkeypatching the isolated lookup
``get_api_key_record`` and the best-effort ``_touch_api_key_last_used``.
"""

import re

import dependencies
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from dependencies import (
    _hash_secret,
    _required_scope,
    generate_api_key,
    parse_api_key,
    verify_api_key,
    verify_authentication,
)


# ----- key helpers --------------------------------------------------------


def test_generate_api_key_format():
    key_id, secret, full = generate_api_key()
    assert full == f"rm_{key_id}_{secret}"
    assert re.fullmatch(r"[0-9a-f]{12}", key_id)
    assert re.fullmatch(r"[0-9a-f]{48}", secret)


def test_generate_api_key_is_unique():
    a = generate_api_key()[2]
    b = generate_api_key()[2]
    assert a != b


def test_parse_api_key_roundtrip():
    key_id, secret, full = generate_api_key()
    assert parse_api_key(full) == (key_id, secret)


@pytest.mark.parametrize(
    "bad", ["", None, "garbage", "rm_only", "xx_id_secret", "rm__secret", "rm_id_"]
)
def test_parse_api_key_rejects_malformed(bad):
    assert parse_api_key(bad) is None


def test_hash_secret_is_deterministic_sha256():
    assert _hash_secret("abc") == _hash_secret("abc")
    assert len(_hash_secret("abc")) == 64


# ----- _required_scope mapping --------------------------------------------


@pytest.mark.parametrize(
    "method,path,expected",
    [
        ("GET", "/api/v1/hardware", "read"),
        ("HEAD", "/api/v1/devices", "read"),
        ("POST", "/api/v1/events", "ingest"),
        ("DELETE", "/api/v1/device/X", "admin"),
        ("PATCH", "/api/v1/device/X", "admin"),
        ("GET", "/api/v1/admin/api-keys", "admin"),
        ("POST", "/api/v1/admin/api-keys", "admin"),
    ],
)
def test_required_scope(method, path, expected):
    assert _required_scope(method, path) == expected


# ----- verify_api_key (mocked lookup) -------------------------------------


def _install(monkeypatch, scopes, active=True, wrong_secret=False):
    key_id, secret, full = generate_api_key()
    stored_secret = "different" if wrong_secret else secret
    record = {
        "client_id": "test-client",
        "key_hash": _hash_secret(stored_secret),
        "scopes": scopes,
        "active": active,
    }
    monkeypatch.setattr(
        dependencies,
        "get_api_key_record",
        lambda kid: record if kid == key_id else None,
    )
    monkeypatch.setattr(dependencies, "_touch_api_key_last_used", lambda kid: None)
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    return full


def test_verify_api_key_valid(monkeypatch):
    full = _install(monkeypatch, ["read", "ingest"])
    auth = verify_api_key(full)
    assert auth["method"] == "api_key"
    assert auth["client_id"] == "test-client"
    assert auth["scopes"] == ["read", "ingest"]


def test_verify_api_key_wrong_secret(monkeypatch):
    full = _install(monkeypatch, ["read"], wrong_secret=True)
    assert verify_api_key(full) is None


def test_verify_api_key_inactive(monkeypatch):
    full = _install(monkeypatch, ["read"], active=False)
    assert verify_api_key(full) is None


def test_verify_api_key_unknown(monkeypatch):
    monkeypatch.setattr(dependencies, "get_api_key_record", lambda kid: None)
    assert verify_api_key("rm_deadbeef0000_" + "a" * 48) is None


def test_verify_api_key_malformed(monkeypatch):
    assert verify_api_key("not-a-key") is None


# ----- full auth + scope enforcement via verify_authentication ------------


def _client():
    app = FastAPI()

    @app.get("/data", dependencies=[Depends(verify_authentication)])
    def read_data():
        return {"ok": True}

    @app.post("/data", dependencies=[Depends(verify_authentication)])
    def ingest_data():
        return {"ok": True}

    @app.delete("/data/{x}", dependencies=[Depends(verify_authentication)])
    def delete_data(x: str):
        return {"ok": True}

    @app.get("/admin/thing", dependencies=[Depends(verify_authentication)])
    def admin_thing():
        return {"ok": True}

    return TestClient(app)


def test_read_scope_can_read_only(monkeypatch):
    key = _install(monkeypatch, ["read"])
    c = _client()
    h = {"X-API-Key": key}
    assert c.get("/data", headers=h).status_code == 200
    assert c.post("/data", headers=h).status_code == 403
    assert c.delete("/data/1", headers=h).status_code == 403
    assert c.get("/admin/thing", headers=h).status_code == 403


def test_ingest_scope_can_post_only(monkeypatch):
    key = _install(monkeypatch, ["ingest"])
    c = _client()
    h = {"X-API-Key": key}
    assert c.post("/data", headers=h).status_code == 200
    assert c.get("/data", headers=h).status_code == 403


def test_admin_scope_can_delete_and_hit_admin(monkeypatch):
    key = _install(monkeypatch, ["admin"])
    c = _client()
    h = {"X-API-Key": key}
    assert c.delete("/data/1", headers=h).status_code == 200
    assert c.get("/admin/thing", headers=h).status_code == 200


def test_multi_scope(monkeypatch):
    key = _install(monkeypatch, ["read", "ingest"])
    c = _client()
    h = {"X-API-Key": key}
    assert c.get("/data", headers=h).status_code == 200
    assert c.post("/data", headers=h).status_code == 200
    assert c.delete("/data/1", headers=h).status_code == 403


def test_invalid_api_key_is_401(monkeypatch):
    _install(monkeypatch, ["read"], wrong_secret=True)
    c = _client()
    # well-formed but secret won't match the stored hash
    bad = "rm_" + "0" * 12 + "_" + "a" * 48
    assert c.get("/data", headers={"X-API-Key": bad}).status_code == 401


def test_legacy_passphrase_keeps_full_access(monkeypatch):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    monkeypatch.setattr(dependencies, "REPORTMATE_PASSPHRASE", "legacy-secret")
    c = _client()
    h = {"X-Client-Passphrase": "legacy-secret"}
    # Legacy credential is granted ALL scopes -> read, ingest, admin all pass.
    assert c.get("/data", headers=h).status_code == 200
    assert c.post("/data", headers=h).status_code == 200
    assert c.delete("/data/1", headers=h).status_code == 200
    assert c.get("/admin/thing", headers=h).status_code == 200
