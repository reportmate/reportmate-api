import pytest
from fastapi.testclient import TestClient

import routers.system_extensions as extensions
from main import app
from routers.system_extensions import activation, managed, shape_item, signature

HEADERS = {"X-Internal-Secret": "test-internal-secret"}


@pytest.mark.parametrize("state,expected", [
    ("activated_enabled", "activated"), ("enabled", "activated"),
    ("activated_waiting_for_user", "notActivated"), ("terminated_waiting_to_uninstall_on_reboot", "notActivated"),
    ("", "unknown"), (None, "unknown"),
])
def test_system_extension_activation(state, expected):
    assert activation({"kind": "systemExtension", "state": state}) == expected


def test_only_matching_kinds_carry_derived_states():
    assert activation({"kind": "helper", "state": "x"}) is None
    assert signature({"kind": "systemExtension", "signed": True}) is None
    assert managed({"kind": "kernelExtension"}) is None


@pytest.mark.parametrize("signed,expected", [(1, "signed"), (0, "unsigned"), (True, "signed"), (None, "unknown"), ("x", "unknown")])
def test_helper_signature_is_unknown_when_not_reported(signed, expected):
    assert signature({"kind": "helper", "signed": signed}) == expected


def test_managed_by_profile_is_unknown_when_not_collected():
    assert shape_item({"kind": "systemExtension", "state": "activated_enabled"})["managed"] == "unknown"
    assert shape_item({"kind": "systemExtension", "managedByProfile": True})["managed"] == "yes"


@pytest.mark.parametrize("query", [
    "activations=on", "signatures=maybe", "managed=perhaps", "kinds=app", "platform=invalid",
    "limit=2001", "offset=-1", 'items=["task:x"]',
])
def test_invalid_queries_fail_before_accessing_the_database(query):
    assert TestClient(app).get(f"/api/v1/system/extensions?{query}", headers=HEADERS).status_code == 422


def test_extensions_report_requires_authentication():
    client = TestClient(app)
    assert client.get("/api/v1/system/extensions").status_code == 401
    assert client.get("/api/v1/system/extensions/filters").status_code == 401


def test_windows_scope_is_not_applicable_without_a_query(monkeypatch):
    monkeypatch.setattr(extensions, "load_devices", lambda *a, **k: pytest.fail("queried for Windows"))
    client = TestClient(app)
    body = client.get("/api/v1/system/extensions", params={"platform": "win", "signatures": "unsigned"}, headers=HEADERS).json()
    assert body["applicable"] is False and body["rows"] == []
    assert client.get("/api/v1/system/extensions/filters", params={"platform": "win"}, headers=HEADERS).json()["applicable"] is False


def test_malformed_extension_payloads_do_not_fail_the_report(monkeypatch):
    devices = [
        None,
        {"serialNumber": "TESTSERIAL01", "deviceName": ["x"], "inventoryAvailable": True, "items": [
            {"kind": "helper", "key": "com.example.helper", "name": "com.example.helper", "signed": {"bad": 1}, "teamId": 5},
            {"kind": "systemExtension", "key": 3, "name": 3, "state": ["x"], "managedByProfile": "x"},
            7,
        ]},
    ]
    monkeypatch.setattr(extensions, "load_devices", lambda *a, **k: devices)
    response = TestClient(app).get("/api/v1/system/extensions", params={"items": '["helper:com.example.helper"]'}, headers=HEADERS)
    assert response.status_code == 200
    rows = response.json()["rows"]
    assert {row["kind"] for row in rows} == {"helper", "systemExtension"}
    assert next(row for row in rows if row["kind"] == "helper")["signature"] == "unknown"
    assert next(row for row in rows if row["kind"] == "systemExtension")["activation"] == "unknown"
