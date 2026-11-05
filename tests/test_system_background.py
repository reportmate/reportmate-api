import json

import pytest
from fastapi.testclient import TestClient

import routers.system_background as background
from main import app
from routers.system_background import enabled_state, last_run_state, origin, shape_item
from routers.system_item_reports import boolean, selected_items

HEADERS = {"X-Internal-Secret": "test-internal-secret"}


@pytest.mark.parametrize("code,expected", [
    ("0", "succeeded"), (0, "succeeded"), ("0x0", "succeeded"),
    ("267011", "notRun"), ("0x41303", "notRun"), ("267009", "running"),
    ("-2147020576", "failed"), ("1", "failed"), ("0x80070002", "failed"),
    (None, "unknown"), ("", "unknown"), ("not a number", "unknown"),
])
def test_task_last_result_classification(code, expected):
    assert last_run_state(code) == expected


def test_scheduler_informational_codes_are_not_failures():
    for code in background.OK_CODES:
        assert last_run_state(code) != "failed"


@pytest.mark.parametrize("item,expected", [
    ({"kind": "task", "path": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"}, "builtIn"),
    ({"kind": "task", "path": "\\Vendor Update Task"}, "thirdParty"),
    ({"kind": "task", "path": ""}, "unknown"),
    ({"kind": "launchd", "name": "com.apple.example", "source": "System"}, "builtIn"),
    ({"kind": "launchd", "name": "com.example.agent", "source": "User"}, "thirdParty"),
    ({"kind": "launchd", "name": "com.example.agent", "source": None}, "unknown"),
    ({"kind": "loginItem", "bundleId": "com.apple.AddressBook"}, "builtIn"),
    ({"kind": "loginItem", "bundleId": "com.example.app"}, "thirdParty"),
    ({"kind": "loginItem", "bundleId": None}, "unknown"),
])
def test_origin_uses_collected_fields_only(item, expected):
    assert origin(item) == expected


@pytest.mark.parametrize("item,expected", [
    ({"kind": "task", "enabled": True}, "enabled"), ({"kind": "task", "enabled": False}, "disabled"),
    ({"kind": "task", "enabled": None}, "unknown"), ({"kind": "loginItem", "enabled": 1}, "enabled"),
    ({"kind": "launchd", "state": "Disabled"}, "disabled"), ({"kind": "launchd", "state": "Loaded"}, "enabled"),
    ({"kind": "launchd", "state": "Something"}, "unknown"),
])
def test_enabled_state_never_assumes_enabled(item, expected):
    assert enabled_state(item) == expected


def test_launchd_rows_have_no_task_result():
    row = shape_item({"kind": "launchd", "name": "com.example.agent", "state": "Enabled", "runAtLoad": 1, "keepAlive": None})
    assert row["lastRun"] == "notApplicable" and row["runAtLoad"] is True and row["keepAlive"] is None


def test_boolean_rejects_unrecognized_values():
    assert boolean(1) is True and boolean("false") is False and boolean(2) is None and boolean({}) is None


def test_selected_items_require_known_kinds():
    parsed = selected_items(json.dumps(["task:\\Vendor Task", "launchd:com.example.agent"]), ["task", "launchd", "loginItem"])
    assert parsed["task"] == {"\\vendor task"} and parsed["launchd"] == {"com.example.agent"}


@pytest.mark.parametrize("query", [
    "enabled=on", "lastRuns=broken", "origins=vendor", "kinds=driver", "platform=invalid",
    "limit=2001", "offset=-1", "freshness=recent", "maxAgeHours=0",
    'items=["service:x"]', "items=[1]", "items=notjson",
])
def test_invalid_queries_fail_before_accessing_the_database(query):
    assert TestClient(app).get(f"/api/v1/system/background?{query}", headers=HEADERS).status_code == 422


def test_background_report_requires_authentication():
    client = TestClient(app)
    assert client.get("/api/v1/system/background").status_code == 401
    assert client.get("/api/v1/system/background/filters").status_code == 401


def test_report_without_selection_or_failure_filter_runs_no_query(monkeypatch):
    monkeypatch.setattr(background, "load_devices", lambda *a, **k: pytest.fail("queried without a selection"))
    body = TestClient(app).get("/api/v1/system/background", headers=HEADERS).json()
    assert body["queryRequired"] is True and body["rows"] == []


def test_malformed_device_payloads_do_not_fail_the_report(monkeypatch):
    devices = [
        "not a device",
        {"serialNumber": "TESTSERIAL01", "deviceName": 42, "platform": ["bad"], "inventoryAvailable": True,
         "collectedAt": {"bad": True}, "items": [
             "not an item",
             {"kind": "task", "key": 7, "name": None, "path": ["\\Vendor"], "enabled": "maybe", "lastRunCode": {"x": 1}},
             {"kind": "launchd", "key": "com.example.agent", "name": "com.example.agent", "source": 5, "state": 3},
         ]},
        {"serialNumber": "TESTSERIAL02", "deviceName": None, "inventoryAvailable": True, "items": {"not": "a list"}},
        {"serialNumber": None, "deviceName": "Device", "inventoryAvailable": False, "items": None},
    ]
    monkeypatch.setattr(background, "load_devices", lambda *a, **k: devices)
    response = TestClient(app).get("/api/v1/system/background", params={"items": '["launchd:com.example.agent"]'}, headers=HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["devicesWithoutInventory"] == 3
    task = next(row for row in body["rows"] if row["kind"] == "task")
    assert task["enabledState"] == "unknown" and task["lastRun"] == "unknown" and task["freshness"] == "unknown"
