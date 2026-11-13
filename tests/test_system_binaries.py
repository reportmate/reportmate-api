import pytest
from fastapi.testclient import TestClient

import routers.system_binaries as binaries
from main import app
from routers.system_binaries import running_state, shape_item

HEADERS = {"X-Internal-Secret": "test-internal-secret"}


@pytest.mark.parametrize("running,expected", [(True, "yes"), (False, "no"), ("true", "yes"), (None, "unknown"), ("x", "unknown")])
def test_running_state_is_unknown_when_not_reported(running, expected):
    assert running_state({"running": running}) == expected


def test_shape_item_drops_invalid_process_counts_and_defaults_source():
    item = shape_item({"kind": "binary", "processCount": True, "source": ""})
    assert item["processCount"] is None and item["source"] == "unknown" and item["runningState"] == "unknown"
    assert shape_item({"kind": "binary", "processCount": 3})["processCount"] == 3


@pytest.mark.parametrize("query", [
    "categories=daemon", "sources=npm", "running=maybe", "platform=invalid",
    "limit=2001", "offset=-1", 'items=["helper:x"]', "items=httpd",
])
def test_invalid_queries_fail_before_accessing_the_database(query):
    assert TestClient(app).get(f"/api/v1/system/binaries?{query}", headers=HEADERS).status_code == 422


def test_binaries_report_requires_authentication():
    client = TestClient(app)
    assert client.get("/api/v1/system/binaries").status_code == 401
    assert client.get("/api/v1/system/binaries/filters").status_code == 401


def test_report_needs_a_selection_category_or_running_filter(monkeypatch):
    monkeypatch.setattr(binaries, "load_devices", lambda *a, **k: pytest.fail("queried without a selection"))
    client = TestClient(app)
    for params in ({}, {"running": "no"}, {"sources": "os"}):
        body = client.get("/api/v1/system/binaries", params=params, headers=HEADERS).json()
        assert body["queryRequired"] is True and body["rows"] == []


def test_rows_filter_by_selection_source_running_and_version(monkeypatch):
    captured = {}
    devices = [
        None,
        {"serialNumber": "TESTSERIAL01", "deviceName": "Server one", "platform": "macOS", "inventoryAvailable": True, "items": [
            {"kind": "binary", "key": "httpd", "name": "httpd", "category": "server", "path": "/usr/sbin/httpd",
             "version": "2.4.67", "source": "os", "running": True, "processCount": 4},
            {"kind": "binary", "key": "httpd", "name": "httpd", "category": "server", "path": "/opt/homebrew/bin/httpd",
             "version": "2.4.62", "source": "homebrew", "running": False, "processCount": 0},
            {"kind": "binary", "key": "node", "name": "node", "category": "runtime", "running": None},
            7,
        ]},
        {"serialNumber": "TESTSERIAL02", "inventoryAvailable": False, "items": None},
    ]

    def load(name, params):
        captured.update(params)
        return devices

    monkeypatch.setattr(binaries, "load_devices", load)
    client = TestClient(app)
    body = client.get("/api/v1/system/binaries", params={"items": '["binary:HTTPD"]'}, headers=HEADERS).json()
    assert captured["binary_keys"] == ["httpd"] and captured["running_only"] is False
    assert sorted(row["path"] for row in body["rows"]) == ["/opt/homebrew/bin/httpd", "/usr/sbin/httpd"]
    assert body["devicesWithoutInventory"] == 2 and body["devicesReporting"] == 1
    assert body["summary"]["source:os"] == 1 and body["summary"]["runningState:yes"] == 1

    body = client.get("/api/v1/system/binaries", params={"items": '["binary:httpd"]', "sources": "os", "versions": "2.4.67"}, headers=HEADERS).json()
    assert [row["version"] for row in body["rows"]] == ["2.4.67"]

    body = client.get("/api/v1/system/binaries", params={"running": "yes"}, headers=HEADERS).json()
    assert captured["running_only"] is True
    assert [row["path"] for row in body["rows"]] == ["/usr/sbin/httpd"]

    body = client.get("/api/v1/system/binaries", params={"categories": "runtime"}, headers=HEADERS).json()
    assert [row["name"] for row in body["rows"]] == ["node"] and body["rows"][0]["runningState"] == "unknown"
