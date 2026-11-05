from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from main import app
from routers.system_updates import build_update_options, flag, kb_number, shape_updates

NOW = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
FRESH = (NOW - timedelta(hours=2)).isoformat()
STALE = (NOW - timedelta(days=5)).isoformat()
SEARCHED = {"status": "succeeded", "checkedAt": FRESH}


def windows(serial, collected=FRESH, pending=None, installed=None, count=None, search=SEARCHED):
    pending = [] if pending is None else pending
    return {
        "updateSearch": search,
        "serialNumber": serial,
        "deviceName": serial,
        "platform": "Windows 11",
        "collectedAt": collected,
        "pendingWindowsUpdates": pending,
        "pendingWindowsUpdatesCount": len(pending) if count is None else count,
        "installedUpdates": installed or [],
    }


def mac(serial, collected=FRESH, pending=None, search=SEARCHED):
    return {
        "updateSearch": search,
        "serialNumber": serial,
        "deviceName": serial,
        "platform": "macOS",
        "collectedAt": collected,
        "pendingAppleUpdates": pending,
    }


SECURITY = {
    "title": "2026-06 Security Update (KB5000001)",
    "kbNumber": "KB5000001",
    "category": "Security Updates",
    "severity": "Important",
    "cves": ["CVE-2026-0001"],
    "isMandatory": False,
    "isDownloaded": True,
    "rebootRequired": True,
    "releaseDate": "2026-06-09T00:00:00",
}
DEFINITION = {
    "title": "Security Intelligence Update - KB2267602 (Version 1.0)",
    "kbNumber": "KB2267602",
    "category": "Definition Updates",
    "severity": "",
    "cves": [],
    "isDownloaded": False,
    "rebootRequired": False,
}
MACOS = {
    "name": "macOS 26.5",
    "version": "26.5",
    "deferred": 1,
    "isSecurity": 0,
    "productKey": "",
    "restartRequired": 0,
    "firstOfferedAt": "2026-05-12T10:43:25Z",
    "deferredUntil": "2026-07-01T00:00:00Z",
}


def shape(rows, **overrides):
    args = dict(
        keys=set(),
        cves=set(),
        states=set(),
        freshness="all",
        max_age_hours=24,
        platform="",
        search="",
        security_only=False,
        deferred="all",
        reboot_required=False,
        min_age_days=0,
        limit=1000,
        offset=0,
        now=NOW,
    )
    args.update(overrides)
    return shape_updates(rows, **args)


@pytest.mark.parametrize(
    "raw,expected",
    [
        (True, True),
        (1, True),
        ("true", True),
        (0, False),
        (False, False),
        ("0", False),
        (None, None),
        ("maybe", None),
    ],
)
def test_collected_flags(raw, expected):
    assert flag(raw) is expected


def test_kb_number_from_field_or_title():
    assert kb_number("KB5000001") == "KB5000001"
    assert (
        kb_number("", "Security Intelligence Update - KB2267602 (Version 1)")
        == "KB2267602"
    )
    assert kb_number(None, "No KB here") is None


def test_one_row_per_device_and_pending_update_with_none_rows():
    result = shape(
        [
            windows("TESTSERIAL01", pending=[SECURITY, DEFINITION]),
            windows("TESTSERIAL02"),
            mac("TESTSERIAL03", pending=[MACOS]),
            mac("TESTSERIAL04", pending=[]),
        ]
    )
    rows = {(r["serialNumber"], r["updateKey"]): r for r in result["rows"]}
    assert rows[("TESTSERIAL01", "windows:kb5000001")]["state"] == "pending"
    assert rows[("TESTSERIAL01", "windows:kb5000001")]["cves"] == ["CVE-2026-0001"]
    assert rows[("TESTSERIAL01", "windows:kb2267602")]["isSecurity"] is False
    assert rows[("TESTSERIAL02", None)]["state"] == "none"
    mac_row = rows[("TESTSERIAL03", "macos:macos 26.5")]
    assert (mac_row["deferred"], mac_row["rebootRequired"], mac_row["ageDays"]) == (
        True,
        False,
        49,
    )
    assert rows[("TESTSERIAL04", None)]["state"] == "none"
    assert result["summary"] == {"pending": 3, "none": 2}


@pytest.mark.parametrize(
    "row",
    [
        mac("TESTSERIAL05", pending=None),
        mac("TESTSERIAL05", pending=["not an object"]),
        windows("TESTSERIAL05", pending=[SECURITY], count=4),
        mac("TESTSERIAL05", collected=STALE, pending=[]),
        mac("TESTSERIAL05", collected=None, pending=[]),
    ],
)
def test_missing_malformed_or_stale_collection_is_unknown_never_none(row):
    result = shape([row])
    assert {r["state"] for r in result["rows"]} == {"unknown"}


def test_stale_pending_keeps_reported_state():
    row = shape([windows("TESTSERIAL06", collected=STALE, pending=[SECURITY])])["rows"][
        0
    ]
    assert (row["state"], row["reportedState"], row["freshness"]) == (
        "unknown",
        "pending",
        "stale",
    )


def test_selected_kb_reports_installed_pending_not_reported_and_unknown():
    installed = [
        {
            "id": "KB5000001",
            "title": "Security Update",
            "installDate": "2026-06-10T00:00:00",
        }
    ]
    result = shape(
        [
            windows("TESTSERIAL07", pending=[SECURITY]),
            windows("TESTSERIAL08", installed=installed, collected=STALE),
            windows("TESTSERIAL09"),
            windows("TESTSERIAL10", collected=STALE),
            mac("TESTSERIAL11", pending=[]),
        ],
        keys={"windows:kb5000001"},
    )
    states = {r["serialNumber"]: r["state"] for r in result["rows"]}
    assert states == {
        "TESTSERIAL07": "pending",
        "TESTSERIAL08": "installed",
        "TESTSERIAL09": "not_reported",
        "TESTSERIAL10": "unknown",
    }


def test_cve_selection_and_attribute_filters():
    rows = [
        windows("TESTSERIAL12", pending=[SECURITY, DEFINITION]),
        windows("TESTSERIAL13", pending=[DEFINITION]),
    ]
    by_cve = shape(rows, cves={"cve-2026-0001"})["rows"]
    assert [(r["serialNumber"], r["state"]) for r in by_cve] == [
        ("TESTSERIAL12", "pending"),
        ("TESTSERIAL13", "not_reported"),
    ]
    security = shape(rows, security_only=True)["rows"]
    assert [(r["serialNumber"], r["kb"]) for r in security] == [
        ("TESTSERIAL12", "KB5000001")
    ]
    assert shape(rows, reboot_required=True)["total"] == 1
    assert shape([mac("TESTSERIAL14", pending=[MACOS])], deferred="no")["total"] == 0
    assert shape([mac("TESTSERIAL14", pending=[MACOS])], min_age_days=50)["total"] == 0
    assert shape([mac("TESTSERIAL14", pending=[MACOS])], min_age_days=49)["total"] == 1


def test_options_list_collected_updates_and_cves():
    updates, cves = build_update_options(
        [
            windows(
                "TESTSERIAL15",
                pending=[SECURITY],
                installed=[{"id": "KB5000002", "title": "Update"}],
            ),
            windows(
                "TESTSERIAL16",
                installed=[{"id": "KB5000001", "title": "Security Update"}],
            ),
            mac("TESTSERIAL17", pending=[MACOS]),
        ],
        NOW,
    )
    by_key = {u["key"]: u for u in updates}
    assert by_key["windows:kb5000001"]["pendingDevices"] == 1
    assert by_key["windows:kb5000001"]["installedDevices"] == 1
    assert by_key["windows:kb5000001"]["title"] == SECURITY["title"]
    assert by_key["windows:kb5000002"]["installedDevices"] == 1
    assert by_key["macos:macos 26.5"]["platform"] == "macos"
    assert cves == [{"cve": "CVE-2026-0001", "devices": 1}]


@pytest.mark.parametrize(
    "query",
    [
        "states=patched",
        "platform=invalid",
        "deferred=maybe",
        "minAgeDays=-1",
        "limit=2001",
        "freshness=recent",
        'updates=["kb5000001"]',
        'cves=["not-a-cve"]',
        "updates=[1]",
    ],
)
def test_invalid_queries_fail_before_accessing_the_database(query):
    response = TestClient(app).get(
        f"/api/v1/system/updates?{query}",
        headers={"X-Internal-Secret": "test-internal-secret"},
    )
    assert response.status_code == 422


def test_updates_report_requires_authentication():
    client = TestClient(app)
    assert client.get("/api/v1/system/updates").status_code == 401
    assert client.get("/api/v1/system/updates/filters").status_code == 401
    assert (
        client.get(
            "/api/v1/system/updates/filters?platform=invalid",
            headers={"X-Internal-Secret": "test-internal-secret"},
        ).status_code
        == 422
    )


def test_malformed_collected_types_never_fail_the_report():
    odd = {"title": 12345, "kbNumber": {"kb": 1}, "category": {"name": "Security"}, "severity": ["High"],
           "cves": "CVE-2026-0001", "releaseDate": 20260609, "isDownloaded": "maybe"}
    odd_installed = [{"id": 5000001, "title": ["Security Update"], "category": None, "installDate": {}}, "not an object"]
    odd_mac = {"name": {"label": "x"}, "version": 26.5, "deferred": "yes", "firstOfferedAt": ["2026-05-12"]}
    rows = [
        windows("TESTSERIAL18", pending=[odd], installed=odd_installed),
        mac("TESTSERIAL19", pending=[odd_mac]),
        {"serialNumber": "TESTSERIAL20", "platform": None, "collectedAt": FRESH, "pendingWindowsUpdates": "garbage"},
    ]
    result = shape(rows)
    states = {r["serialNumber"]: r["state"] for r in result["rows"]}
    assert states == {"TESTSERIAL18": "pending", "TESTSERIAL19": "pending", "TESTSERIAL20": "unknown"}
    win = next(r for r in result["rows"] if r["serialNumber"] == "TESTSERIAL18")
    assert (win["title"], win["kb"], win["category"], win["cves"], win["isSecurity"]) == ("12345", None, "", [], False)
    assert shape(rows, cves={"cve-2026-0001"})["summary"] == {"not_reported": 1}
    updates, cves = build_update_options(rows, NOW)
    assert cves == []
    assert [(u["key"], u["pendingDevices"]) for u in updates] == [("windows:title:12345", 1)]


def test_nothing_pending_needs_a_fresh_successful_search():
    result = shape(
        [
            windows("TESTSERIAL01"),
            windows("TESTSERIAL02", search=None),
            windows("TESTSERIAL03", search={"status": "succeeded", "checkedAt": STALE}),
            windows(
                "TESTSERIAL04",
                search={"status": "failed", "error": "Search timed out (0x8024401C)", "checkedAt": FRESH},
            ),
            mac("TESTSERIAL05", pending=[], search={"status": "failed", "error": "No network", "checkedAt": FRESH}),
            mac("TESTSERIAL06", pending=[], search="succeeded"),
        ]
    )
    rows = {r["serialNumber"]: r for r in result["rows"]}
    assert rows["TESTSERIAL01"]["state"] == "none"
    assert rows["TESTSERIAL02"]["state"] == "unknown"
    assert rows["TESTSERIAL02"]["updateSearch"]["status"] == "not_reported"
    assert rows["TESTSERIAL03"]["state"] == "unknown"
    assert rows["TESTSERIAL03"]["updateSearch"]["freshness"] == "stale"
    assert rows["TESTSERIAL04"]["state"] == "search_failed"
    assert rows["TESTSERIAL04"]["updateSearch"]["error"] == "Search timed out (0x8024401C)"
    assert rows["TESTSERIAL05"]["state"] == "search_failed"
    assert rows["TESTSERIAL06"]["state"] == "unknown"
    assert result["summary"] == {"none": 1, "unknown": 3, "search_failed": 2}


def test_a_failed_search_on_a_stale_collection_is_unknown():
    result = shape(
        [windows("TESTSERIAL01", collected=STALE, search={"status": "failed", "checkedAt": STALE})]
    )
    row = result["rows"][0]
    assert (row["reportedState"], row["state"]) == ("search_failed", "unknown")


def test_pending_updates_stay_pending_whatever_the_search_status():
    result = shape([windows("TESTSERIAL01", pending=[SECURITY], search=None)])
    assert [r["state"] for r in result["rows"]] == ["pending"]


def test_search_failed_is_a_valid_state_filter():
    client = TestClient(app)
    response = client.get(
        "/api/v1/system/updates?states=search_failed",
        headers={"X-Internal-Secret": "test-internal-secret"},
    )
    assert response.status_code != 422
