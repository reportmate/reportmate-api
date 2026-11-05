from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from main import app
from routers import security_vulnerabilities as report
from routers.security_vulnerabilities import (
    cve_id,
    exploited_flag,
    normalize_cve,
    normalize_detection,
    summarize_cves,
    within_window,
)

HEADERS = {"X-Internal-Secret": "test-internal-secret"}
NOW = datetime.now(timezone.utc)


def _device(serial, platform, **extra):
    return {
        "serialNumber": serial,
        "deviceName": f"Device {serial}",
        "platform": platform,
        "assetTag": None,
        "usage": "Assigned",
        "catalog": "Staff",
        "area": "Lab",
        "fleet": None,
        "location": "Room 1",
        "room": "Room 1",
        "archived": False,
        "inventoryState": "checked_out",
        "lastSeen": NOW.isoformat(),
        "collectedAt": (NOW - timedelta(hours=2)).isoformat(),
        "hasSecurity": True,
        **extra,
    }


WINDOWS_CVE = {
    "cve": "CVE-2026-10001",
    "url": "https://example.com/CVE-2026-10001",
    "source": "msrc",
    "status": "Unpatched",
    "severity": "Important",
    "kbArticle": "KB1000001",
    "osVersion": "10.0.26200",
    "description": "Example Security Update (KB1000001)",
    "patchedVersion": "KB1000001",
    "activelyExploited": False,
}
WINDOWS_PENDING = {
    "cve": "Pending Security Update",
    "url": "https://example.com/help/1000002",
    "source": "msrc",
    "status": "Unpatched",
    "severity": "Unknown",
    "kbArticle": "KB1000002",
    "osVersion": "10.0.26200",
    "description": "Example .NET Security Update (KB1000002)",
    "patchedVersion": "KB1000002",
    "activelyExploited": False,
}
MAC_CVE = {
    "cve": "CVE-2026-10001",
    "url": "https://example.com/feed.json",
    "os_version": "26.1",
    "patched_version": "26.7.2",
    "actively_exploited": "true",
}

ROWS = [
    _device(
        "TESTSERIAL01",
        "Windows 11",
        windowsCves=[WINDOWS_CVE, WINDOWS_PENDING],
        macCves=None,
    ),
    _device("TESTSERIAL02", "macOS", windowsCves=None, macCves=[MAC_CVE]),
    _device("TESTSERIAL03", "macOS", windowsCves=None, macCves=None, hasSecurity=False),
]


@pytest.fixture
def loaded(monkeypatch):
    data = {
        "vulnerabilities": ROWS,
        "detections": [
            _device(
                "TESTSERIAL01",
                "Windows 11",
                detections=[
                    {
                        "source": "WindowsDefender",
                        "status": "Blocked",
                        "category": "ASR Rule",
                        "severity": "Moderate",
                        "threatName": "Example rule",
                        "filePath": "C:\\Example\\app.exe",
                        "detectedAt": (NOW - timedelta(days=2)).isoformat(),
                        "count": 3,
                    },
                    {
                        "source": "WindowsDefender",
                        "status": "Quarantined",
                        "category": "Malware",
                        "severity": "Severe",
                        "threatName": "Example threat",
                        "filePath": "C:\\Example\\old.exe",
                        "detectedAt": (NOW - timedelta(days=40)).isoformat(),
                    },
                    {
                        "source": "OtherVendor",
                        "status": "Blocked",
                        "threatName": "Undated",
                        "detectedAt": "not a time",
                    },
                ],
            ),
            _device("TESTSERIAL02", "macOS", detections=None),
        ],
    }
    monkeypatch.setattr(report, "_load", lambda kind, platform, archived: data[kind])
    return TestClient(app)


def test_cve_ids_are_only_real_cve_identifiers():
    assert cve_id("cve-2026-10001") == "CVE-2026-10001"
    assert cve_id("Pending Security Update") is None
    assert cve_id(None) is None


@pytest.mark.parametrize(
    "raw,expected",
    [
        (True, True),
        ("true", True),
        ("1", True),
        (False, False),
        ("false", False),
        (None, None),
        ("", None),
        ("maybe", None),
    ],
)
def test_exploited_flag_keeps_unknown(raw, expected):
    assert exploited_flag(raw) is expected


def test_windows_entry_keeps_collected_severity_and_status():
    entry = normalize_cve(WINDOWS_CVE, "windows")
    assert entry["identifier"] == "CVE-2026-10001"
    assert (
        entry["status"],
        entry["severity"],
        entry["fixedIn"],
        entry["affectedVersion"],
    ) == ("unpatched", "Important", "KB1000001", "10.0.26200")
    assert entry["activelyExploited"] is False


def test_pending_update_is_identified_by_its_update_not_a_cve():
    entry = normalize_cve(WINDOWS_PENDING, "windows")
    assert entry["cve"] is None and entry["identifier"] == "KB1000002"
    assert entry["severity"] is None


def test_mac_entry_has_no_invented_severity():
    entry = normalize_cve(MAC_CVE, "mac")
    assert entry["severity"] is None
    assert (entry["status"], entry["product"], entry["fixedIn"], entry["source"]) == (
        "unpatched",
        "macOS",
        "26.7.2",
        "SOFA",
    )
    assert entry["activelyExploited"] is True


def test_malformed_entries_are_skipped():
    assert normalize_cve("CVE-2026-1", "windows") is None
    assert normalize_cve({}, "mac") is None
    assert normalize_detection(None) is None


def test_summary_counts_distinct_devices_and_exploitation():
    pairs = [
        (
            {"serialNumber": "A", "platform": "Windows"},
            normalize_cve(WINDOWS_CVE, "windows"),
        ),
        (
            {"serialNumber": "A", "platform": "Windows"},
            normalize_cve(WINDOWS_CVE, "windows"),
        ),
        ({"serialNumber": "B", "platform": "macOS"}, normalize_cve(MAC_CVE, "mac")),
    ]
    [group] = summarize_cves(pairs)
    assert group["devices"] == 2 and group["unpatchedDevices"] == 2
    assert group["activelyExploited"] is True
    assert group["severities"] == ["Important"] and group["platforms"] == ["macOS", "Windows"]


def test_device_rows_and_coverage(loaded):
    body = loaded.get("/api/v1/security/vulnerabilities", headers=HEADERS).json()
    assert body["total"] == 3
    assert body["coverage"] == {
        "devices": 3,
        "reporting": 2,
        "notReporting": 1,
        "listMayBeIncomplete": 0,
    }
    assert {row["serialNumber"] for row in body["rows"]} == {
        "TESTSERIAL01",
        "TESTSERIAL02",
    }


def test_filters_apply_before_paging(loaded):
    body = loaded.get(
        "/api/v1/security/vulnerabilities", params={"exploited": "yes"}, headers=HEADERS
    ).json()
    assert [row["serialNumber"] for row in body["rows"]] == ["TESTSERIAL02"]
    body = loaded.get(
        "/api/v1/security/vulnerabilities",
        params={"severities": "not_reported"},
        headers=HEADERS,
    ).json()
    assert {row["identifier"] for row in body["rows"]} == {
        "KB1000002",
        "CVE-2026-10001",
    }
    body = loaded.get(
        "/api/v1/security/vulnerabilities",
        params={"cves": '["CVE-2026-10001"]', "limit": 1, "offset": 1},
        headers=HEADERS,
    ).json()
    assert body["total"] == 2 and len(body["rows"]) == 1


def test_summary_view(loaded):
    body = loaded.get(
        "/api/v1/security/vulnerabilities", params={"view": "summary"}, headers=HEADERS
    ).json()
    assert [(g["identifier"], g["devices"]) for g in body["cves"]] == [
        ("CVE-2026-10001", 2),
        ("KB1000002", 1),
    ]


def test_vulnerability_options(loaded):
    body = loaded.get(
        "/api/v1/security/vulnerabilities/filters", headers=HEADERS
    ).json()
    assert {c["identifier"] for c in body["cves"]} == {"CVE-2026-10001", "KB1000002"}
    assert {s["value"] for s in body["severities"]} == {"Important", "not_reported"}


def test_detection_window_excludes_undated_rows(loaded):
    body = loaded.get(
        "/api/v1/security/detections", params={"days": 7}, headers=HEADERS
    ).json()
    assert [row["threatName"] for row in body["rows"]] == ["Example rule"]
    assert body["coverage"] == {
        "devices": 2,
        "reporting": 1,
        "notReporting": 1,
        "devicesWithDetections": 1,
    }
    body = loaded.get("/api/v1/security/detections", headers=HEADERS).json()
    assert body["total"] == 3
    assert body["rows"][0]["path"] == "C:\\Example\\app.exe"


def test_detection_vendor_filter_and_options(loaded):
    body = loaded.get(
        "/api/v1/security/detections",
        params={"vendors": "othervendor"},
        headers=HEADERS,
    ).json()
    assert [row["threatName"] for row in body["rows"]] == ["Undated"]
    options = loaded.get("/api/v1/security/detections/filters", headers=HEADERS).json()
    assert [v["value"] for v in options["vendors"]] == [
        "OtherVendor",
        "WindowsDefender",
    ]
    assert {v["value"] for v in options["categories"]} == {
        "ASR Rule",
        "Malware",
        "not_reported",
    }


def test_window_never_assumes_recent():
    since = NOW - timedelta(days=1)
    assert within_window({"lastSeenAt": None, "detectedAt": None}, since) is False
    assert within_window({"lastSeenAt": None, "detectedAt": None}, None) is True


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/security/vulnerabilities",
        "/api/v1/security/vulnerabilities/filters",
        "/api/v1/security/detections",
        "/api/v1/security/detections/filters",
    ],
)
def test_reports_require_authentication(path):
    assert TestClient(app).get(path).status_code == 401


@pytest.mark.parametrize(
    "query",
    [
        "statuses=fixed",
        "exploited=maybe",
        "platform=invalid",
        "limit=5001",
        "view=table",
        "cves=[1]",
        "maxAgeHours=0",
    ],
)
def test_invalid_vulnerability_queries_fail_before_the_database(query):
    assert (
        TestClient(app)
        .get(f"/api/v1/security/vulnerabilities?{query}", headers=HEADERS)
        .status_code
        == 422
    )


@pytest.mark.parametrize("query", ["days=-1", "platform=invalid", "offset=-1"])
def test_invalid_detection_queries_fail_before_the_database(query):
    assert (
        TestClient(app)
        .get(f"/api/v1/security/detections?{query}", headers=HEADERS)
        .status_code
        == 422
    )
