"""GET /api/v1/dashboard/insights without a database.

The card queries run against Postgres in test_dashboard_insights_sql.py. These
pin what Python owns: the card shapes and their deep links, the OS Currency
five-device rule, error isolation between cards, and the cache (fresh, stale
while refreshing, and one computation for any number of concurrent callers).
"""

import asyncio
import threading
import time

import pytest
from fastapi.testclient import TestClient

import dashboard_insights as di
from routers import insights as insights_router

AUTH = {"X-Client-Passphrase": "test-passphrase"}


# ── Links ───────────────────────────────────────────────────────


def test_link_params_are_strings_and_drop_none():
    assert di.link("/system", uptime="30d+", deferred=1, skip=None) == {
        "path": "/system",
        "params": {"uptime": "30d+", "deferred": "1"},
    }


def test_device_and_app_links_encode_the_path():
    assert di.device_link("SAMPLE 1/2")["path"] == "/device/SAMPLE%201%2F2"
    assert di.app_usage_link("Adobe Photoshop 2026") == {
        "path": "/applications/usage/Adobe%20Photoshop%202026",
        "params": {"days": "30"},
    }
    assert di.app_usage_link("SAMPLE", 7, ["Shared", "Lab"], ["Staff"], "macOS")["params"] == {
        "days": "7", "usages": "Shared,Lab", "catalogs": "Staff", "platform": "macOS",
    }


def test_platform_normalization():
    assert di.normalize_platform(None) == "all"
    assert di.normalize_platform("MACOS") == "macOS"
    assert di.normalize_platform("windows") == "Windows"
    assert di.normalize_platform("linux") is None


# ── Card shaping ────────────────────────────────────────────────


def test_reboot_debt_shape_and_links():
    card = di.shape_reboot_debt(
        {
            "devices": 9,
            "up_lt1d": 1,
            "up_1_3d": 2,
            "up_3_7d": 0,
            "up_1_2w": 1,
            "up_2_4w": 3,
            "up_30d": 2,
            "pending": 4,
            "deferred": 1,
        }
    )
    assert card["uptime30dPlus"] == {
        "count": 2,
        "link": {"path": "/system", "params": {"uptime": "30d+"}},
    }
    assert card["uptime2to4w"]["link"]["params"] == {"uptime": "2-4w"}
    assert card["pendingUpdates"]["link"]["params"] == {"pending": "1-5,6-10,10+"}
    assert card["deferredUpdates"]["link"]["params"] == {"deferred": "1"}
    assert [b["key"] for b in card["uptimeBuckets"]] == [
        "lt1d",
        "1-3d",
        "3-7d",
        "1-2w",
        "2-4w",
        "30d+",
    ]


def test_protection_gaps_worst_first_and_ineligible_rows_dropped():
    card = di.shape_protection_gaps(
        {
            "devices": 10,
            "encryption_off": 1,
            "firewall_off": 4,
            "antivirus_total": 0,
            "antivirus_off": 0,
            "sip_total": 6,
            "sip_off": 4,
            "secure_boot_total": 4,
            "secure_boot_off": 2,
            "with_threats": 1,
            "critical_cves": 3,
        }
    )
    assert [g["key"] for g in card["gaps"]] == [
        "firewall",
        "sip",
        "secureBoot",
        "encryption",
    ]
    assert card["gaps"][0]["link"] == {
        "path": "/security",
        "params": {"firewall": "off"},
    }
    assert card["gaps"][2]["link"]["params"] == {"secureBoot": "off"}
    assert card["withThreats"]["link"]["params"] == {"threats": "1"}
    assert card["criticalCves"]["link"]["params"] == {"cve": "critical"}


def test_checkin_gaps_reasons_and_links():
    card = di.shape_checkin_gaps(
        (5, 2, 1),
        [
            {"reason": "invalid_passphrase", "count": 3, "devices": 2},
            {"reason": "malformed_json", "count": 4, "devices": 1},
        ],
        {"stale": 2, "missing": 7},
    )
    assert [r["reason"] for r in card["reasons"]] == [
        "malformed_json",
        "invalid_passphrase",
    ]
    assert card["reasons"][0]["link"] == {
        "path": "/events/failures",
        "params": {"hours": "24", "reason": "malformed_json"},
    }
    assert card["retried"]["link"]["params"] == {"hours": "24", "outcome": "retried"}
    assert card["stale"]["link"] == {"path": "/devices", "params": {"status": "stale"}}
    assert card["missing"]["link"] == {
        "path": "/devices",
        "params": {"status": "missing"},
    }


def test_certificates_soonest_link():
    card = di.shape_certificates(
        {
            "devices": 4,
            "expiring_certs": 3,
            "expiring_devices": 2,
            "expired_user_devices": 1,
        },
        [{"cn": "SAMPLE Wi-Fi", "days": 4.6, "devices": 2}],
    )
    assert card["soonest"][0]["daysUntilExpiry"] == 5
    assert card["soonest"][0]["link"]["params"] == {
        "certSearch": "SAMPLE Wi-Fi",
        "certStatus": "expiring",
    }
    assert card["expiring"]["link"]["params"] == {"certs": "expiring"}
    assert card["expiredUser"]["link"]["params"] == {"certs": "expired"}


def test_connectivity_links():
    card = di.shape_connectivity(
        {
            "devices": 5,
            "weak_signal": 2,
            "poor_quality": 1,
            "quality_measured": 3,
            "on_vpn": 1,
        }
    )
    assert card["weakSignal"]["link"] == {
        "path": "/network",
        "params": {"signal": "weak"},
    }
    assert card["poorQuality"]["measured"] == 3
    assert card["poorQuality"]["link"] == {
        "path": "/network",
        "params": {"quality": "poor"},
    }
    assert card["onVpn"]["link"] == {"path": "/network", "params": {"vpn": "1"}}


def test_install_health_splits_agents_and_links_carry_them():
    counts = {"munki_devices": 4, "cimian_devices": 3, "munki_with_errors": 2, "munki_with_warnings": 1,
              "cimian_with_errors": 1, "cimian_with_warnings": 0, "munki_error_items": 5,
              "munki_warning_items": 1, "cimian_error_items": 2, "cimian_warning_items": 0}
    card = di.shape_install_health(counts, [{"name": "SAMPLE App", "devices": 2}],
                                   {"munki": 1, "cimian": 2}, [{"agent": "cimian", "items": 4, "devices": 2}])
    assert (card["devices"], card["withErrors"]["count"], card["errorItems"]["count"]) == (7, 3, 7)
    assert (card["pending"]["items"], card["silentAgents"]["count"]) == (4, 3)
    assert card["withErrors"]["link"] == {"path": "/installs", "params": {"filter": "errors"}}
    assert card["silentAgents"]["link"]["params"] == {"stale": "1"}
    assert card["topFailing"][0]["link"]["params"] == {"item": "SAMPLE App", "filter": "errors"}
    cimian = card["byAgent"][1]
    assert (cimian["name"], cimian["platform"]) == ("Cimian", "Windows")
    assert cimian["silentAgents"]["link"]["params"] == {"stale": "1", "agent": "cimian"}
    assert cimian["warningItems"]["link"]["params"] == {"filter": "warnings", "agent": "cimian"}
    only_mac = di.shape_install_health(counts, [], {}, [], "macOS")
    assert [a["agent"] for a in only_mac["byAgent"]] == ["munki"]


def test_silent_agents_counted_per_agent():
    from datetime import datetime, timedelta, timezone

    seen = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
    rows = [
        {"has_cimian": True, "cimian_sessions": [{"end_time": (seen - timedelta(days=9)).isoformat()}],
         "cimian_run": {}, "last_seen": seen},
        {"has_munki": True, "munki_sessions": None,
         "munki_run": {"endTime": (seen - timedelta(days=2)).isoformat()}, "last_seen": seen},
        {"has_munki": True, "munki_sessions": [], "munki_run": {"startTime": None}, "last_seen": seen},
    ]
    assert di.silent_agent_counts(rows) == {"munki": 0, "cimian": 1}


def test_storage_buckets_and_links():
    rows = [{"platform": "macOS", "devices": 3, "free_lt5": 1, "free_5_10": 1, "free_10_20": 0, "free_20_plus": 1,
             "cap_le256": 1, "cap_512": 2, "cap_1t": 0, "cap_2t_plus": 0}]
    card = di.shape_storage(rows, [{"serial": "SAMPLE1", "name": None, "platform": "macOS",
                                    "total_bytes": 1000, "free_bytes": 20, "free_ratio": 0.02}])
    assert [b["link"]["params"]["storage"] for b in card["freeSpace"]] == ["lt5", "5-10", "10-20", "20+"]
    assert card["lowStorage"]["count"] == 2
    assert card["lowStorage"]["byPlatform"] == [{"platform": "macOS", "count": 2,
        "link": {"path": "/hardware", "params": {"storage": "low", "platform": "macOS"}}}]
    assert [c["link"]["params"]["capacity"] for c in card["capacity"]] == ["le256", "512", "1t", "2t+"]
    assert card["fullest"][0] == {"serialNumber": "SAMPLE1", "name": "SAMPLE1", "platform": "macOS", "freePct": 2.0,
                                  "freeBytes": 20, "totalBytes": 1000, "link": {"path": "/device/SAMPLE1", "params": {}}}


def test_directory_join_views():
    rows = [
        {"platform": "Windows", "devices": 4, "entra": 1, "domain": 1, "hybrid": 1, "workgroup": 1,
         "mac_psso": 0, "mac_bound": 0, "mac_unbound": 0, "extra_admins": 2, "shared": 1, "assigned": 3},
        {"platform": "macOS", "devices": 3, "entra": 0, "domain": 1, "hybrid": 0, "workgroup": 2,
         "mac_psso": 1, "mac_bound": 1, "mac_unbound": 1, "extra_admins": 1, "shared": 0, "assigned": 3},
    ]
    views = di.shape_directory_join(rows)["views"]
    assert set(views) == {"all", "windows", "mac"}
    assert {s["key"]: s["count"] for s in views["all"]["segments"]}["workgroup"] == 3
    assert [s["key"] for s in views["mac"]["segments"]] == ["psso", "bound", "unbound"]
    assert views["mac"]["segments"][1]["link"] == {"path": "/identity",
                                                   "params": {"directory": "bound", "platform": "macOS"}}
    assert views["windows"]["segments"][0]["link"]["params"] == {"join": "entra", "platform": "Windows"}
    assert views["all"]["extraAdmins"] == {"count": 3, "link": {"path": "/identity", "params": {"admins": "extra"}}}
    assert views["windows"]["assigned"]["link"]["params"] == {"usage": "assigned", "platform": "Windows"}


def test_management_tools_products_merge_and_links():
    rows = [
        {"tool": "installs", "platform": "macOS", "mdm_name": None, "devices": 5, "devices_with_errors": 2,
         "devices_with_warnings": 1, "error_lines": 9, "warning_lines": 1},
        {"tool": "installs", "platform": "Windows", "mdm_name": None, "devices": 3, "devices_with_errors": 1,
         "devices_with_warnings": 0, "error_lines": 1, "warning_lines": 0},
        {"tool": "bootstrap", "platform": "macOS", "mdm_name": None, "devices": 5, "devices_with_errors": 1,
         "devices_with_warnings": 0, "error_lines": 2, "warning_lines": 0},
        {"tool": "bootstrap", "platform": "Windows", "mdm_name": None, "devices": 3, "devices_with_errors": 1,
         "devices_with_warnings": 0, "error_lines": 1, "warning_lines": 0},
        {"tool": "mdm", "platform": "Windows", "mdm_name": "Intune", "devices": 3, "devices_with_errors": 0,
         "devices_with_warnings": 0, "error_lines": 0, "warning_lines": 0},
    ]
    messages = [{"message": "Download of <n> failed", "tool": "installs", "platform": "macOS", "mdm_name": None,
                 "devices": 2, "lines": 4, "sample_serial": "SAMPLE1"}]
    card = di.shape_management_tools(rows, messages)
    names = [t["name"] for t in card["tools"]]
    assert names == ["Munki", "BootstrapMate", "Cimian", "Intune"]
    boot = card["tools"][1]
    assert (boot["devices"], boot["devicesWithErrors"], boot["platform"]) == (8, 2, None)
    assert boot["link"] == {"path": "/devices", "params": {"tool": "bootstrap", "level": "error"}}
    assert card["tools"][0]["link"]["params"] == {"tool": "installs", "level": "error", "platform": "macOS"}
    assert card["tools"][0]["warningsLink"]["params"]["level"] == "warning"
    top = card["topErrors"][0]
    assert (top["name"], top["devices"]) == ("Munki", 2)
    assert top["sampleDevice"]["link"] == {"path": "/device/SAMPLE1",
                                           "params": {"tab": "management", "tool": "installs", "level": "error"}}


def test_tool_window_start_is_an_hour_key():
    from datetime import datetime, timezone

    assert di.window_start_hour(datetime(2026, 10, 22, 13, 44, tzinfo=timezone.utc)) == "2026-10-21T13"


def test_app_usage_top_ten_and_filter_links():
    usage = [{"app": f"SAMPLE {i}", "total_seconds": 3600 * i, "active_seconds": 0,
              "device_count": 1, "active_device_count": 1} for i in range(1, 13)]
    options = [{"kind": "usage", "value": "Shared", "devices": 3}, {"kind": "catalog", "value": "Lab", "devices": 2}]
    card = di.shape_app_usage(usage, options, platform="Windows", days=30, usages=["Shared"], catalogs=[])
    assert len(card["apps"]) == 10
    assert card["apps"][0]["name"] == "SAMPLE 12"
    assert card["apps"][0]["link"]["params"] == {"days": "30", "usages": "Shared", "platform": "Windows"}
    assert card["available"] == {"usages": [{"value": "Shared", "devices": 3}],
                                 "catalogs": [{"value": "Lab", "devices": 2}]}
    assert card["link"]["params"] == {"type": "usage", "period": "30", "usages": "Shared", "platform": "Windows"}


# ── OS Currency: the five-device rule ───────────────────────────


def mac(version, devices):
    return di.OSRow("macOS", "macOS", version, "", "", devices)


def win(name, build, ubr, devices):
    return di.OSRow("Windows", f"{name} Enterprise", "", build, ubr, devices)


def test_one_beta_mac_does_not_put_the_fleet_behind():
    card = di.os_currency([mac("26.3.1", 5), mac("26.4", 1)])
    assert card["rated"] == 6
    assert card["behind"]["count"] == 0
    assert card["pctOnLatest"] == 100


def test_without_five_devices_the_highest_version_seen_is_latest():
    card = di.os_currency([mac("26.3.1", 4), mac("26.4", 1)])
    assert card["behind"]["count"] == 4
    assert card["lagging"] == [
        {
            "version": "26.3.1",
            "label": "macOS 26.3.1",
            "devices": 4,
            "link": {"path": "/system", "params": {"osVersion": "26.3.1"}},
        }
    ]


def test_five_devices_on_a_newer_patch_set_the_bar():
    card = di.os_currency([mac("26.3.1", 7), mac("26.4", 5)])
    assert card["behind"]["count"] == 7
    assert card["behind"]["link"] == {"path": "/system", "params": {"patch": "behind"}}


def test_unsupported_counts_majors_in_release_order():
    rows = [mac("26.3", 5), mac("15.7", 1), mac("14.8", 1), mac("13.7", 1)]
    card = di.os_currency(rows)
    # 26 follows 15, so two majors behind 26 is 14: only 13 is unsupported.
    assert card["unsupportedMac"]["count"] == 1
    assert card["unsupportedMac"]["link"]["params"] == {"os": "unsupported"}


def test_unsupported_bar_ignores_a_major_below_five_devices():
    card = di.os_currency(
        [mac("27.0", 1), mac("26.3", 5), mac("15.7", 1), mac("14.8", 1)]
    )
    assert card["unsupportedMac"]["count"] == 0


def test_windows_trains_by_build_and_windows10():
    rows = [
        win("Windows 11", "26100", "4000", 5),
        win("Windows 11", "26100", "3000", 2),
        win("Windows 10", "19045", "5000", 1),
    ]
    card = di.os_currency(rows)
    assert card["behind"]["count"] == 2
    assert card["windows10"] == {
        "count": 1,
        "link": {"path": "/system", "params": {"os": "windows10"}},
    }
    assert card["lagging"][0]["version"] == "11.26100"
    assert card["lagging"][0]["label"] == "Windows 11 build 26100"


def test_platform_filter_counts_only_that_platform_but_rules_use_the_fleet():
    rows = [mac("26.3.1", 5), mac("26.2", 1), win("Windows 11", "26100", "4000", 3)]
    card = di.os_currency(rows, "macOS")
    assert (card["devices"], card["rated"], card["behind"]["count"]) == (6, 6, 1)


def test_version_parsing():
    assert di.version_parts("26.3.1 (a)") == [26, 3, 1]
    assert di.version_parts("") == []
    assert di.OSRow("macOS", "macOS", "26.3.1 (a)", "", "", 1).version_key() == "26.3.1"


# ── Error isolation ─────────────────────────────────────────────


class FakeCursor:
    description = [("x",)]

    def execute(self, *_a, **_k):
        pass

    def fetchall(self):
        return []


class FakeConnection:
    def cursor(self):
        return FakeCursor()

    def rollback(self):
        pass

    def close(self):
        pass


def test_a_failing_card_does_not_take_the_others_down(monkeypatch):
    monkeypatch.setattr(di, "get_db_connection", lambda: FakeConnection())
    monkeypatch.setattr(di, "_has_inventory_state_table", lambda: True)

    def ok(run, scope, **_):
        return {"devices": 1}

    def boom(run, scope, **_):
        raise RuntimeError('relation "security" does not exist SELECT secret FROM ...')

    def slow(run, scope, **_):
        raise RuntimeError(
            "ERROR: canceling statement due to statement timeout (57014)"
        )

    funcs = {key: ok for key in di.CARD_KEYS}
    funcs["protectionGaps"] = boom
    funcs["osCurrency"] = slow
    monkeypatch.setattr(di, "CARD_FUNCTIONS", funcs)

    result = di.compute_insights("all", False)
    assert all(c.pop("generatedAt") and "computeSeconds" in c for c in result["cards"].values())
    cards = {k: {f: v for f, v in c.items() if f != "computeSeconds"} for k, c in result["cards"].items()}
    assert list(cards) == list(di.CARD_KEYS)
    assert cards["protectionGaps"] == {"error": "Could not compute this card"}
    assert cards["osCurrency"]["error"].startswith("Timed out after")
    assert all(
        cards[k] == {"devices": 1}
        for k in di.CARD_KEYS
        if k not in ("protectionGaps", "osCurrency")
    )
    assert "secret" not in str(cards)


def test_no_database_fails_every_card_but_still_answers(monkeypatch):
    def down():
        raise RuntimeError("Database connection failed")

    monkeypatch.setattr(di, "get_db_connection", down)
    monkeypatch.setattr(di, "_inventory_state_checked", None)
    result = di.compute_insights("all", False)
    assert all(v["error"] == "Database unavailable" for v in result["cards"].values())


# ── Log level summaries (stamped at ingest) ─────────────────────


def test_parse_line_shapes():
    from log_tails import parse_line

    cases = {
        "[2026-10-22 13:44:00] ERROR  boom": ("2026-10-22T13", "error"),
        "[2026-10-22 13:44:00] INFO  mentions CRITICAL": ("2026-10-22T13", "info"),
        "Oct 22 2026 13:44:00 -0700 WARNING: slow": ("2026-10-22T20", "warning"),
        "2026-10-22 13:44:00:123 | IntuneMdmAgent | E | 7 | x | failed": ("2026-10-22T13", "error"),
        '<![LOG[step failed]LOG]!><time="13:44:00.000+000" date="10-22-2026" component="c" context="" type="3" thread="1" file="">':
            ("2026-10-22T13", "error"),
        "2026-10-22T13:44:00Z something WARN here": ("2026-10-22T13", "warning"),
        "no time but ERROR": (None, "error"),
    }
    for line, (hour, level) in cases.items():
        when, got = parse_line(line)
        assert (when.strftime("%Y-%m-%dT%H") if when else None, got) == (hour, level), line
    when, level = parse_line('{"timestamp": "2026-10-22T13:44:00Z", "level": "error", "message": "x"}', jsonl=True)
    assert (when.hour, level) == (13, "error")


def test_summarize_root_counts_hours_messages_and_is_deterministic():
    import copy

    from log_tails import stamp_log_summaries, summarize_root

    root = {"tool": "installs", "newestModified": "2026-10-22T15:00:00Z", "tails": [
        {"file": "run.log", "lines": [
            "[2026-10-22 13:01:00] ERROR  Download of SAMPLE failed: 404 at /Library/ManagedInstalls/x.pkg",
            "[2026-10-22 13:02:00] ERROR  Download of SAMPLE failed: 500 at /Library/ManagedInstalls/y.pkg",
            "[2026-10-22 14:00:00] WARN  slow",
            "plain undated ERROR line",
            "[2026-10-22 14:05:00] INFO  fine",
        ]},
        {"file": "state.json", "lines": ["{\"error\": \"ignored\"}"]},
    ]}
    summary = summarize_root(root)
    assert summary["hours"] == {"2026-10-22T13": [2, 0], "2026-10-22T14": [0, 1], "2026-10-22T15": [1, 0]}
    assert summary["undated"] == [0, 0]
    top = summary["errors"][0]
    assert top["n"] == 2 and top["last"] == "2026-10-22T13"
    assert "<path>" in top["m"] and "404" not in top["m"]

    module = {"logs": {"roots": [copy.deepcopy(root)]}}
    again = {"logs": {"roots": [copy.deepcopy(root)]}}
    assert stamp_log_summaries(module) == stamp_log_summaries(again)
    assert module["logs"]["roots"][0]["levelSummary"] == summary


# ── Endpoints and cache ─────────────────────────────────────────


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(insights_router, "BACKGROUND_REFRESH", False)
    insights_router.reset_cache()
    from main import app

    with TestClient(app) as c:
        yield c
    insights_router.reset_cache()


def fake_card(card, platform="all", include_archived=False, error=False):
    if error:
        return {"error": "Could not compute this card", "generatedAt": "2026-10-22T00:00:00+00:00"}
    return {"devices": 1, "card": card, "platform": platform, "generatedAt": "2026-10-22T00:00:00+00:00"}


@pytest.fixture
def calls(monkeypatch):
    seen = []

    def compute(card, platform, include_archived):
        seen.append((card, platform, include_archived))
        return fake_card(card, platform, include_archived)

    def app_usage(platform, usages, catalogs, days):
        seen.append(("appUsage", platform, usages, catalogs, days))
        return {"apps": [], "generatedAt": "2026-10-22T00:00:00+00:00"}

    monkeypatch.setattr(di, "compute_card", compute)
    monkeypatch.setattr(di, "compute_app_usage", app_usage)
    return seen


def test_endpoints_require_auth(client):
    assert client.get("/api/v1/dashboard/insights").status_code == 401
    assert client.get("/api/v1/dashboard/insights/storage").status_code == 401
    assert client.get("/api/v1/dashboard/insights/appUsage").status_code == 401


def test_unknown_platform_and_card(client, calls):
    assert client.get("/api/v1/dashboard/insights?platform=linux", headers=AUTH).status_code == 422
    assert client.get("/api/v1/dashboard/insights/storage?platform=linux", headers=AUTH).status_code == 422
    assert client.get("/api/v1/dashboard/insights/unmanagedDevices", headers=AUTH).status_code == 404


def test_per_card_endpoint_envelope_and_cache(client, calls):
    r = client.get("/api/v1/dashboard/insights/storage?platform=windows", headers=AUTH)
    assert r.status_code == 200
    assert r.headers["X-Insights-Cache"] == "miss"
    body = r.json()
    assert body == {"card": "storage", "platform": "Windows", "includeArchived": False,
                    "generatedAt": "2026-10-22T00:00:00+00:00", "data": fake_card("storage", "Windows")}
    r = client.get("/api/v1/dashboard/insights/storage?platform=Windows", headers=AUTH)
    assert r.headers["X-Insights-Cache"] == "fresh"
    assert calls == [("storage", "Windows", False)]


def test_per_card_etag_answers_304(client, calls):
    r = client.get("/api/v1/dashboard/insights/osCurrency", headers=AUTH)
    etag = r.headers["ETag"]
    r = client.get("/api/v1/dashboard/insights/osCurrency", headers={**AUTH, "If-None-Match": etag})
    assert r.status_code == 304
    assert r.content == b""


def test_combined_is_assembled_from_the_per_card_cache(client, calls):
    client.get("/api/v1/dashboard/insights/storage", headers=AUTH)
    r = client.get("/api/v1/dashboard/insights", headers=AUTH)
    body = r.json()
    assert list(body["cards"]) == list(di.CARD_KEYS)
    assert body["cards"]["storage"]["generatedAt"]
    assert sorted(calls) == sorted((card, "all", False) for card in di.CARD_KEYS)
    r = client.get("/api/v1/dashboard/insights", headers=AUTH)
    assert r.headers["X-Insights-Cache"] == "fresh"
    assert len(calls) == len(di.CARD_KEYS)
    r = client.get("/api/v1/dashboard/insights/protectionGaps", headers=AUTH)
    assert r.headers["X-Insights-Cache"] == "fresh"


def test_app_usage_is_cached_per_filter_combination(client, calls):
    client.get("/api/v1/dashboard/insights/appUsage?usages=Shared,Lab", headers=AUTH)
    r = client.get("/api/v1/dashboard/insights/app-usage?usages=Lab,%20Shared", headers=AUTH)
    assert r.headers["X-Insights-Cache"] == "fresh"
    assert r.json()["card"] == "appUsage"
    client.get("/api/v1/dashboard/insights/appUsage?catalogs=Staff&days=7", headers=AUTH)
    assert calls == [("appUsage", "all", ("Lab", "Shared"), (), 30), ("appUsage", "all", (), ("Staff",), 7)]


def test_expired_card_is_served_while_one_refresh_runs(client, calls):
    client.get("/api/v1/dashboard/insights/storage", headers=AUTH)
    key = ("storage", "all", False)
    result, _stored = insights_router._entries[key]
    insights_router._entries[key] = (result, time.monotonic() - 10_000)

    r = client.get("/api/v1/dashboard/insights/storage", headers=AUTH)
    assert r.headers["X-Insights-Cache"] == "stale"
    assert int(r.headers["Age"]) >= 10_000
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        r = client.get("/api/v1/dashboard/insights/storage", headers=AUTH)
        if r.headers["X-Insights-Cache"] == "fresh":
            break
        time.sleep(0.01)
    assert r.headers["X-Insights-Cache"] == "fresh"
    assert calls.count(key) == 2


def test_a_failed_card_expires_sooner():
    assert insights_router._ttl_for(fake_card("x", error=True)) == insights_router.ERROR_TTL_SECONDS
    assert insights_router._ttl_for(fake_card("x")) == insights_router.CACHE_TTL_SECONDS


def test_concurrent_cold_requests_share_one_computation(monkeypatch):
    insights_router.reset_cache()
    seen = []
    release = threading.Event()

    def compute(card, platform, include_archived):
        seen.append(card)
        release.wait(5)
        return fake_card(card)

    monkeypatch.setattr(di, "compute_card", compute)

    async def scenario():
        waiters = [asyncio.create_task(insights_router.get_cached(("storage", "all", False))) for _ in range(8)]
        await asyncio.sleep(0.05)
        release.set()
        return await asyncio.gather(*waiters)

    results = asyncio.run(scenario())
    insights_router.reset_cache()
    assert seen == ["storage"]
    assert {state for _r, state, _age in results} == {"miss"}


def test_refresh_pass_fills_every_default_card_one_at_a_time(monkeypatch):
    insights_router.reset_cache()
    running, peak, seen = [0], [0], []

    def compute(card, platform, include_archived):
        running[0] += 1
        peak[0] = max(peak[0], running[0])
        seen.append((card, platform))
        running[0] -= 1
        return fake_card(card, platform)

    monkeypatch.setattr(di, "compute_card", compute)
    monkeypatch.setattr(di, "compute_app_usage", lambda *a: {"apps": [], "generatedAt": "x"})
    monkeypatch.setattr(insights_router, "REFRESH_STAGGER_SECONDS", 0)
    asyncio.run(insights_router.refresh_pass())
    assert peak[0] == 1
    assert len(seen) == 3 * len(di.CARD_KEYS)
    for platform in ("all", "macOS", "Windows"):
        assert ("appUsage", platform, (), (), 30) in insights_router._entries
        for card in di.CARD_KEYS:
            assert (card, platform, False) in insights_router._entries
    insights_router.reset_cache()


def test_tool_devices_shape():
    rows = [{"serial": "SAMPLE1", "name": None, "platform": "macOS", "lines": 4, "last_hour": "2026-10-22T13"}]
    out = di.shape_tool_devices(rows, tool="installs", level="warning", hours=24, platform="all")
    assert out == {"tool": "installs", "level": "warning", "hours": 24, "platform": "all", "devices": [{
        "serialNumber": "SAMPLE1", "deviceName": "SAMPLE1", "platform": "macOS", "count": 4,
        "lastAt": "2026-10-22T13:00:00Z",
        "link": {"path": "/device/SAMPLE1", "params": {"tab": "management", "tool": "installs", "level": "warning"}},
    }]}


def test_tool_devices_endpoint_validates_and_caches(client, monkeypatch):
    seen = []

    def compute(tool, level, hours, platform):
        seen.append((tool, level, hours, platform))
        return {"tool": tool, "level": level, "hours": hours, "platform": platform,
                "devices": [], "generatedAt": "2026-10-22T00:00:00+00:00"}

    monkeypatch.setattr(di, "compute_tool_devices", compute)
    url = "/api/v1/dashboard/insights/managementToolErrors/devices"
    assert client.get(f"{url}?tool=installs").status_code == 401
    assert client.get(url, headers=AUTH).status_code == 422
    assert client.get(f"{url}?tool=installs&level=info", headers=AUTH).status_code == 422
    assert client.get(f"{url}?tool=installs&hours=500", headers=AUTH).status_code == 422
    assert client.get(f"{url}?tool=x%20y", headers=AUTH).status_code == 422

    r = client.get(f"{url}?tool=Installs&level=warning&platform=macos", headers=AUTH)
    assert r.status_code == 200 and r.headers["X-Insights-Cache"] == "miss"
    assert r.json()["devices"] == []
    r = client.get(f"{url}?tool=installs&level=warning&platform=macOS", headers=AUTH)
    assert r.headers["X-Insights-Cache"] == "fresh"
    r2 = client.get(f"{url}?tool=installs&level=warning&platform=macOS",
                    headers={**AUTH, "If-None-Match": r.headers["ETag"]})
    assert r2.status_code == 304
    assert seen == [("installs", "warning", 24, "macOS")]
