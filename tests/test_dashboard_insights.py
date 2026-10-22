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


def test_unmanaged_percentages_round_like_javascript():
    rows = [
        {
            "platform": "macOS",
            "devices": 4,
            "unmanaged": 1,
            "seen_24h": 1,
            "seen_7d": 0,
            "silent": 0,
        },
        {
            "platform": "Windows",
            "devices": 4,
            "unmanaged": 0,
            "seen_24h": 0,
            "seen_7d": 0,
            "silent": 0,
        },
    ]
    card = di.shape_unmanaged(rows, [])
    assert card["unmanaged"]["pct"] == 13  # 12.5 rounds up, as Math.round does
    assert card["enrolledPct"] == 88
    assert card["unmanaged"]["link"] == {
        "path": "/management",
        "params": {"enrolled": "0"},
    }


def test_install_health_links():
    card = di.shape_install_health(
        {"devices": 3, "with_errors": 2, "with_warnings": 1},
        [{"name": "SAMPLE App", "devices": 2}],
        silent_agents=1,
    )
    assert card["withErrors"]["link"]["params"] == {"filter": "errors"}
    assert card["withWarnings"]["link"]["params"] == {"filter": "warnings"}
    assert card["topFailing"][0]["link"]["params"] == {
        "item": "SAMPLE App",
        "filter": "errors",
    }
    assert card["silentAgents"] == {
        "count": 1,
        "thresholdDays": 7,
        "link": {"path": "/installs", "params": {"stale": "1"}},
    }


def test_silent_agents_use_the_agent_the_device_runs():
    from datetime import datetime, timedelta, timezone

    seen = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
    rows = [
        {
            "has_cimian": True,
            "cimian_sessions": [{"end_time": (seen - timedelta(days=9)).isoformat()}],
            "cimian_run": {},
            "last_seen": seen,
        },
        {
            "has_munki": True,
            "munki_sessions": None,
            "munki_run": {"endTime": (seen - timedelta(days=2)).isoformat()},
            "last_seen": seen,
        },
        {
            "has_munki": True,
            "munki_sessions": [],
            "munki_run": {"startTime": None},
            "last_seen": seen,
        },
    ]
    assert di.silent_agent_count(rows) == 1


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


def test_local_admins_join_links():
    card = di.shape_local_admins(
        [
            {
                "platform": "macOS",
                "devices": 3,
                "extra_admins": 1,
                "admins_2": 1,
                "admins_3": 0,
                "admins_4_plus": 0,
                "entra": 0,
                "domain": 0,
                "hybrid": 0,
                "workgroup": 3,
            }
        ],
        [
            {
                "serial": "SAMPLE1",
                "name": "SAMPLE1-name",
                "platform": "macOS",
                "admins": 2,
            }
        ],
    )
    assert card["extraAdmins"]["link"]["params"] == {"admins": "extra"}
    assert {j["key"]: j["link"]["params"]["join"] for j in card["join"]} == {
        "entra": "entra",
        "domain": "domain",
        "hybrid": "hybrid",
        "workgroup": "workgroup",
    }
    assert card["workgroup"]["byPlatform"] == [{"platform": "macOS", "count": 3}]
    assert card["topDevices"][0]["link"] == {"path": "/device/SAMPLE1", "params": {}}


def test_unused_software_needs_the_install_floor():
    usage = [
        {
            "app": "Shelfware",
            "key": "shelfware",
            "total_seconds": 3600,
            "active_seconds": 0,
            "device_count": 1,
            "active_device_count": 0,
        },
        {
            "app": "Popular",
            "key": "popular",
            "total_seconds": 360000,
            "active_seconds": 3600,
            "device_count": 40,
            "active_device_count": 40,
        },
        {
            "app": "Rare",
            "key": "rare",
            "total_seconds": 10,
            "active_seconds": 0,
            "device_count": 1,
            "active_device_count": 0,
        },
    ]
    card = di.shape_unused_software(usage, {"shelfware": 50, "popular": 50, "rare": 9})
    assert [a["name"] for a in card["leastUsed"]] == ["Shelfware", "Popular"]
    assert card["leastUsed"][0]["usageRate"] == 0.0
    assert [a["name"] for a in card["mostUsed"]] == ["Popular", "Shelfware", "Rare"]
    assert card["leastUsed"][0]["link"] == {
        "path": "/applications/usage/Shelfware",
        "params": {"days": "30"},
    }


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
    cards = result["cards"]
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
    result = di.compute_insights("all", False)
    assert all(v == {"error": "Database unavailable"} for v in result["cards"].values())


# ── Endpoint and cache ──────────────────────────────────────────


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(insights_router, "WARM_ON_STARTUP", False)
    insights_router.reset_cache()
    from main import app

    with TestClient(app) as c:
        yield c
    insights_router.reset_cache()


def fake_result(platform, include_archived, error=False):
    cards = {k: {"devices": 1} for k in di.CARD_KEYS}
    if error:
        cards["softwareRisk"] = {"error": "Could not compute this card"}
    return {
        "generatedAt": "2026-10-22T00:00:00+00:00",
        "platform": platform,
        "includeArchived": include_archived,
        "computeSeconds": 0.0,
        "cards": cards,
    }


def test_endpoint_requires_auth(client):
    assert client.get("/api/v1/dashboard/insights").status_code == 401


def test_endpoint_rejects_an_unknown_platform(client):
    assert (
        client.get(
            "/api/v1/dashboard/insights?platform=linux", headers=AUTH
        ).status_code
        == 422
    )


def test_endpoint_shape_and_cache_per_scope(client, monkeypatch):
    calls = []

    def compute(platform, include_archived):
        calls.append((platform, include_archived))
        return fake_result(platform, include_archived)

    monkeypatch.setattr(di, "compute_insights", compute)

    r = client.get("/api/v1/dashboard/insights", headers=AUTH)
    assert r.status_code == 200
    assert r.headers["X-Insights-Cache"] == "miss"
    body = r.json()
    assert set(body) >= {"generatedAt", "platform", "cards"}
    assert list(body["cards"]) == list(di.CARD_KEYS)

    r = client.get("/api/v1/dashboard/insights?platform=all", headers=AUTH)
    assert r.headers["X-Insights-Cache"] == "fresh"

    r = client.get("/api/v1/dashboard/insights?platform=macos", headers=AUTH)
    assert r.json()["platform"] == "macOS"
    client.get("/api/v1/dashboard/insights?includeArchived=true", headers=AUTH)

    assert calls == [("all", False), ("macOS", False), ("all", True)]


def test_expired_value_is_served_while_one_refresh_runs(client, monkeypatch):
    calls = []

    def compute(platform, include_archived):
        calls.append(platform)
        return fake_result(platform, include_archived)

    monkeypatch.setattr(di, "compute_insights", compute)
    client.get("/api/v1/dashboard/insights", headers=AUTH)

    result, _stored = insights_router._entries[("all", False)]
    insights_router._entries[("all", False)] = (result, time.monotonic() - 10_000)

    r = client.get("/api/v1/dashboard/insights", headers=AUTH)
    assert r.headers["X-Insights-Cache"] == "stale"
    assert int(r.headers["Age"]) >= 10_000

    deadline = time.monotonic() + 5
    while len(calls) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(calls) == 2
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        r = client.get("/api/v1/dashboard/insights", headers=AUTH)
        if r.headers["X-Insights-Cache"] == "fresh":
            break
        time.sleep(0.01)
    assert r.headers["X-Insights-Cache"] == "fresh"


def test_a_result_with_a_failed_card_expires_sooner(monkeypatch):
    assert (
        insights_router._ttl_for(fake_result("all", False, error=True))
        == insights_router.ERROR_TTL_SECONDS
    )
    assert (
        insights_router._ttl_for(fake_result("all", False))
        == insights_router.CACHE_TTL_SECONDS
    )


def test_concurrent_cold_requests_share_one_computation(monkeypatch):
    insights_router.reset_cache()
    calls = []
    release = threading.Event()

    def compute(platform, include_archived):
        calls.append(platform)
        release.wait(5)
        return fake_result(platform, include_archived)

    monkeypatch.setattr(di, "compute_insights", compute)

    async def scenario():
        waiters = [
            asyncio.create_task(insights_router.get_insights(("all", False)))
            for _ in range(8)
        ]
        await asyncio.sleep(0.05)
        release.set()
        return await asyncio.gather(*waiters)

    results = asyncio.run(scenario())
    insights_router.reset_cache()
    assert calls == ["all"]
    assert {state for _r, state, _age in results} == {"miss"}
    assert all(r is results[0][0] for r, _s, _a in results)
