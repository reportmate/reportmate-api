"""Identity posture report: three-valued checks, report-time token expiry, and the SQL projection.

The SQL tests run against real PostgreSQL and are skipped without
TEST_DATABASE_URL; CI provides one.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from main import app
from routers.identity_posture import (
    activation_lock_state,
    laps_source,
    laps_state,
    posture_checks,
    prt_state,
    psso_state,
    psso_users,
    recovery_key_state,
    shape_posture,
    tri,
)

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
HEADERS = {"X-Internal-Secret": "test-internal-secret"}


def iso(**kw):
    return (NOW + timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.mark.parametrize(
    "raw,expected",
    [
        (True, True),
        (False, False),
        (1, True),
        (0, False),
        ("true", True),
        ("Enabled", True),
        ("Disabled", False),
        (None, None),
        ("", None),
        (2, None),
        ("Likely Enabled", None),
    ],
)
def test_collected_booleans_keep_unknown_distinct(raw, expected):
    assert tri(raw) is expected


def test_laps_needs_explicit_false_from_both_checks():
    assert (
        laps_state({"windowsLapsConfigured": True, "legacyLapsInstalled": False})
        == "configured"
    )
    assert (
        laps_state({"windowsLapsConfigured": False, "legacyLapsInstalled": True})
        == "configured"
    )
    assert (
        laps_state({"windowsLapsConfigured": False, "legacyLapsInstalled": False})
        == "not_configured"
    )
    assert laps_state({"windowsLapsConfigured": False}) == "unknown"
    assert laps_state(None) == "unknown"


def test_laps_source_is_reported_only_when_sent():
    assert laps_source({"policySource": "gpo"}) == "gpo"
    assert laps_source({"policySource": "none"}) == "none"
    assert laps_source({"windowsLapsConfigured": False}) is None
    assert laps_source({"policySource": "registry"}) is None
    assert laps_source(None) is None


def test_prt_state_is_judged_at_report_time_and_keeps_missing_apart():
    collected = {"status": "collected", "entraPrt": True}
    assert prt_state(None, NOW) == "not_reported"
    assert prt_state({"status": "notAvailable", "reason": "No user is signed in"}, NOW) == "not_available"
    assert prt_state({"status": "failed"}, NOW) == "failed"
    assert prt_state({"status": "collected", "entraPrt": False}, NOW) == "none"
    assert prt_state({"status": "collected"}, NOW) == "unknown"
    assert prt_state({**collected, "entraPrtExpiryTime": iso(days=3)}, NOW) == "valid"
    assert prt_state({**collected, "entraPrtExpiryTime": iso(hours=-1)}, NOW) == "expired"
    assert prt_state(collected, NOW) == "valid"


def test_no_valid_prt_view_needs_a_collected_answer():
    def checks(prt):
        return posture_checks("Windows", {"prtState": prt}, "fresh", "fresh")["noValidPrt"]

    assert checks("none") is True
    assert checks("expired") is True
    assert checks("valid") is False
    for state in ("not_reported", "not_available", "failed", "unknown"):
        assert checks(state) is None
    assert posture_checks("Windows", {"prtState": "none"}, "stale", "fresh")["noValidPrt"] is None
    assert posture_checks("macOS", {"prtState": "none"}, "fresh", "fresh")["noValidPrt"] is None


def test_windows_rows_report_sso_complexity_and_laps_source():
    row = _row(
        "WIN1",
        "Windows 11",
        iso(hours=-1),
        windows={
            "laps": {
                "windowsLapsConfigured": False,
                "legacyLapsInstalled": False,
                "policySource": "none",
            },
            "passwordPolicy": {"errorMessage": "", "complexityRequired": False},
            "userSso": {
                "status": "collected",
                "userName": "EXAMPLE\\sample",
                "entraPrt": True,
                "entraPrtExpiryTime": iso(days=5),
                "cloudTgt": True,
            },
        },
    )
    old = _row("WIN2", "Windows 11", iso(hours=-1), windows={"laps": {}})
    result = shape_posture(
        [row, old], views=[], freshness="all", search="", max_age_hours=168,
        limit=500, offset=0, now=NOW,
    )
    by = {d["serialNumber"]: d for d in result["devices"]}
    new = by["WIN1"]["reported"]
    assert (new["prtState"], new["prtUser"], new["cloudTgt"], new["onPremTgt"]) == (
        "valid", "EXAMPLE\\sample", True, None,
    )
    assert (new["passwordComplexity"], new["lapsPolicySource"]) == (False, "none")
    legacy = by["WIN2"]["reported"]
    assert (legacy["prtState"], legacy["passwordComplexity"], legacy["lapsPolicySource"]) == (
        "not_reported", None, None,
    )
    assert by["WIN2"]["checks"]["noValidPrt"] is None
    assert result["unknown"]["noValidPrt"] == 1


def test_activation_lock_keeps_inference_separate():
    assert activation_lock_state({"status": "Enabled"}) == "on"
    assert activation_lock_state({"status": "Likely Enabled"}) == "likely"
    assert activation_lock_state({"status": "Disabled"}) == "off"
    assert activation_lock_state({"status": "Unknown"}) == "unknown"
    assert activation_lock_state(None) == "unknown"


def test_recovery_key_absence_requires_filevault_on_and_both_answers():
    assert (
        recovery_key_state(
            {"enabled": 1, "personalRecoveryKey": 1, "institutionalRecoveryKey": 0}
        )
        == "present"
    )
    assert (
        recovery_key_state(
            {"enabled": 1, "personalRecoveryKey": 0, "institutionalRecoveryKey": 0}
        )
        == "none"
    )
    assert recovery_key_state({"enabled": 1, "personalRecoveryKey": 0}) == "unknown"
    assert (
        recovery_key_state(
            {"enabled": 0, "personalRecoveryKey": 0, "institutionalRecoveryKey": 0}
        )
        == "filevault_off"
    )
    assert recovery_key_state(None) == "unknown"


def test_psso_token_expiry_is_judged_at_report_time():
    sso = {
        "deviceRegistered": 1,
        "users": [
            {
                "username": "sample1",
                "registered": 1,
                "tokenExpiration": iso(days=3),
                "tokenExpired": 0,
            },
            {
                "username": "sample2",
                "registered": 1,
                "tokenExpiration": iso(days=-3),
                "tokenExpired": 0,
            },
            {
                "username": "sample3",
                "registered": 0,
                "tokenExpiration": "",
                "tokenExpired": None,
            },
        ],
    }
    users = psso_users(sso, NOW)
    assert [u["token"] for u in users] == ["valid", "expired", "not_registered"]
    assert psso_state(sso, users) == "expired"


def test_psso_states_without_tokens():
    unregistered = {
        "deviceRegistered": 0,
        "users": [{"username": "sample", "registered": 0}],
    }
    assert psso_state(unregistered, psso_users(unregistered, NOW)) == "not_registered"
    no_expiry = {
        "deviceRegistered": 1,
        "users": [{"username": "sample", "registered": 1}],
    }
    assert psso_state(no_expiry, psso_users(no_expiry, NOW)) == "unknown"
    assert psso_state(None, []) == "unknown"


def test_stale_collection_cannot_put_a_device_in_a_quick_view():
    reported = {"laps": "not_configured", "autoLogin": True}
    assert posture_checks("Windows", reported, "fresh", "fresh")["noLaps"] is True
    stale = posture_checks("Windows", reported, "stale", "fresh")
    assert stale["noLaps"] is None and stale["autoLogin"] is None
    assert stale["activationLock"] is None


def _row(serial, platform, collected, windows=None, mac=None, security=None):
    return {
        "serialNumber": serial,
        "deviceName": serial,
        "platform": platform,
        "identityReported": True,
        "securityReported": True,
        "identityCollectedAt": collected,
        "securityCollectedAt": security or collected,
        "windows": windows or {},
        "mac": mac or {},
    }


def test_quick_views_count_unknown_separately_and_filter_by_all_selected():
    rows = [
        _row(
            "WIN1",
            "Windows 11",
            iso(hours=-1),
            windows={
                "laps": {"windowsLapsConfigured": False, "legacyLapsInstalled": False},
                "autoLogin": {"autoAdminLogon": True},
            },
        ),
        _row(
            "WIN2",
            "Windows 11",
            iso(hours=-1),
            windows={
                "laps": {"windowsLapsConfigured": True, "legacyLapsInstalled": False},
                "autoLogin": {"autoAdminLogon": False},
            },
        ),
        _row(
            "WIN3",
            "Windows 11",
            iso(days=-30),
            windows={
                "laps": {"windowsLapsConfigured": False, "legacyLapsInstalled": False}
            },
        ),
        _row(
            "MAC1",
            "macOS",
            iso(hours=-1),
            mac={
                "activationLock": {"status": "Disabled"},
                "fileVault": {
                    "enabled": 1,
                    "personalRecoveryKey": 0,
                    "institutionalRecoveryKey": 0,
                },
            },
        ),
    ]
    result = shape_posture(
        rows,
        views=[],
        freshness="all",
        search="",
        max_age_hours=168,
        limit=500,
        offset=0,
        now=NOW,
    )
    assert result["summary"]["noLaps"] == 1
    assert result["unknown"]["noLaps"] == 1
    assert result["summary"]["noRecoveryKey"] == 1
    assert result["unknown"]["autoLogin"] == 1
    assert result["unknown"]["expiredPssoToken"] == 1
    both = shape_posture(
        rows,
        views=["noLaps", "autoLogin"],
        freshness="all",
        search="",
        max_age_hours=168,
        limit=500,
        offset=0,
        now=NOW,
    )
    assert [d["serialNumber"] for d in both["devices"]] == ["WIN1"]


@pytest.mark.parametrize(
    "query",
    [
        "views=bogus",
        "platform=invalid",
        "maxAgeHours=0",
        "limit=501",
        "offset=-1",
        "freshness=recent",
    ],
)
def test_invalid_queries_fail_before_accessing_the_database(query):
    assert (
        TestClient(app)
        .get(f"/api/v1/identity/posture?{query}", headers=HEADERS)
        .status_code
        == 422
    )


def test_posture_requires_authentication():
    assert TestClient(app).get("/api/v1/identity/posture").status_code == 401


_TEST_DB = os.getenv("TEST_DATABASE_URL")
SCHEMA = "identity_posture_test"

WIN_IDENTITY = {
    "collectedAt": "2026-06-01T11:00:00Z",
    "laps": {
        "windowsLapsConfigured": False,
        "legacyLapsInstalled": False,
        "backupDirectory": "",
        "adminAccountName": "",
    },
    "autoLogin": {
        "autoAdminLogon": True,
        "hasDefaultPassword": True,
        "defaultUserName": "sample",
    },
    "uac": {"level": "NotifyChangesSecure", "enableLua": True},
    "passwordPolicy": {
        "errorMessage": "",
        "minPasswordLength": 13,
        "lockoutThreshold": 5,
        "lockoutDurationMinutes": 30,
    },
    "windowsHello": {
        "statusDisplay": "Enabled (PIN)",
        "credentialProviders": {"pinEnabled": True, "fingerprintEnabled": False},
        "credentialGuard": {"isEnabled": False, "isConfigured": False},
    },
    "tpmOwnership": {"isOwned": True, "isReady": True},
    "userSsoState": {
        "status": "collected",
        "userName": "EXAMPLE\\sample",
        "sessionId": 1,
        "context": "userSession",
        "collectedAt": "2026-06-01T11:00:00Z",
        "entraPrt": True,
        "entraPrtUpdateTime": "2000-01-01T00:00:00Z",
        "entraPrtExpiryTime": "2000-01-14T00:00:00Z",
        "entraPrtAuthority": "https://login.example.com/tenant",
        "cloudTgt": True,
        "onPremTgt": False,
    },
    "summary": {"failedLoginsLast7Days": 2},
    "users": [{"username": "sample", "sid": "S-1-5-21-0"}],
}
MAC_IDENTITY = {
    "platformSSOUsers": {
        "supported": 1,
        "deviceRegistered": 1,
        "provider": "Example IdP",
        "users": [
            {
                "username": "sample",
                "registered": 1,
                "tokenExpiration": "2000-01-01T00:00:00Z",
                "tokenExpired": 0,
                "userPrincipalName": "sample@example.com",
            },
        ],
    },
    "secureTokenUsers": {"tokenGrantedCount": 1, "tokenMissingCount": 0},
}
MAC_SECURITY = {
    "activationLock": {
        "status": "Likely Enabled",
        "findMyMac": "Enabled",
        "email": "sample@example.com",
    },
    "fileVault": {
        "enabled": 1,
        "status": "Enabled",
        "personalRecoveryKey": 1,
        "institutionalRecoveryKey": 0,
    },
    "bootstrapToken": {
        "status": "Escrowed",
        "escrowed": 1,
        "supported": 1,
        "rawOutput": "sample",
    },
}


def _connect(search_path=True):
    import pg8000

    pg8000.paramstyle = "pyformat"
    u = urlparse(_TEST_DB)
    conn = pg8000.connect(
        host=u.hostname,
        port=u.port or 5432,
        database=u.path.lstrip("/"),
        user=u.username,
        password=u.password,
    )
    if search_path:
        conn.cursor().execute(f"SET search_path TO {SCHEMA}")
    return conn


@pytest.fixture(scope="module")
def db():
    conn = _connect(search_path=False)
    conn.autocommit = True
    cur = conn.cursor()
    for stmt in [
        f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE",
        f"CREATE SCHEMA {SCHEMA}",
        f"SET search_path TO {SCHEMA}",
        """CREATE TABLE devices (id TEXT PRIMARY KEY, device_id TEXT, serial_number TEXT UNIQUE, name TEXT,
               platform TEXT, archived BOOLEAN NOT NULL DEFAULT FALSE, last_seen TIMESTAMPTZ)""",
        "CREATE TABLE identity (id SERIAL PRIMARY KEY, device_id TEXT UNIQUE, data JSONB, collected_at TIMESTAMPTZ DEFAULT NOW())",
        "CREATE TABLE security (id SERIAL PRIMARY KEY, device_id TEXT UNIQUE, data JSONB, collected_at TIMESTAMPTZ DEFAULT NOW())",
        "CREATE TABLE inventory (id SERIAL PRIMARY KEY, device_id TEXT UNIQUE, data JSONB)",
        "CREATE TABLE device_inventory_state (serial_number TEXT PRIMARY KEY, state TEXT)",
    ]:
        cur.execute(stmt)
    for serial, platform in (
        ("TESTSERIAL01", "Windows 11"),
        ("TESTSERIAL02", "macOS"),
        ("TESTSERIAL03", "macOS"),
    ):
        cur.execute(
            "INSERT INTO devices (id, device_id, serial_number, name, platform, last_seen) VALUES (%s, %s, %s, %s, %s, NOW())",
            (serial, serial, serial, serial, platform),
        )
        cur.execute(
            "INSERT INTO inventory (device_id, data) VALUES (%s, %s::jsonb)",
            (serial, json.dumps({"deviceName": f"{serial}-NAME", "usage": "Shared"})),
        )
    cur.execute(
        "INSERT INTO identity (device_id, data) VALUES ('TESTSERIAL01', %s::jsonb)",
        (json.dumps(WIN_IDENTITY),),
    )
    cur.execute(
        "INSERT INTO identity (device_id, data, collected_at) VALUES ('TESTSERIAL02', %s::jsonb, NOW())",
        (json.dumps(MAC_IDENTITY),),
    )
    cur.execute(
        "INSERT INTO security (device_id, data, collected_at) VALUES ('TESTSERIAL02', %s::jsonb, NOW())",
        (json.dumps(MAC_SECURITY),),
    )
    cur.execute(
        "INSERT INTO device_inventory_state VALUES ('TESTSERIAL02', 'checked_out')"
    )
    conn.close()
    yield
    conn = _connect(search_path=False)
    conn.autocommit = True
    conn.cursor().execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")
    conn.close()


def _rows(platform=""):
    from dependencies import load_sql

    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        load_sql("devices/identity_posture"),
        {"include_archived": False, "platform": platform},
    )
    rows = [r[0] for r in cur.fetchall()]
    conn.close()
    return {
        r["serialNumber"]: (json.loads(r) if isinstance(r, str) else r) for r in rows
    }


@pytest.mark.skipif(
    not _TEST_DB, reason="TEST_DATABASE_URL not set; skipping live-DB posture tests"
)
def test_projection_joins_identity_and_security_without_full_documents(db):
    rows = _rows()
    assert set(rows) == {"TESTSERIAL01", "TESTSERIAL02", "TESTSERIAL03"}
    win, mac, empty = rows["TESTSERIAL01"], rows["TESTSERIAL02"], rows["TESTSERIAL03"]
    assert win["windows"]["autoLogin"] == {
        "autoAdminLogon": True,
        "hasDefaultPassword": True,
    }
    assert win["identityCollectedAt"] == "2026-06-01T11:00:00Z"
    assert win["windows"]["userSso"]["entraPrt"] is True
    assert "entraPrtAuthority" not in win["windows"]["userSso"]
    assert mac["mac"]["activationLock"] == {
        "status": "Likely Enabled",
        "findMyMac": "Enabled",
    }
    assert mac["mac"]["fileVault"]["personalRecoveryKey"] == 1
    assert mac["mac"]["platformSSO"]["users"][0] == {
        "username": "sample",
        "registered": 1,
        "tokenExpiration": "2000-01-01T00:00:00Z",
        "tokenExpired": 0,
    }
    assert mac["inventoryState"] == "checked_out"
    assert (
        empty["identityReported"] is not True and empty["securityReported"] is not True
    )
    text = json.dumps(rows)
    assert (
        "S-1-5-21-0" not in text
        and "sample@example.com" not in text
        and "rawOutput" not in text
    )


@pytest.mark.skipif(
    not _TEST_DB, reason="TEST_DATABASE_URL not set; skipping live-DB posture tests"
)
def test_projection_shapes_into_report(db):
    assert set(_rows("windows")) == {"TESTSERIAL01"}
    now = datetime.now(timezone.utc)
    result = shape_posture(
        list(_rows().values()),
        views=[],
        freshness="all",
        search="",
        max_age_hours=24 * 365 * 100,
        limit=500,
        offset=0,
        now=now,
    )
    by = {d["serialNumber"]: d for d in result["devices"]}
    assert (
        by["TESTSERIAL01"]["checks"]["noLaps"] is True
        and by["TESTSERIAL01"]["checks"]["autoLogin"] is True
    )
    assert by["TESTSERIAL01"]["reported"]["helloProviders"] == ["PIN"]
    assert by["TESTSERIAL01"]["reported"]["prtState"] == "expired"
    assert by["TESTSERIAL01"]["checks"]["noValidPrt"] is True
    assert by["TESTSERIAL02"]["checks"]["expiredPssoToken"] is True
    assert by["TESTSERIAL02"]["checks"]["activationLock"] is True
    assert by["TESTSERIAL02"]["checks"]["noRecoveryKey"] is False
    assert all(value is None for value in by["TESTSERIAL03"]["checks"].values())


def test_malformed_types_show_as_unknown_instead_of_failing_the_report():
    rows = [
        _row("BAD1", "Windows 11", iso(hours=-1), windows={"laps": "yes", "autoLogin": ["x"], "uac": {"level": 7}}),
        _row("BAD2", "macOS", 12345, mac={"platformSSO": {"users": "sample", "provider": ["x"]},
                                           "fileVault": [1], "activationLock": {"status": {"x": 1}}}),
        _row("BAD3", "macOS", iso(hours=-1), mac={"platformSSO": {"users": [None, 3, {"registered": "maybe", "username": 9}]}}),
        {"serialNumber": "BAD4", "platform": "Windows 11", "windows": "not an object", "identityCollectedAt": {"x": 1}},
        "not a row",
        _row("BAD5", 42, iso(hours=-1)),
        _row("GOOD", "Windows 11", iso(hours=-1), windows={"autoLogin": {"autoAdminLogon": True}}),
    ]
    result = shape_posture(rows, views=[], freshness="all", search="", max_age_hours=168, limit=500, offset=0, now=NOW)
    by = {d.get("serialNumber"): d for d in result["devices"]}
    assert by["GOOD"]["checks"]["autoLogin"] is True
    for serial in ("BAD1", "BAD2", "BAD3", "BAD4"):
        assert by[serial]["checks"]["noLaps"] in (None,)
    assert by["BAD1"]["reported"]["uacLevel"] is None
    assert by["BAD2"]["reported"]["recoveryKey"] == "unknown"
    assert by["BAD3"]["reported"]["pssoUsers"][0]["username"] is None
    assert result["summary"]["autoLogin"] == 1
    assert by["BAD5"]["platform"] == "Unknown"
