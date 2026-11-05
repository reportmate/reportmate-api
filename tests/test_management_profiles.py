from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from main import app
from routers.management_enrollment import enrollment_fields
from routers.management_profiles import (
    preference_scope,
    profile_scope,
    profile_state,
    shape_profiles,
)

HEADERS = {"X-Internal-Secret": "test-internal-secret"}
NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
FRESH = (NOW - timedelta(hours=1)).isoformat()
STALE = (NOW - timedelta(days=3)).isoformat()


@pytest.mark.parametrize(
    "matched,freshness,available,expected",
    [
        (True, "fresh", True, "installed"),
        (True, "stale", True, "installed"),
        (False, "fresh", True, "missing"),
        (False, "stale", True, "unknown"),
        (False, "unknown", True, "unknown"),
        (False, "fresh", False, "unknown"),
        (False, "fresh", None, "unknown"),
    ],
)
def test_missing_needs_fresh_nonempty_inventory(
    matched, freshness, available, expected
):
    assert profile_state(matched, freshness, available) == expected


def test_scopes_follow_recorded_values():
    assert profile_scope({"user": "System Level"}) == "system"
    assert profile_scope({"user": "someuser"}) == "user"
    assert profile_scope({"type": "Device"}) == "system"
    assert profile_scope({"type": "User"}) == "user"
    assert profile_scope({}) == "unknown"
    assert preference_scope(["System Level"]) == "system"
    assert preference_scope(["System Level", "someuser"]) == "system+user"
    assert preference_scope([]) == "unknown"


def _device(serial, platform, collected, matches, available=True):
    return {
        "serialNumber": serial,
        "deviceName": serial,
        "platform": platform,
        "collectedAt": collected,
        "inventoryAvailable": available,
        "inventoryCount": 3 if available else 0,
        "matches": matches,
        "inventoryState": "deployed",
    }


def _shape(rows, **overrides):
    args = dict(
        kind="profile",
        selected={"com.example.wifi"},
        labels={"com.example.wifi": {"identifier": "com.example.Wifi", "name": "Wifi"}},
        state=set(),
        freshness="all",
        max_age_hours=24,
        platform="",
        search="",
        scopes={},
        inventory_states=set(),
        limit=500,
        offset=0,
        now=NOW,
    )
    args.update(overrides)
    return shape_profiles(rows, **args)


def test_rows_per_device_and_profile_with_honest_absence():
    match = {
        "key": "com.example.wifi",
        "identifier": "com.example.Wifi",
        "name": "Wifi",
        "user": "System Level",
        "installDate": "2026-01-01 10:00:00 +0000",
        "uuid": "UUID-1",
    }
    rows = [
        _device("TESTSERIAL01", "macOS", FRESH, [match]),
        _device("TESTSERIAL02", "macOS", FRESH, []),
        _device("TESTSERIAL03", "macOS", STALE, []),
        _device("TESTSERIAL04", "macOS", FRESH, [], available=False),
        _device("TESTSERIAL05", "Windows", FRESH, []),
    ]
    result = _shape(rows)
    states = {r["serialNumber"]: r["state"] for r in result["devices"]}
    # Windows never reported this macOS profile, so it is not evaluated for absence.
    assert states == {
        "TESTSERIAL01": "installed",
        "TESTSERIAL02": "missing",
        "TESTSERIAL03": "unknown",
        "TESTSERIAL04": "unknown",
    }
    installed = result["devices"][0]
    assert installed["scope"] == "system" and installed["installDate"].startswith(
        "2026-01-01"
    )
    assert result["summary"] == {"installed": 1, "missing": 1, "unknown": 2}
    assert _shape(rows, state={"missing"})["total"] == 1


def test_no_per_device_cap_on_matches():
    matches = [
        {"key": f"p{i}", "identifier": f"p{i}", "name": f"P{i}", "type": "Device"}
        for i in range(80)
    ]
    rows = [_device("TESTSERIAL01", "Windows", FRESH, matches)]
    result = _shape(rows, selected={f"p{i}" for i in range(80)}, labels={})
    assert result["total"] == 80


def test_preference_rows_carry_values():
    match = {
        "key": "com.example.app",
        "identifier": "com.example.app",
        "name": "com.example.app",
        "settingCount": 2,
        "scopes": ["System Level"],
        "values": [{"scope": "System Level", "value": "1"}],
    }
    result = _shape(
        [_device("TESTSERIAL01", "macOS", FRESH, [match])],
        kind="preference",
        selected={"com.example.app"},
        labels={},
    )
    row = result["devices"][0]
    assert (
        row["scope"] == "system"
        and row["values"][0]["value"] == "1"
        and row["settingCount"] == 2
    )


@pytest.mark.parametrize(
    "query",
    [
        "kind=other",
        "states=present",
        "platform=invalid",
        "maxAgeHours=0",
        "limit=2001",
        "identifiers=%5Binvalid",
        "kind=profile&preferenceKey=Foo",
    ],
)
def test_invalid_queries_fail_before_accessing_the_database(query):
    assert (
        TestClient(app)
        .get(f"/api/v1/management/profiles?{query}", headers=HEADERS)
        .status_code
        == 422
    )


def test_too_many_selections_rejected():
    ids = "[" + ",".join(f'"p{i}"' for i in range(51)) + "]"
    assert (
        TestClient(app)
        .get(
            "/api/v1/management/profiles", params={"identifiers": ids}, headers=HEADERS
        )
        .status_code
        == 422
    )


def test_empty_selection_needs_no_database():
    body = TestClient(app).get("/api/v1/management/profiles", headers=HEADERS).json()
    assert body["queryRequired"] is True and body["devices"] == []


def test_profile_report_requires_authentication():
    client = TestClient(app)
    assert client.get("/api/v1/management/profiles").status_code == 401
    assert client.get("/api/v1/management/profiles/filters").status_code == 401


def test_mac_enrollment_fields():
    management = {"mdm_info": {"is_user_approved": "true", "enrolled_in_dep": "true"}}
    enrollment = {
        "enrolled": "true",
        "user_approved": "false",
        "installed_from_dep": "",
        "dep_capable": "true",
    }
    fields = enrollment_fields(
        management, {"certificate_expires": "Sep 16 23:10:35 2027 GMT"}, enrollment
    )
    assert fields["userApprovedMdm"] is False
    assert (
        fields["installedFromDep"] is True
    )  # falls back to mdm_info when enrollment is blank
    assert fields["depCapable"] is True
    assert fields["mdmCertificateExpires"] == "2027-09-16T23:10:35+00:00"
    # macOS does not report compliance or a sync time: unknown, never healthy.
    assert fields["complianceState"] is None and fields["lastMdmSync"] is None


def test_windows_enrollment_fields():
    management = {
        "lastSync": "2026-01-15T05:12:59.2325928Z",
        "deviceDetails": {"intuneDeviceId": "00000000-0000-0000-0000-000000000001"},
        "metadata": {
            "Certificates": [
                {
                    "Issuer": "Example MDM Device CA",
                    "Subject": "00000000-0000-0000-0000-000000000001",
                    "NotValidAfter": "2027-10-19T07:52:28",
                },
                {
                    "Issuer": "Example Device Management Device CA",
                    "Subject": "other",
                    "NotValidAfter": "2027-10-21T11:28:45",
                },
                {
                    "Issuer": "Example MDM Device CA",
                    "Subject": "stale",
                    "NotValidAfter": "2028-01-01T00:00:00",
                },
            ]
        },
        "compliancePolicies": [{"isCompliant": True}, {"isCompliant": False}],
    }
    fields = enrollment_fields(management, {}, {"isEnrolled": True})
    assert fields["lastMdmSync"].startswith("2026-01-15T05:12:59")
    assert fields["mdmCertificateExpires"] == "2027-10-19T07:52:28+00:00"
    assert (fields["complianceState"], fields["complianceSource"]) == (
        "non_compliant",
        "policies",
    )
    assert (
        fields["userApprovedMdm"] is None
        and fields["installedFromDep"] is None
        and fields["depCapable"] is None
    )


def test_enrollment_fields_unknown_when_not_collected():
    fields = enrollment_fields({}, {}, {})
    assert all(value is None for value in fields.values())
    assert (
        enrollment_fields({"compliancePolicies": []}, {}, {})["complianceState"] is None
    )
    assert (
        enrollment_fields(
            {"compliance_status": {"overall_status": "compliant"}}, {}, {}
        )["complianceState"]
        == "compliant"
    )


def test_each_selection_is_evaluated_only_on_platforms_that_report_it():
    mac = {"key": "mac.profile", "identifier": "mac.profile", "name": "Mac", "user": "System Level"}
    win = {"key": "win.profile", "identifier": "win.profile", "name": "Win", "type": "Device"}
    rows = [_device("TESTSERIAL01", "macOS", FRESH, [mac]), _device("TESTSERIAL02", "Windows", FRESH, [win]),
            _device("TESTSERIAL03", "macOS", FRESH, [])]
    result = _shape(rows, selected={"mac.profile", "win.profile"}, labels={})
    pairs = {(r["serialNumber"], r["identifier"], r["state"]) for r in result["devices"]}
    assert pairs == {("TESTSERIAL01", "mac.profile", "installed"), ("TESTSERIAL02", "win.profile", "installed"),
                     ("TESTSERIAL03", "mac.profile", "missing")}


def test_malformed_device_payloads_report_unknown_instead_of_failing():
    good = {"key": "com.example.wifi", "identifier": "com.example.Wifi", "name": "Wifi", "user": "System Level"}
    rows = [
        _device("TESTSERIAL01", "macOS", FRESH, [good]),
        {"serialNumber": 12345, "deviceName": ["not", "text"], "platform": {"os": "mac"}, "osName": "macOS",
         "collectedAt": 7, "inventoryAvailable": "yes", "inventoryCount": "many", "inventoryState": 3,
         "matches": "not a list"},
        {**_device("TESTSERIAL03", "macOS", FRESH, []), "matches": [None, 5, "x", {"key": None},
            {"key": "com.example.wifi", "identifier": {"bad": 1}, "name": 9, "user": ["x"], "payloadCount": "abc",
             "installDate": {"bad": True}, "removalDisallowed": "true"}]},
        "not a dict",
        None,
    ]
    result = _shape(rows, search="", inventory_states=set())
    by_serial = {r["serialNumber"]: r for r in result["devices"]}
    assert by_serial["TESTSERIAL01"]["state"] == "installed"
    assert by_serial["12345"]["state"] == "unknown" and by_serial["12345"]["deviceName"] is None
    malformed = by_serial["TESTSERIAL03"]
    assert malformed["state"] == "installed" and malformed["identifier"] == "com.example.Wifi"
    assert malformed["name"] == "9" and malformed["installDate"] is None and malformed["payloadCount"] is None
    assert malformed["scope"] == "unknown"
    # search over coerced text still works on malformed rows
    assert _shape(rows, search="12345")["total"] == 1
    pref = {"key": "com.example.app", "identifier": "com.example.app", "scopes": "System Level",
            "settingCount": [], "values": [{"scope": 1, "value": {"x": 1}}, "bad"]}
    row = _shape([_device("TESTSERIAL01", "macOS", FRESH, [pref])], kind="preference",
                 selected={"com.example.app"}, labels={})["devices"][0]
    assert row["scope"] == "unknown" and row["settingCount"] is None and row["values"] == [{"scope": "1", "value": None}]


@pytest.mark.parametrize("management,certificate,enrollment", [
    ("not a dict", None, None),
    ({"metadata": {"Certificates": "x"}, "deviceDetails": [], "compliancePolicies": "x", "lastSync": 5}, [], "x"),
    ({"metadata": {"Certificates": [None, 3, {"Issuer": 5, "NotValidAfter": {}}]}, "mdm_info": "x",
      "compliance_status": ["x"], "compliancePolicies": [None, {"isCompliant": "maybe"}]}, {"certificate_expires": 12}, {"user_approved": []}),
])
def test_malformed_enrollment_payloads_are_unknown(management, certificate, enrollment):
    fields = enrollment_fields(management, certificate, enrollment)
    assert all(value is None for value in fields.values())
