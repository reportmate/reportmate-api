"""Provider on the bulk management endpoint when the enrolment blocks are missing.

Some Macs report mdm_info.managed_via_mdm=true from mdmclient while the
mdm_enrollment and mdm_certificate blocks are absent from the same payload.
With nothing to name a provider from, the endpoint used to call these devices
Unmanaged, contradicting the payload. They are managed by an MDM we cannot
identify, so they read as "Unknown MDM" and as enrolled.
"""

import datetime

import pytest
from fastapi.testclient import TestClient

from dependencies import invalidate_caches
from routers.fleet import _mdm_info_reports_managed

AUTH = {"X-Client-Passphrase": "test-passphrase"}


def make_row(serial, management):
    """One row in the shape bulk_management.sql returns."""
    return (
        serial,
        f"uuid-{serial}",
        datetime.datetime(2026, 9, 2, 12, 0, 0),
        management,
        datetime.datetime(2026, 9, 2, 11, 0, 0),
        f"Device {serial}",
        serial.lower(),
        "Assigned",
        "Staff",
        "A3030",
        f"A-{serial}",
        "IT",
        "",
        "macOS",
        "macOS 26",
    )


class FakeCursor:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, query, params=None):
        pass

    def fetchall(self):
        return self._rows

    def close(self):
        pass


class FakeConnection:
    def __init__(self, rows):
        self._rows = rows

    def cursor(self):
        return FakeCursor(self._rows)

    def close(self):
        pass


ROWS = [
    make_row(
        "MANAGEDNOBLOCKS",
        {"mdm_info": {"managed_via_mdm": "true", "enrolled_in_dep": "true"}},
    ),
    make_row(
        "MANAGEDINFOURL",
        {
            "mdm_info": {
                "managed_via_mdm": "true",
                "mdm_server_url_full": "https://fef.msub03.manage.microsoft.com/StatelessIOSEnrollment/mdm",
            }
        },
    ),
    make_row("NOTMANAGED", {"mdm_info": {"managed_via_mdm": "false"}}),
    make_row("EMPTYPAYLOAD", {}),
    make_row(
        "EXPLICITNOTENROLLED",
        {
            "mdm_enrollment": {"enrolled": "false"},
            "mdm_info": {"managed_via_mdm": "true"},
        },
    ),
    make_row(
        "INTUNEURL",
        {
            "mdm_enrollment": {
                "enrolled": "true",
                "server_url": "https://manage.microsoft.com/x",
            },
            "mdm_info": {"managed_via_mdm": "true"},
        },
    ),
]


@pytest.fixture
def devices(monkeypatch):
    import routers.fleet as fleet_router

    monkeypatch.setattr(fleet_router, "get_db_connection", lambda: FakeConnection(ROWS))
    invalidate_caches()
    from main import app

    response = TestClient(app).get("/api/v1/management", headers=AUTH)
    invalidate_caches()
    assert response.status_code == 200
    return {d["serialNumber"]: d for d in response.json()}


def test_managed_without_enrolment_blocks_is_unknown_mdm(devices):
    device = devices["MANAGEDNOBLOCKS"]
    assert device["provider"] == "Unknown MDM"
    assert device["isEnrolled"] is True
    assert device["enrollmentStatus"] == "Enrolled"


def test_mdmclient_server_url_names_the_provider(devices):
    assert devices["MANAGEDINFOURL"]["provider"] == "Microsoft Intune"


def test_unmanaged_devices_stay_unmanaged(devices):
    for serial in ("NOTMANAGED", "EMPTYPAYLOAD"):
        assert devices[serial]["provider"] == "Unmanaged"
        assert devices[serial]["isEnrolled"] is False


def test_explicit_enrolment_flag_is_not_overridden(devices):
    assert devices["EXPLICITNOTENROLLED"]["isEnrolled"] is False


def test_enrolment_url_still_wins(devices):
    assert devices["INTUNEURL"]["provider"] == "Microsoft Intune"
    assert devices["INTUNEURL"]["isEnrolled"] is True


def test_managed_flag_parsing():
    assert _mdm_info_reports_managed({"mdm_info": {"managed_via_mdm": "true"}}) is True
    assert _mdm_info_reports_managed({"mdmInfo": {"managedViaMdm": True}}) is True
    assert (
        _mdm_info_reports_managed({"mdm_info": {"managed_via_mdm": "false"}}) is False
    )
    assert _mdm_info_reports_managed({"mdm_info": {"managed_via_mdm": ""}}) is False
    assert _mdm_info_reports_managed({"mdm_info": []}) is False
    assert _mdm_info_reports_managed(None) is False
    assert _mdm_info_reports_managed({}) is False
