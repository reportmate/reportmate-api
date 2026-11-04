from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from main import app
from routers.system_services import collection_freshness, coverage_state, service_state, startup_type, _names


@pytest.mark.parametrize("raw,expected", [
    ("RUNNING", "running"), ("Running", "running"), (4, "running"),
    ("STOPPED", "stopped"), ("Stopped", "stopped"), (1, "stopped"),
    (None, "unknown"), ("START_PENDING", "unknown"),
])
def test_recorded_service_statuses(raw, expected):
    assert service_state(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("AUTO_START", "automatic"), ("Automatic", "automatic"),
    ("DEMAND_START", "manual"), ("Disabled", "disabled"),
    ("BOOT_START", "boot"), ("SYSTEM_START", "system"), (None, "unknown"),
])
def test_recorded_startup_types(raw, expected):
    assert startup_type(raw) == expected


def test_collection_age_never_invents_a_recent_timestamp():
    now = datetime.now(timezone.utc)
    assert collection_freshness(None, now, 24) == "unknown"
    assert collection_freshness("invalid", now, 24) == "unknown"
    assert collection_freshness((now + timedelta(hours=1)).isoformat(), now, 24) == "unknown"
    assert collection_freshness((now - timedelta(hours=24)).isoformat(), now, 24) == "fresh"
    assert collection_freshness((now - timedelta(hours=24, seconds=1)).isoformat(), now, 24) == "stale"
    assert collection_freshness((now - timedelta(hours=25)).isoformat(), now, 168) == "fresh"


@pytest.mark.parametrize("reported,freshness,available,expected", [
    ("missing", "fresh", True, "missing"),
    ("missing", "fresh", False, "unknown"),
    ("missing", "fresh", None, "unknown"),
    ("missing", "stale", True, "unknown"),
    ("running", "stale", True, "unknown"),
    ("running", "unknown", True, "unknown"),
    ("running", "fresh", True, "running"),
    ("stopped", "fresh", True, "stopped"),
])
def test_missing_or_stale_collection_cannot_claim_coverage(reported, freshness, available, expected):
    assert coverage_state(reported, freshness, available) == expected


@pytest.mark.parametrize("query", [
    "states=connected", "startups=on", "platform=invalid", "maxAgeHours=0",
    "limit=501", "offset=-1", "freshness=recent", "versions=15.20",
])
def test_invalid_queries_fail_before_accessing_the_database(query):
    client = TestClient(app)
    response = client.get(f"/api/v1/system/services?{query}", headers={"X-Internal-Secret": "test-internal-secret"})
    assert response.status_code == 422


def test_services_report_requires_authentication():
    client = TestClient(app)
    assert client.get("/api/v1/system/services?service=Sysmon").status_code == 401


def test_exact_names_preserve_punctuation():
    assert _names('["Agent Service", "Application (x64, English)"]') == {"agent service", "application (x64, english)"}
    assert _names("Agent,Other") == {"agent", "other"}


@pytest.mark.parametrize("value", ['[invalid', '[1]', '[null]'])
def test_invalid_exact_names_fail_before_accessing_the_database(value):
    response = TestClient(app).get("/api/v1/system/services", params={"serviceNames": value}, headers={"X-Internal-Secret": "test-internal-secret"})
    assert response.status_code == 422


def test_service_options_require_authentication_and_validate_platform():
    client = TestClient(app)
    assert client.get("/api/v1/system/services/filters").status_code == 401
    assert client.get("/api/v1/system/services/filters?platform=invalid", headers={"X-Internal-Secret": "test-internal-secret"}).status_code == 422
