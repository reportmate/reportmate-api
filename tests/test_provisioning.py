"""The fleet provisioning record: derivation, wipe-range filters and paging.

The bulk projections it composes are stubbed at the router boundary, so these
tests pin the derivation itself and the endpoint's contract without a database.
"""

import pytest
from fastapi.testclient import TestClient

from dependencies import invalidate_caches
from routers import provisioning as prov

AUTH = {"X-Client-Passphrase": "test-passphrase"}


def system(serial, install_date="2026-08-25T20:07:17", **extra):
    row = {
        "serialNumber": serial,
        "deviceId": serial,
        "deviceName": f"Device {serial}",
        "platform": "Windows",
        "usage": "Shared",
        "lastSeen": "2026-08-27T12:00:00+00:00",
        "installDate": install_date,
        "lastInPlaceUpgrade": None,
        "inPlaceUpgradeCount": None,
    }
    row.update(extra)
    return row


def management(serial, policy_date="2026-08-25T20:07:33Z", status="Registered"):
    return {
        "serialNumber": serial,
        "autopilotConfig": {"policyDate": policy_date, "status": status},
    }


def installs(serial, *statuses):
    sessions = [
        {
            "status": status,
            "start_time": f"2026-08-26T0{i}:00:00Z",
            "end_time": f"2026-08-26T0{i}:20:00Z",
        }
        for i, status in enumerate(statuses)
    ]
    return {
        "serialNumber": serial,
        "modules": {"installs": {"cimian": {"sessions": sessions}}},
    }


def one(systems, mgmt=(), inst=()):
    [record] = prov.derive_records(systems, list(mgmt), list(inst))
    return record


# ─── Derivation ─────────────────────────────────────────────────────────


def test_a_matching_policy_write_corroborates_the_wipe():
    record = one([system("S1")], [management("S1")])
    assert record["corroborated"] is True
    assert record["wipedAt"] == "2026-08-25T20:07:17+00:00"
    assert record["autopilotPolicyDate"] == "2026-08-25T20:07:33Z"


def test_a_distant_policy_write_does_not_corroborate():
    record = one([system("S1")], [management("S1", policy_date="2024-03-01T10:00:00Z")])
    assert record["corroborated"] is False


def test_no_policy_write_is_uncorroborated_but_still_returned():
    record = one([system("S1")])
    assert record["corroborated"] is False
    assert record["autopilotPolicyDate"] is None


def test_no_install_date_leaves_corroboration_unknown():
    record = one([system("S1", install_date=None)], [management("S1")])
    assert record["wipedAt"] is None
    assert record["corroborated"] is None
    assert record["upgradeAtInstall"] is None


def test_an_upgrade_marker_at_the_install_date_is_flagged():
    record = one(
        [system("S1", lastInPlaceUpgrade="2026-08-25T13:00:00", inPlaceUpgradeCount=2)]
    )
    assert record["upgradeAtInstall"] is True
    assert record["inPlaceUpgradeCount"] == 2


def test_an_old_upgrade_marker_does_not_explain_the_install():
    record = one(
        [system("S1", lastInPlaceUpgrade="2024-07-23T09:12:33", inPlaceUpgradeCount=1)]
    )
    assert record["upgradeAtInstall"] is False


def test_zero_upgrades_stays_zero_and_unreported_stays_null():
    assert one([system("S1", inPlaceUpgradeCount=0)])["inPlaceUpgradeCount"] == 0
    assert one([system("S1")])["inPlaceUpgradeCount"] is None


def test_any_clean_session_in_the_window_is_converged():
    """A flapping device whose latest run failed one item still came up built."""
    record = one(
        [system("S1")],
        inst=[installs("S1", "completed", "completed", "partial_failure")],
    )
    assert record["converged"] is True
    assert record["lastSessionStatus"] == "partial_failure"
    assert record["lastCleanSessionAt"] == "2026-08-26T01:20:00+00:00"
    assert record["sessionsSeen"] == 3


def test_no_clean_session_is_not_converged():
    record = one([system("S1")], inst=[installs("S1", "partial_failure", "failed")])
    assert record["converged"] is False
    assert record["lastCleanSessionAt"] is None


def test_unfinished_sessions_carry_no_verdict():
    record = one(
        [system("S1")], inst=[installs("S1", "completed", "running", "running")]
    )
    assert record["converged"] is True
    assert record["lastSessionStatus"] == "completed"
    assert record["sessionsSeen"] == 1
    assert record["sessionsUnfinished"] == 2


def test_no_cimian_data_is_null_not_false():
    record = one([system("S1", platform="macOS")])
    assert record["converged"] is None
    assert record["sessionsSeen"] == 0


def test_cached_projections_are_not_mutated():
    systems = [system("S1")]
    before = dict(systems[0])
    prov.derive_records(systems, [management("S1")], [installs("S1", "completed")])
    assert systems[0] == before


# ─── Filters ────────────────────────────────────────────────────────────


def test_a_bare_upper_date_covers_the_whole_day():
    upper = prov.parse_bound("2026-08-25", "wipedTo", end_of_day=True)
    records = prov.derive_records([system("S1")], [], [])
    assert prov.filter_records(records, wiped_to=upper) == records


def test_a_bad_bound_is_rejected():
    with pytest.raises(prov.HTTPException) as exc:
        prov.parse_bound("last tuesday", "wipedFrom", end_of_day=False)
    assert exc.value.status_code == 422


def test_a_ranged_query_drops_devices_with_no_install_date():
    records = prov.derive_records(
        [system("S1"), system("S2", install_date=None)], [], []
    )
    lower = prov.parse_bound("2026-08-01", "wipedFrom", end_of_day=False)
    assert [
        r["serialNumber"] for r in prov.filter_records(records, wiped_from=lower)
    ] == ["S1"]
    assert len(prov.filter_records(records)) == 2


# ─── Endpoint ───────────────────────────────────────────────────────────

FLEET_SYSTEMS = [
    system("S1", install_date="2026-08-11T09:00:00"),
    system("S2", install_date="2026-08-25T20:07:17"),
    system("S3", install_date="2026-09-02T08:00:00"),
    system("S4", install_date="2025-02-23T10:00:00"),
    system("S5", install_date=None, platform="macOS"),
]


@pytest.fixture
def client(monkeypatch):
    calls = []

    def bulk(name, rows):
        def fn(**kwargs):
            calls.append((name, kwargs))
            return [dict(r) for r in rows]

        return fn

    monkeypatch.setattr(prov.fleet, "get_bulk_system", bulk("system", FLEET_SYSTEMS))
    monkeypatch.setattr(
        prov.fleet, "get_bulk_management", bulk("management", [management("S2")])
    )
    monkeypatch.setattr(
        prov.fleet,
        "get_bulk_installs_full",
        bulk("installs", [installs("S2", "completed")]),
    )
    invalidate_caches()
    from main import app

    test_client = TestClient(app)
    test_client.calls = calls
    yield test_client
    invalidate_caches()


def serials(response):
    return [r["serialNumber"] for r in response.json()]


def test_every_device_is_returned_without_filters(client):
    r = client.get("/api/v1/provisioning", headers=AUTH)
    assert r.status_code == 200
    assert serials(r) == ["S1", "S2", "S3", "S4", "S5"]
    assert r.headers["X-Total-Count"] == "5"
    s2 = r.json()[1]
    assert s2["corroborated"] is True and s2["converged"] is True


def test_the_wipe_range_filters(client):
    r = client.get(
        "/api/v1/provisioning?wipedFrom=2026-08-01&wipedTo=2026-08-31", headers=AUTH
    )
    assert serials(r) == ["S1", "S2"]
    assert r.headers["X-Total-Count"] == "2"


def test_paging_runs_over_the_filtered_set(client):
    first = client.get(
        "/api/v1/provisioning?wipedFrom=2026-01-01&limit=2", headers=AUTH
    )
    assert serials(first) == ["S1", "S2"]
    assert first.headers["X-Total-Count"] == "3"
    assert 'rel="next"' in first.headers["Link"]
    second = client.get(
        "/api/v1/provisioning?wipedFrom=2026-01-01&limit=2&offset=2", headers=AUTH
    )
    assert serials(second) == ["S3"]


def test_platform_filter(client):
    r = client.get("/api/v1/provisioning?platform=macos", headers=AUTH)
    assert serials(r) == ["S5"]


def test_the_projections_are_read_whole_and_archive_flag_passes_through(client):
    client.get("/api/v1/provisioning?includeArchived=true&limit=1", headers=AUTH)
    assert {name for name, _ in client.calls} == {"system", "management", "installs"}
    for _, kwargs in client.calls:
        assert kwargs["include_archived"] is True
        assert kwargs["limit"] is None and kwargs["offset"] == 0


def test_an_inverted_range_is_rejected(client):
    r = client.get(
        "/api/v1/provisioning?wipedFrom=2026-09-01&wipedTo=2026-08-01", headers=AUTH
    )
    assert r.status_code == 422


def test_a_malformed_bound_is_rejected(client):
    r = client.get("/api/v1/provisioning?wipedFrom=yesterday", headers=AUTH)
    assert r.status_code == 422


def test_authentication_is_required(client):
    assert client.get("/api/v1/provisioning").status_code in (401, 403)


class _EmptyCursor:
    def execute(self, query, params=None):
        pass

    def fetchall(self):
        return []

    def close(self):
        pass


class _EmptyConnection:
    def cursor(self):
        return _EmptyCursor()

    def rollback(self):
        pass

    def close(self):
        pass


def test_the_real_projections_compose_without_request_defaults(monkeypatch):
    """Called in-process, the bulk handlers get explicit arguments, not Query objects."""
    monkeypatch.setattr(prov.fleet, "get_db_connection", lambda: _EmptyConnection())
    invalidate_caches()
    from main import app

    r = TestClient(app).get("/api/v1/provisioning", headers=AUTH)
    invalidate_caches()
    assert r.status_code == 200
    assert r.json() == []
    assert r.headers["X-Total-Count"] == "0"
