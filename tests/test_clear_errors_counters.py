"""Clearing an installs payload must also zero the dashboard's counters.

The regression this guards: clear-errors rewrote installs.data and nothing else.
The dashboard does not read that JSONB - it sums the precomputed
cimian_errors / cimian_warnings / munki_errors / munki_warnings columns that
ingest maintains - so a cleanup left /installs/full clean while the dashboard
cards did not move at all, which is the one place anyone looks.

These exercise the endpoint's own clearing function against the ingest's own
counting function, so the two can only agree.
"""
import pytest
from datetime import datetime, timezone

from routers.admin import _clear_install_issue_fields, _clear_stale_items_by_age
from routers.events import _install_issue_counts


def test_cimian_errors_and_warnings_stop_counting():
    data = {"cimian": {"items": [
        {"itemName": "A", "currentStatus": "Error", "lastError": "boom", "failureCount": 2},
        {"itemName": "B", "currentStatus": "Warning", "lastWarning": "loop", "warningCount": 1},
        {"itemName": "C", "currentStatus": "Installed"},
    ]}}
    assert _install_issue_counts(data) != (0, 0, 0, 0)
    assert _clear_install_issue_fields(data) is True
    assert _install_issue_counts(data)[:2] == (0, 0)


def test_cimian_warning_status_is_reset_not_just_the_text():
    # Blanking lastWarning while leaving currentStatus at Warning is the exact
    # shape of the first version of this bug.
    data = {"cimian": {"items": [{"itemName": "A", "currentStatus": "Warning", "lastWarning": "x"}]}}
    _clear_install_issue_fields(data)
    assert data["cimian"]["items"][0]["currentStatus"] == "Installed"


def test_munki_run_strings_and_items_stop_counting():
    data = {"munki": {
        "errors": "one failed; another failed",
        "warnings": "something looked odd",
        "items": [
            {"name": "X", "status": "install_failed", "lastError": "nope"},
            {"name": "Y", "status": "installed", "lastWarning": "looping"},
        ],
    }}
    assert _install_issue_counts(data) != (0, 0, 0, 0)
    assert _clear_install_issue_fields(data) is True
    assert _install_issue_counts(data)[2:] == (0, 0)


def test_healthy_record_is_untouched_and_reports_no_change():
    data = {"cimian": {"items": [{"itemName": "A", "currentStatus": "Installed"}]}}
    assert _install_issue_counts(data) == (0, 0, 0, 0)
    assert _clear_install_issue_fields(data) is False
    assert _install_issue_counts(data) == (0, 0, 0, 0)


def test_non_dict_payload_is_ignored():
    assert _clear_install_issue_fields(None) is False
    assert _clear_install_issue_fields([]) is False


# --- per-item age clearing -------------------------------------------------
# The regression these guard: clear-errors keyed only on device check-in, so a
# machine that phones home hourly kept week-old failures forever. One lab
# machine held 45 records dated six days earlier while reporting in daily.

from datetime import datetime, timedelta, timezone

from routers.admin import _clear_stale_items_by_age, _item_attempt_age_days


def _item(name, attempt_age_days, status="Error"):
    when = datetime.now(timezone.utc) - timedelta(days=attempt_age_days)
    return {
        "itemName": name,
        "currentStatus": status,
        "lastError": "boom",
        "failureCount": 1,
        "lastAttemptTime": when.isoformat(),
    }


def test_old_failure_is_cleared_and_recent_one_is_kept():
    data = {"cimian": {"items": [_item("Old", 6), _item("Fresh", 0.1)]}}
    assert _clear_stale_items_by_age(data, datetime.now(timezone.utc), 1.0) is True
    items = {i["itemName"]: i for i in data["cimian"]["items"]}
    assert items["Old"]["currentStatus"] == "Installed"
    assert items["Old"]["lastError"] == ""
    assert items["Fresh"]["currentStatus"] == "Error", "a live failure must survive"
    assert items["Fresh"]["lastError"] == "boom"


def test_counters_agree_after_age_clearing():
    data = {"cimian": {"items": [_item("Old", 6)]}}
    _clear_stale_items_by_age(data, datetime.now(timezone.utc), 1.0)
    assert _install_issue_counts(data)[:2] == (0, 0)


def test_item_with_no_timestamp_is_left_alone():
    # Without a timestamp its age is unknowable; deleting evidence on a guess
    # is worse than leaving it.
    data = {"cimian": {"items": [{"itemName": "X", "currentStatus": "Error", "lastError": "boom"}]}}
    assert _clear_stale_items_by_age(data, datetime.now(timezone.utc), 1.0) is False
    assert data["cimian"]["items"][0]["currentStatus"] == "Error"


def test_healthy_items_are_never_touched():
    data = {"cimian": {"items": [{"itemName": "A", "currentStatus": "Installed",
                                  "lastAttemptTime": "2020-01-01T00:00:00+00:00"}]}}
    assert _clear_stale_items_by_age(data, datetime.now(timezone.utc), 1.0) is False


def test_age_falls_back_through_timestamp_fields():
    now = datetime.now(timezone.utc)
    old = (now - timedelta(days=3)).isoformat()
    assert _item_attempt_age_days({"lastUpdate": old}, now) > 2.9
    assert _item_attempt_age_days({"endTime": old}, now) > 2.9
    assert _item_attempt_age_days({}, now) is None
    assert _item_attempt_age_days({"lastAttemptTime": "not-a-date"}, now) is None


# --- Counter/cleaner parity ---------------------------------------------
# A fleet-wide clear-errors run cleared 19 of ~67 flagged devices. The cause was
# not a bug in either function on its own: the counter matched any status
# *containing* "error"/"failed"/"problem"/"warning", while the cleaner tested
# membership of a hand-written set of five literals. Every status outside that
# set - and every Munki errorItems/warningItems list - counted forever. These
# assert the only property that matters: whatever the counter counts, the
# cleaner clears.

CIMIAN_COUNTED_STATUSES = [
    "Error", "Failed", "Problem", "needs_reinstall", "install_failed",
    "Install Error", "Removal Failed", "Uninstall Failed", "install-error",
    "Warning", "needs-attention", "Install Warning",
]


@pytest.mark.parametrize("status", CIMIAN_COUNTED_STATUSES)
def test_every_counted_cimian_status_is_cleared(status):
    data = {"cimian": {"items": [{"itemName": "A", "currentStatus": status}]}}
    assert _install_issue_counts(data)[:2] != (0, 0), f"{status} not counted - update this list"
    assert _clear_install_issue_fields(data) is True
    assert _install_issue_counts(data)[:2] == (0, 0)


def test_munki_run_level_item_lists_stop_counting():
    data = {"munki": {
        "errorItems": [{"name": "X", "message": "failed to install"}],
        "warningItems": [{"name": "Y", "message": "deprecated"}],
    }}
    assert _install_issue_counts(data)[2:] == (1, 1)
    assert _clear_install_issue_fields(data) is True
    assert _install_issue_counts(data)[2:] == (0, 0)


def test_clearing_is_idempotent_and_reports_no_change_when_clean():
    data = {"cimian": {"items": [{"itemName": "A", "currentStatus": "Install Error"}]},
            "munki": {"warningItems": [{"name": "Y", "message": "z"}]}}
    assert _clear_install_issue_fields(data) is True
    assert _clear_install_issue_fields(data) is False
    assert _install_issue_counts(data) == (0, 0, 0, 0)


def test_age_gated_clear_uses_the_same_flag_rule():
    old = "2020-01-01T00:00:00Z"
    data = {"cimian": {"items": [
        {"itemName": "A", "currentStatus": "needs-attention", "lastAttemptTime": old},
    ]}}
    assert _install_issue_counts(data)[:2] != (0, 0)
    assert _clear_stale_items_by_age(data, datetime.now(timezone.utc), 1.0) is True
    assert _install_issue_counts(data)[:2] == (0, 0)
