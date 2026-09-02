"""Clearing an installs payload must also zero the dashboard's counters.

The regression this guards: clear-errors rewrote installs.data and nothing else.
The dashboard does not read that JSONB - it sums the precomputed
cimian_errors / cimian_warnings / munki_errors / munki_warnings columns that
ingest maintains - so a cleanup left /installs/full clean while the dashboard
cards did not move at all, which is the one place anyone looks.

These exercise the endpoint's own clearing function against the ingest's own
counting function, so the two can only agree.
"""
from routers.admin import _clear_install_issue_fields
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
