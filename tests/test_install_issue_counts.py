"""Precomputed install issue counts (dashboard performance).

The ingestion path maintains per-device error/warning counters on the
installs row so the dashboard aggregates columns instead of expanding every
install item's JSONB per request. These tests pin the status-matching rules
to the ones the dashboard SQL previously applied at read time (and that
migration 0003 uses for the backfill), so all three stay in agreement.
"""

from routers.events import _install_issue_counts


def test_empty_and_missing_shapes():
    assert _install_issue_counts(None) == (0, 0, 0, 0)
    assert _install_issue_counts({}) == (0, 0, 0, 0)
    assert _install_issue_counts({"cimian": None, "munki": None}) == (0, 0, 0, 0)
    assert _install_issue_counts({"cimian": {"items": None}}) == (0, 0, 0, 0)
    # Non-list items (malformed payload) count as no items, not an error.
    assert _install_issue_counts({"cimian": {"items": "broken"}}) == (0, 0, 0, 0)


def test_cimian_error_statuses():
    items = [
        {"currentStatus": "Error"},
        {"currentStatus": "install-error"},
        {"currentStatus": "Failed"},
        {"currentStatus": "problem detected"},
        {"currentStatus": "needs_reinstall"},
        {"currentStatus": "installed"},
        {"currentStatus": ""},
        "not-a-dict",
    ]
    ce, cw, me, mw = _install_issue_counts({"cimian": {"items": items}})
    assert (ce, cw, me, mw) == (5, 0, 0, 0)


def test_cimian_warning_statuses():
    items = [
        {"currentStatus": "Warning"},
        {"currentStatus": "needs-attention"},
        {"currentStatus": "installed"},
    ]
    ce, cw, me, mw = _install_issue_counts({"cimian": {"items": items}})
    assert (ce, cw, me, mw) == (0, 2, 0, 0)


def test_munki_statuses():
    items = [
        {"status": "install_failed"},
        {"status": "Error"},
        {"status": "warning: partial"},
        {"status": "installed"},
    ]
    ce, cw, me, mw = _install_issue_counts({"munki": {"items": items}})
    # "install_failed" matches the (error|failed) rule via "failed".
    assert (ce, cw, me, mw) == (0, 0, 2, 1)


def test_mixed_sources_counted_independently():
    data = {
        "cimian": {"items": [{"currentStatus": "failed"}]},
        "munki": {"items": [{"status": "warning"}]},
    }
    assert _install_issue_counts(data) == (1, 0, 0, 1)


def test_munki_item_warning_and_error_fields_count():
    data = {"munki": {"items": [
        {"name": "FleetMate", "status": "installed", "currentStatus": "Warning", "lastWarning": "Will not attempt to remove FleetMate"},
        {"name": "Chrome", "status": "installed", "lastError": "Installer returned 1"},
        {"name": "Slack", "status": "installed"},
    ]}}
    assert _install_issue_counts(data) == (0, 0, 1, 1)


def test_munki_run_level_warnings_count_when_no_item_is_named():
    structured = {"munki": {"items": [{"name": "Slack", "status": "installed"}],
                            "warningItems": [{"message": "Could not download catalog Production"}],
                            "errorItems": []}}
    assert _install_issue_counts(structured) == (0, 0, 0, 1)
    legacy = {"munki": {"items": [{"name": "Slack", "status": "installed"}],
                        "warnings": "Download of Excel failed; Download of Word failed",
                        "errors": "Could not retrieve manifest"}}
    assert _install_issue_counts(legacy) == (0, 0, 1, 2)
