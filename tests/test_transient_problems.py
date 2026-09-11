"""An unreachable Munki server is not a failed run.

A laptop that sleeps, roams or leaves the network mid-run cannot fetch its
catalog or manifest, reports that as an error, and succeeds an hour later. The
Munki fork already logs the reasoned line as info for exactly this case
(FetchError.transientNetworkErrorCodes), but Munki 7 reports a failed catalog
twice and the caller's bare "Could not download catalog X" still lands as an
error. These pin the ingest-side suppression: the same six NSURLError codes as
the fork, the same localized descriptions as the Mac client's fallback, and
only the run-level fetches -- an item's own download failure is the item's
story.
"""
import copy
import json

from install_status import (
    SESSION_TRANSIENT_FIELD, TRANSIENT_FIELD,
    install_issue_counts, run_event_is_moot, stamp_items, suppress_transient_problems,
)

BARE = "Could not download catalog Production"
HTTP404 = "Could not retrieve catalog Production.yaml from server. HTTP error 404: Not Found"
MANIFEST_TIMEOUT = ("Could not retrieve manifest Shared/Staff/Room/Host from the server: "
                    "There was a connection error: -1001: The request timed out.")
PRIMARY_OFFLINE = ("Could not retrieve managed install primary manifest: There was a connection "
                   "error: -1009: The Internet connection appears to be offline.")
MANIFEST_404 = "Could not retrieve manifest Shared/Staff/Room/Host from the server. HTTP error 404: Not Found"
ITEM_LOST = "Download of Excel failed: error -1005: The network connection was lost."


def munki_module(errors=(), warnings=(), items=None, status=None):
    """A payload shaped the way the Mac client sends a fork run: the legacy
    flattened strings, the copied-up errorItems/warningItems, and the session."""
    error_items = [dict(e) for e in errors]
    warning_items = [dict(w) for w in warnings]
    flat_errors = "; ".join(e["message"] for e in errors)
    flat_warnings = "; ".join(w["message"] for w in warnings)
    if status is None:
        status = "Error" if errors else ("Warning" if warnings else "Active")
    munki = {
        "status": status,
        "lastRunSuccess": 0 if errors else 1,
        "items": items if items is not None else [{"name": "Excel", "currentStatus": "Installed"}],
        "errorItems": copy.deepcopy(error_items),
        "warningItems": copy.deepcopy(warning_items),
        "sessions": [{
            "session_id": "2026-09-09-0440", "status": "completed",
            "summary": {"errors": len(errors), "warnings": len(warnings)},
            "error_items": copy.deepcopy(error_items),
            "warning_items": copy.deepcopy(warning_items),
        }],
    }
    if flat_errors:
        munki["errors"] = flat_errors
    if flat_warnings:
        munki["warnings"] = flat_warnings
    return {"munki": munki}


def test_a_bare_catalog_failure_is_suppressed_everywhere_it_was_reported():
    data = munki_module(errors=[{"message": BARE}])
    assert suppress_transient_problems(data) == 3
    munki = data["munki"]
    assert "errors" not in munki
    assert munki["errorItems"] == []
    assert munki["sessions"][0]["error_items"] == []
    assert munki["sessions"][0]["summary"]["errors"] == 0
    assert munki["sessions"][0][SESSION_TRANSIENT_FIELD] == [{"level": "error", "message": BARE}]
    assert munki[TRANSIENT_FIELD] == [{"level": "error", "message": BARE}]
    assert munki["status"] == "Active"
    assert munki["lastRunSuccess"] is True
    assert install_issue_counts(data) == (0, 0, 0, 0)


def test_a_catalog_the_server_says_is_missing_is_still_an_error():
    data = munki_module(errors=[{"message": HTTP404}, {"message": BARE}])
    assert suppress_transient_problems(data) == 0
    assert data["munki"]["status"] == "Error"
    assert install_issue_counts(data)[2] == 2


def test_manifest_fetches_use_the_forks_six_codes_and_their_descriptions():
    data = munki_module(errors=[{"message": MANIFEST_TIMEOUT}, {"message": PRIMARY_OFFLINE},
                                {"message": MANIFEST_404}])
    suppress_transient_problems(data)
    munki = data["munki"]
    assert munki["errors"] == MANIFEST_404
    assert [p["message"] for p in munki["errorItems"]] == [MANIFEST_404]
    assert munki["status"] == "Error"
    assert [p["message"] for p in munki[TRANSIENT_FIELD]] == [MANIFEST_TIMEOUT, PRIMARY_OFFLINE]


def test_the_updatecheck_wrapper_goes_with_the_manifest_failure_it_repeats():
    manifest = ("Could not retrieve manifest Assigned/Staff/Room/Host from the server: "
                "There was a connection error: -1009: The Internet connection appears to be offline.")
    wrapper = ("Error during updatecheck: There was a connection error: -1009: "
               "The Internet connection appears to be offline.")
    data = munki_module(errors=[{"message": manifest}, {"message": PRIMARY_OFFLINE}, {"message": wrapper}])
    suppress_transient_problems(data)
    munki = data["munki"]
    assert "errors" not in munki
    assert munki["status"] == "Active"
    assert munki["lastRunSuccess"] is True
    assert [p["message"] for p in munki[TRANSIENT_FIELD]] == [manifest, PRIMARY_OFFLINE, wrapper]


def test_an_updatecheck_that_failed_for_a_real_reason_is_still_an_error():
    wrapper = "Error during updatecheck: Could not retrieve manifest Host from the server. HTTP error 404: Not Found"
    data = {"munki": {"status": "Error", "errors": wrapper}}
    assert suppress_transient_problems(data) == 0
    assert data["munki"]["status"] == "Error"


def test_an_items_own_download_failure_is_left_to_the_item():
    data = munki_module(warnings=[{"name": "Excel", "message": ITEM_LOST}])
    assert suppress_transient_problems(data) == 0
    assert data["munki"]["status"] == "Warning"


def test_a_transient_error_beside_real_warnings_leaves_a_warning_run():
    data = munki_module(errors=[{"message": BARE}],
                        warnings=[{"name": "Outlook", "message": "Looping install detected: Outlook"}])
    suppress_transient_problems(data)
    munki = data["munki"]
    assert munki["status"] == "Warning"
    assert munki["lastRunSuccess"] is True
    assert munki["warnings"] == "Looping install detected: Outlook"


def test_only_the_transient_line_is_taken_from_a_flat_string():
    data = {"munki": {"status": "Error", "errors": f"{BARE}; Preflight script failed"}}
    assert suppress_transient_problems(data) == 1
    assert data["munki"]["errors"] == "Preflight script failed"
    assert data["munki"]["status"] == "Error"


def test_legacy_munki_without_sessions_is_covered_too():
    data = {"munki": {"status": "Error", "lastRunSuccess": False, "errors": PRIMARY_OFFLINE}}
    assert suppress_transient_problems(data) == 1
    assert data["munki"] == {"status": "Active", "lastRunSuccess": True,
                             TRANSIENT_FIELD: [{"level": "error", "message": PRIMARY_OFFLINE}]}


def test_stamping_suppresses_first_and_is_idempotent():
    data = munki_module(errors=[{"message": BARE}])
    once = json.dumps(stamp_items(copy.deepcopy(data)), sort_keys=True)
    twice = json.dumps(stamp_items(stamp_items(copy.deepcopy(data))), sort_keys=True)
    assert once == twice
    assert '"status": "Active"' in once


def test_a_payload_with_nothing_transient_is_untouched():
    data = munki_module(errors=[{"message": MANIFEST_404}])
    before = json.dumps(data, sort_keys=True)
    assert suppress_transient_problems(data) == 0
    assert json.dumps(data, sort_keys=True) == before
    cimian = {"cimian": {"items": [], "events": [{"level": "ERROR", "message": BARE}]}}
    assert suppress_transient_problems(cimian) == 0


def test_the_run_event_goes_with_the_only_error_it_announced():
    data = stamp_items(munki_module(errors=[{"message": BARE}]))
    assert run_event_is_moot(data, "error")
    assert run_event_is_moot(data, "warning")
    assert not run_event_is_moot(data, "success")


def test_the_run_event_stays_when_real_problems_remain():
    data = stamp_items(munki_module(
        errors=[{"message": BARE}],
        warnings=[{"name": "Outlook", "message": "Looping install detected: Outlook"}],
        items=[{"name": "Outlook", "currentStatus": "Warning", "lastWarning": "Looping install detected: Outlook"}],
    ))
    assert run_event_is_moot(data, "error")
    assert not run_event_is_moot(data, "warning")
    untouched = stamp_items(munki_module(errors=[{"message": MANIFEST_404}]))
    assert not run_event_is_moot(untouched, "error")
