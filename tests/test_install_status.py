"""One ladder decides an item's state, for Munki and Cimian alike.

Munki and Cimian are the two halves of one deployment story and their clients
already agree on the wire -- both fill currentStatus/mappedStatus from the same
Installed/Pending/Warning/Error/Removed vocabulary, both carry lastAttemptStatus
and lastError/lastWarning. Three consumers used to classify that payload three
different ways, each convinced Munki was the odd one out. These pin the shared
ladder so a fourth cannot appear.
"""
import pytest

from install_status import (
    ERROR, WARNING, PENDING, INSTALLED, REMOVED, STATE_FIELD,
    classify_item, install_issue_counts, item_state_totals, stamp_items,
)


# --- the vocabulary both clients write -------------------------------------

@pytest.mark.parametrize("status,expected", [
    ("Installed", INSTALLED), ("installed", INSTALLED), ("success", INSTALLED),
    ("Pending", PENDING), ("Pending Install", PENDING), ("update-available", PENDING),
    ("Update Available", PENDING), ("update_available", PENDING), ("Skipped", PENDING),
    ("Warning", WARNING), ("needs-attention", WARNING), ("Not Installed", WARNING),
    ("Install Loop", WARNING),
    ("Error", ERROR), ("failed", ERROR), ("install_failed", ERROR), ("needs_reinstall", ERROR),
    ("Removed", REMOVED),
])
def test_the_shared_vocabulary_maps_the_same_on_both_platforms(status, expected):
    assert classify_item({"currentStatus": status}) == expected
    assert classify_item({"mappedStatus": status}) == expected


def test_one_state_is_spelled_three_ways_and_all_three_land_together():
    # "Update Available", "update-available" and "update_available" all appear
    # in live payloads; so do "Pending Install" and "pending_install".
    for spelling in ("Update Available", "update-available", "update_available"):
        assert classify_item({"currentStatus": spelling}) == PENDING


def test_not_installed_is_a_warning_not_an_installed_item():
    # It contains the word "installed" but means the opposite: the package is
    # managed, was expected, and is absent. Cimian's own mapper agrees.
    assert classify_item({"currentStatus": "Not Installed"}) == WARNING


def test_a_status_naming_a_failure_beats_the_word_install_inside_it():
    # "install_failed" and "needs_reinstall" both contain "install"; neither is
    # an installed item.
    assert classify_item({"currentStatus": "install_failed"}) == ERROR
    assert classify_item({"currentStatus": "needs_reinstall"}) == ERROR


# --- presence is not an outcome --------------------------------------------

def test_installed_does_not_mask_a_failed_attempt():
    # Both tools report an item as Installed while recording that the most
    # recent attempt failed. Reading the status alone loses every one of them.
    assert classify_item({"status": "installed", "lastError": "Installer returned 1"}) == ERROR
    assert classify_item({"currentStatus": "Installed", "lastAttemptStatus": "Failed"}) == ERROR
    assert classify_item({"currentStatus": "Installed", "lastAttemptStatus": "Warning"}) == WARNING


def test_a_status_that_names_a_problem_wins_over_the_message():
    assert classify_item({"currentStatus": "Error", "lastWarning": "something milder"}) == ERROR


def test_an_error_outranks_a_warning_on_the_same_item():
    assert classify_item({"status": "installed", "lastError": "boom", "lastWarning": "hmm"}) == ERROR


def test_legacy_munki_has_only_the_message():
    # Munki without the fork's session reports writes no normalized status.
    assert classify_item({"name": "Chrome", "status": "installed"}) == INSTALLED
    assert classify_item({"name": "Chrome", "status": "installed", "lastWarning": "Download failed"}) == WARNING


def test_an_unreadable_item_is_left_alone():
    assert classify_item({}) is None
    assert classify_item("nonsense") is None
    assert classify_item({"currentStatus": ""}) is None


# --- install loops ----------------------------------------------------------

def test_a_looping_item_is_at_least_a_warning_whatever_it_reports():
    # Cimian's mapper takes a hasInstallLoop argument and never reads it, and
    # the Mac client forwards the flag only when the fork set it, so a package
    # reinstalling every run can arrive looking perfectly healthy.
    assert classify_item({"currentStatus": "Installed", "hasInstallLoop": True}) == WARNING
    assert classify_item({"currentStatus": "Installed", "installLoopDetected": True}) == WARNING
    assert classify_item({"status": "installed", "hasInstallLoop": True}) == WARNING


def test_a_loop_does_not_downgrade_a_real_error():
    assert classify_item({"currentStatus": "Error", "hasInstallLoop": True}) == ERROR


def test_a_healthy_item_is_not_a_warning_just_for_carrying_the_flag():
    assert classify_item({"currentStatus": "Installed", "hasInstallLoop": False}) == INSTALLED


# --- pending is its own state ----------------------------------------------

def test_pending_is_never_counted_as_a_warning():
    # Conflating them is what made one endpoint report 108 devices with
    # warnings where the dashboard reported 23.
    data = {"cimian": {"items": [
        {"currentStatus": "Pending"},
        {"currentStatus": "Update Available"},
        {"currentStatus": "Installed"},
    ]}}
    assert install_issue_counts(data) == (0, 0, 0, 0)
    assert item_state_totals(data)[PENDING] == 2


# --- run-level problems, on both platforms ---------------------------------

def test_both_platforms_fall_back_to_run_level_problems():
    # Cimian had no run-level fallback at all, so a Cimian run that failed
    # without naming an item counted as nothing while the same Munki run
    # counted -- one product disagreeing with itself about a failed run.
    cimian = {"cimian": {"items": [{"currentStatus": "Installed"}],
                         "errorItems": [{"message": "Could not reach the repo"}]}}
    munki = {"munki": {"items": [{"status": "installed"}],
                       "errorItems": [{"message": "Could not download catalog Production"}]}}
    assert install_issue_counts(cimian)[0] == 1
    assert install_issue_counts(munki)[2] == 1


def test_run_level_problems_do_not_double_count_attributed_ones():
    data = {"munki": {"items": [{"status": "installed", "lastError": "boom"}],
                      "errorItems": [{"message": "boom"}]}}
    assert install_issue_counts(data)[2] == 1


def test_the_legacy_semicolon_strings_still_count():
    data = {"munki": {"items": [], "errors": "one failed; another failed",
                      "warnings": "something looked odd"}}
    assert install_issue_counts(data)[2:] == (2, 1)


# --- stamping ---------------------------------------------------------------

def test_every_item_is_stamped_with_its_state():
    data = {"munki": {"items": [{"currentStatus": "Error"}, {"currentStatus": "Installed"}]},
            "cimian": {"items": [{"currentStatus": "Warning"}]}}
    stamp_items(data)
    assert [i[STATE_FIELD] for i in data["munki"]["items"]] == [ERROR, INSTALLED]
    assert data["cimian"]["items"][0][STATE_FIELD] == WARNING


def test_stamping_is_stable_so_the_unchanged_payload_fast_path_still_matches():
    # Ingest skips rewriting multi-MB JSONB when the payload compares equal;
    # a stamp that varied between identical runs would defeat that.
    import copy, json
    data = {"cimian": {"items": [{"currentStatus": "Installed", "itemName": "A"}]}}
    once = json.dumps(stamp_items(copy.deepcopy(data)), sort_keys=True)
    twice = json.dumps(stamp_items(stamp_items(copy.deepcopy(data))), sort_keys=True)
    assert once == twice


def test_an_unclassifiable_item_carries_no_stale_stamp():
    data = {"cimian": {"items": [{STATE_FIELD: ERROR}]}}
    stamp_items(data)
    assert STATE_FIELD not in data["cimian"]["items"][0]


def test_a_payload_that_is_not_a_dict_is_returned_untouched():
    assert stamp_items(None) is None
    assert install_issue_counts(None) == (0, 0, 0, 0)


# --- pending is a standing, not a verdict on the last attempt --------------

def test_a_pending_item_keeps_the_warning_its_attempt_recorded():
    # Munki reports these as pending_install with the message attached. Letting
    # the Pending status win dropped 36 real warnings across 16 Macs.
    item = {"status": "pending_install", "currentStatus": "Pending",
            "lastWarning": "Download of Excel failed: error -1001"}
    assert classify_item(item) == WARNING


def test_a_clean_pending_item_stays_pending():
    assert classify_item({"currentStatus": "Pending"}) == PENDING


def test_the_loop_flag_is_read_whether_it_arrives_as_true_or_as_one():
    # Cimian sends a boolean; the Mac client's value arrives as 1, so an
    # identity check against True missed every real Munki loop.
    assert classify_item({"currentStatus": "Installed", "hasInstallLoop": 1}) == WARNING
    assert classify_item({"currentStatus": "Installed", "hasInstallLoop": True}) == WARNING
    assert classify_item({"currentStatus": "Installed", "hasInstallLoop": 0}) == INSTALLED
    assert classify_item({"currentStatus": "Installed", "hasInstallLoop": "false"}) == INSTALLED
