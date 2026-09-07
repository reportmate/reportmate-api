"""A managed-software run's events replace the previous run's.

The regression this guards: a device hit a transient catalog fetch failure, the
run reported one error and 176 warnings, and every clean run after it added its
own events beside them instead of superseding them. Hours later the dashboard
still counted the device as erroring, and its Installs tab still carried a red
"last run failed" box, while the device itself had been clean for two runs.

Ingest is one long async endpoint against a live connection, so these read its
source: what matters is that the delete happens, that it is keyed on the device
and bounded by the payload's own timestamp, and that events are stored with the
module they belong to.
"""
import ast
import pathlib

import pytest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "routers" / "events.py"
TEXT = SOURCE.read_text(encoding="utf-8")


def _submit_events_source() -> str:
    tree = ast.parse(TEXT)
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "submit_events":
            return ast.get_source_segment(TEXT, node) or ""
    raise AssertionError("submit_events not found")


@pytest.fixture(scope="module")
def submit_events_src():
    return _submit_events_source()


def test_run_scoped_modules_are_named():
    from routers.events import INSTALLS_EVENT_MODULES

    # managedinstalls and munkireport are what the Mac client calls the same
    # run on a payload without structured sessions; all three have to be swept
    # together or the older shape survives the run that fixed it.
    assert set(INSTALLS_EVENT_MODULES) == {"installs", "managedinstalls", "munkireport"}


def test_a_fresh_run_deletes_the_previous_runs_events(submit_events_src):
    delete = submit_events_src[submit_events_src.index("DELETE FROM events"):]
    delete = delete[: delete.index('"""')]
    assert "device_id = %s" in delete, "the sweep must be scoped to one device"
    assert "module_id = ANY(%s)" in delete
    assert "timestamp <= %s" in delete, "a late payload must not delete a newer run"


def test_the_sweep_runs_on_the_module_not_on_the_events(submit_events_src):
    # A run that installed nothing and errored on nothing sends no installs
    # events at all. Keying the sweep on the events present would leave the
    # previous run's error standing for exactly the run that disproved it.
    gate = submit_events_src.index("if has_installs_module:")
    assert gate < submit_events_src.index("DELETE FROM events")
    assert submit_events_src.index("DELETE FROM events") < submit_events_src.index("for event in payload_events:")


def test_legacy_events_without_a_module_id_are_swept_too(submit_events_src):
    # Rows stored before ingest named the module carry no module_id; they are
    # recognisable as a run's own events by the run they are stamped with.
    delete = submit_events_src[submit_events_src.index("DELETE FROM events"):]
    delete = delete[: delete.index('"""')]
    assert "module_id IS NULL" in delete
    assert "jsonb_exists(details, 'session_id')" in delete
    assert "jsonb_exists(details, 'module_status')" in delete


def test_events_are_stored_with_their_module_id(submit_events_src):
    insert = submit_events_src[submit_events_src.index("INSERT INTO events"):]
    insert = insert[: insert.index('"""')]
    assert "module_id" in insert, "every event must carry the module it came from"


def test_an_unnamed_run_event_is_attributed_to_installs(submit_events_src):
    # Clients that predate moduleId on the wire still send the run's outcome.
    assert "module_id = 'installs'" in submit_events_src


def test_os_update_still_keeps_only_the_latest(submit_events_src):
    # os_update is sent only when the version changed, so it cannot ride on the
    # installs sweep; it supersedes its own predecessor.
    assert "module_id = 'os_update'" in submit_events_src
