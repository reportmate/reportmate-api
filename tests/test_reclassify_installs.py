"""Re-running the classifier over stored rows must match ingest, not approximate it.

Every item carries the state ingest decided, and the dashboard's counter columns
are stamped at the same moment, so a classifier change reaches a device only on
its next check-in — an hour for a lab machine, days for a laptop that sleeps.
This endpoint applies the current classifier to what is already stored.
"""
import ast
import pathlib

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "routers" / "admin.py"
TEXT = SOURCE.read_text(encoding="utf-8")


def _reclassify_src() -> str:
    tree = ast.parse(TEXT)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "reclassify_stored_installs":
            return ast.get_source_segment(TEXT, node) or ""
    raise AssertionError("reclassify_stored_installs not found")


def test_it_calls_the_same_two_functions_ingest_calls():
    src = _reclassify_src()
    assert "_stamp_install_items(" in src, "items must be stamped by the shared classifier"
    assert "_install_issue_counts(" in src, "counters must come from the shared classifier"


def test_it_rewrites_both_the_items_and_the_counter_columns():
    # Stamping without the counters leaves the tiles reading the old answer;
    # counters without stamping leaves the device pages reading it.
    src = _reclassify_src()
    assert "SET data = %s::jsonb" in src
    for col in ("cimian_errors", "cimian_warnings", "munki_errors", "munki_warnings"):
        assert col in src


def test_an_unchanged_row_is_not_rewritten():
    # The database is IOPS-constrained and installs holds multi-MB JSONB; a
    # blind rewrite of every row would re-TOAST the lot.
    src = _reclassify_src()
    assert "if before == after and not counters_moved:" in src
    assert "continue" in src


def test_it_reads_in_batches_and_can_be_stopped_short():
    src = _reclassify_src()
    assert "ORDER BY id" in src and "LIMIT %s" in src, "must page rather than load the table"
    assert "limit" in src, "a rehearsal against part of the fleet must be possible"


def test_it_invalidates_the_read_caches():
    # The dashboard aggregates are cached; without this the tiles keep serving
    # the pre-backfill numbers for the cache TTL.
    assert "invalidate_caches()" in _reclassify_src()


def test_it_is_a_manual_post_and_authenticated():
    assert '@router.post("/admin/installs/reclassify"' in TEXT
    idx = TEXT.index('@router.post("/admin/installs/reclassify"')
    assert "verify_authentication" in TEXT[idx:idx + 200]


def test_it_does_not_present_itself_as_a_fresh_check_in():
    # /installs/full reports installs.updated_at as collectedAt. Stamping it in
    # a maintenance rewrite made 70 devices last seen weeks to nine months ago
    # look like they had just reported, and a consumer keying on collectedAt
    # believed it.
    src = _reclassify_src()
    update = src[src.index("UPDATE installs"):]
    update = update[: update.index('"""')]
    assert "updated_at" not in update, "a reclassify must not move the freshness stamp"
