"""/installs/full must say when the installs module was last ingested.

lastSeen is the device's last check-in on ANY payload. The installs module is
published by Cimian's postflight, so it refreshes on an acting Cimian session,
not on every check-in - measured on one host as lastSeen 21:05Z against an
installs payload from 19:36Z, while the device itself had already recorded the
item as Installed at 20:35Z. Without a per-module timestamp a consumer cannot
tell a live failure from one the device resolved hours ago.
"""
import ast
import pathlib


SOURCE = pathlib.Path(__file__).resolve().parents[1] / "routers" / "fleet.py"


def _bulk_installs_full():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "get_bulk_installs_full":
            return node
    raise AssertionError("get_bulk_installs_full not found")


def test_query_selects_installs_updated_at():
    fn = _bulk_installs_full()
    sql = " ".join(
        n.value for n in ast.walk(fn)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and "FROM devices" in n.value
    )
    assert "i.updated_at" in sql, "installs.updated_at must be selected to expose collectedAt"


def test_response_exposes_collected_at_on_the_installs_module():
    fn = _bulk_installs_full()
    keys = [
        n.value for n in ast.walk(fn)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]
    assert "collectedAt" in keys, "the installs module must carry collectedAt"


def test_collected_at_is_distinct_from_last_seen():
    """Guards the actual regression: reusing last_seen would look correct and be wrong."""
    fn = _bulk_installs_full()
    src = ast.get_source_segment(SOURCE.read_text(encoding="utf-8"), fn) or ""
    idx = src.find("'collectedAt'")
    assert idx != -1
    assignment = src[idx:idx + 200]
    assert "installs_updated_at" in assignment, "collectedAt must come from installs.updated_at"
    assert "last_seen" not in assignment, "collectedAt must not be derived from last_seen"
