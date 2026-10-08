"""/installs/full must carry Cimian's module-level session counters.

The projection used to copy items, config, version, status and the last five
sessions, and drop totalSessions. Consumers then read 0 on every Windows device
in a fleet sweep while /device/{serial} returned the real count, so loop and
session history looked absent fleet-wide. The truncated sessions list cannot
stand in for the counter.
"""

import ast
import pathlib

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "routers" / "fleet.py"


def _cimian_projection():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "get_bulk_installs_full":
            fn = node
            break
    else:
        raise AssertionError("get_bulk_installs_full not found")
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Subscript)
            and isinstance(node.targets[0].slice, ast.Constant)
            and node.targets[0].slice.value == "cimian"
            and isinstance(node.value, ast.Dict)
        ):
            return node.value
    raise AssertionError("cimian projection dict not found")


def _projected(field):
    proj = _cimian_projection()
    for key, value in zip(proj.keys, proj.values):
        if isinstance(key, ast.Constant) and key.value == field:
            return value
    return None


def test_total_sessions_survives_the_projection():
    value = _projected("totalSessions")
    assert value is not None, "cimian.totalSessions must be passed through"
    src = ast.unparse(value)
    assert (
        "cimian_data" in src and "'totalSessions'" in src
    ), "totalSessions must come from the stored cimian module, not be recomputed"


def test_session_summary_fields_survive_the_projection():
    for field in ("lastSessionTime", "lastRun"):
        value = _projected(field)
        assert value is not None, f"cimian.{field} must be passed through"
        assert f"'{field}'" in ast.unparse(value)


def test_items_and_sessions_still_projected():
    for field in ("items", "sessions"):
        assert (
            _projected(field) is not None
        ), f"cimian.{field} must stay in the projection"
