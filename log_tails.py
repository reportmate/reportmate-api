"""Helpers for the ``logs`` module payload.

Each client reports a list of log roots (one per ``Managed*/logs`` directory)
and every root carries ``tails``: the last lines of its most relevant logs.
The tails are the bulk of the module and are only wanted when someone opens
that tool's tab, so the device and module endpoints strip them and the
``/device/{serial}/logs/{tool}`` endpoint serves one root with its tail
intact. Both operations live here so the two code paths cannot drift.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _roots(module_data: Any) -> List[Dict[str, Any]]:
    if not isinstance(module_data, dict):
        return []
    roots = module_data.get("roots")
    if not isinstance(roots, list):
        return []
    return [r for r in roots if isinstance(r, dict)]


def strip_log_tails(module_data: Any) -> Any:
    """Return the module with every root's ``tails`` removed.

    The input is not mutated. Anything that is not the expected shape is
    returned unchanged so a malformed payload still reaches the reader, which
    is where it becomes visible.
    """
    if not isinstance(module_data, dict) or not isinstance(
        module_data.get("roots"), list
    ):
        return module_data
    stripped = dict(module_data)
    stripped["roots"] = [
        {k: v for k, v in r.items() if k != "tails"} if isinstance(r, dict) else r
        for r in module_data["roots"]
    ]
    return stripped


def find_log_root(module_data: Any, tool: str) -> Optional[Dict[str, Any]]:
    """Return the root whose ``tool`` key matches, tail included, or None."""
    wanted = (tool or "").strip().lower()
    for root in _roots(module_data):
        if str(root.get("tool", "")).lower() == wanted:
            return root
    return None
