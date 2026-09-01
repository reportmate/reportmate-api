"""Helpers for the ``logs`` section of the management module.

Each client reports, under ``management.logs``, a list of log roots (one per
``Managed*/logs`` directory) and every root carries ``tails``: the last lines
of its most relevant logs. The tails are the bulk of the section and are only
wanted when someone opens that tool's tab, so the device, info and module
endpoints strip them and the ``/device/{serial}/logs/{tool}`` endpoint serves
one root with its tails intact. Both operations live here so the code paths
cannot drift.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _roots(management: Any) -> List[Dict[str, Any]]:
    if not isinstance(management, dict):
        return []
    logs = management.get("logs")
    if not isinstance(logs, dict):
        return []
    roots = logs.get("roots")
    if not isinstance(roots, list):
        return []
    return [r for r in roots if isinstance(r, dict)]


def strip_log_tails(management: Any) -> Any:
    """Return the management module with every log root's ``tails`` removed.

    The input is not mutated. Anything that is not the expected shape is
    returned unchanged so a malformed payload still reaches the reader, which
    is where it becomes visible.
    """
    if not isinstance(management, dict):
        return management
    logs = management.get("logs")
    if not isinstance(logs, dict) or not isinstance(logs.get("roots"), list):
        return management
    stripped = dict(management)
    stripped_logs = dict(logs)
    stripped_logs["roots"] = [
        {k: v for k, v in r.items() if k != "tails"} if isinstance(r, dict) else r
        for r in logs["roots"]
    ]
    stripped["logs"] = stripped_logs
    return stripped


def find_log_root(management: Any, tool: str) -> Optional[Dict[str, Any]]:
    """Return the log root whose ``tool`` key matches, tails included, or None."""
    wanted = (tool or "").strip().lower()
    for root in _roots(management):
        if str(root.get("tool", "")).lower() == wanted:
            return root
    return None
