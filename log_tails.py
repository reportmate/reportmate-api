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


# ---------------------------------------------------------------------------
# Fleet sweeps: level classification and message normalisation
#
# The web viewer and the fleet endpoint must agree on what counts as an error,
# a warning or a debug line, so the vocabulary lives here. Three line shapes
# are recognised: the convention's ``[ts] LEVEL  message``, CMTrace records
# (``type="2"`` warning, ``type="3"`` error) from the Intune Management
# Extension, and the Intune MDM daemon's pipe format (``| W |`` / ``| E |``).
# JSONL events carry a ``"level"`` value, which the word patterns also match.
# ---------------------------------------------------------------------------

import re

LEVELS = ("error", "warning", "info", "debug")

_ERROR_RE = re.compile(r'\b(ERROR|ERR|FAULT|CRITICAL|FATAL)\b|type="3"|\| E \|', re.IGNORECASE)
_WARNING_RE = re.compile(r'\b(WARN|WARNING|WRN)\b|type="2"|\| W \|', re.IGNORECASE)
_DEBUG_RE = re.compile(r'\b(DEBUG|DBG|VERBOSE|TRACE)\b', re.IGNORECASE)

# Postgres flavours of the same patterns (\m and \M are its word boundaries),
# used to narrow tails inside the query when info lines are not wanted.
_SQL_PATTERNS = {
    "error": r'\m(ERROR|ERR|FAULT|CRITICAL|FATAL)\M|type="3"|\| E \|',
    "warning": r'\m(WARN|WARNING|WRN)\M|type="2"|\| W \|',
    "debug": r'\m(DEBUG|DBG|VERBOSE|TRACE)\M',
}


_STAMPED_RE = re.compile(r'^\[[^\]]+\]\s+\[?(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\]?\b', re.IGNORECASE)


def classify_line(line: str) -> str:
    """Return ``error``, ``warning``, ``debug`` or ``info`` for one log line.

    A line in the convention's shape, ``[yyyy-MM-dd HH:mm:ss] LEVEL  message``,
    is classified by its level token alone, so an INFO line that mentions
    CRITICAL stays INFO. Other shapes fall back to the word patterns.
    """
    stamped = _STAMPED_RE.match(line)
    if stamped:
        token = stamped.group(1).upper()
        if token in ("ERROR", "FATAL", "CRITICAL"):
            return "error"
        if token in ("WARN", "WARNING"):
            return "warning"
        if token == "DEBUG":
            return "debug"
        return "info"
    if _ERROR_RE.search(line):
        return "error"
    if _WARNING_RE.search(line):
        return "warning"
    if _DEBUG_RE.search(line):
        return "debug"
    return "info"


def parse_levels(raw: Optional[str]) -> List[str]:
    """Parse a comma-separated ``levels`` query value into known level names.

    Accepts ``warn`` for ``warning`` and ignores blanks and case. An empty or
    missing value means errors and warnings, which is what a sweep wants by
    default. Raises ``ValueError`` on an unknown level so the caller can 400.
    """
    wanted: List[str] = []
    for part in (raw or "").split(","):
        name = part.strip().lower()
        if not name:
            continue
        if name == "warn":
            name = "warning"
        if name not in LEVELS:
            raise ValueError(name)
        if name not in wanted:
            wanted.append(name)
    return wanted or ["error", "warning"]


def sql_pattern_for_levels(levels: List[str]) -> Optional[str]:
    """A Postgres regex that keeps only lines that can belong to ``levels``.

    Returns ``None`` when ``info`` is requested: an info line is anything that
    matches no pattern, so nothing can be filtered out in the query.
    """
    if "info" in levels:
        return None
    return "|".join(_SQL_PATTERNS[level] for level in levels if level in _SQL_PATTERNS) or None


_LEADING_STAMP = re.compile(r'^\[[^\]]*\]\s*(?:ERROR|WARN(?:ING)?|INFO|DEBUG)?\s*', re.IGNORECASE)
_CMTRACE = re.compile(r'^<!\[LOG\[([\s\S]*?)\]LOG\]!>.*$')
_DAEMON = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}:\d{3} \| [^|]+ \| [IWE] \| [^|]* \| [^|]* \| ')
_NOISE = (
    (re.compile(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[.,:]?\d*(?:Z|[+-]\d{2}:?\d{2})?'), "<ts>"),
    (re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.IGNORECASE), "<guid>"),
    (re.compile(r'\b0x[0-9a-f]+\b', re.IGNORECASE), "<hex>"),
    (re.compile(r'\d+(?:\.\d+){2,}'), "<ver>"),
    (re.compile(r'\b\d+\b'), "<n>"),
    (re.compile(r'\s+'), " "),
)


def normalize_message(line: str, width: int = 160) -> str:
    """Collapse a log line to its message shape so the same fault on many
    devices counts once: the leading stamp and level, CMTrace and daemon
    envelopes, timestamps, GUIDs, hex values, versions and numbers are
    replaced by placeholders."""
    text = line.strip()
    if text.startswith("{"):
        # A JSONL event: its message is the shape, not the envelope.
        try:
            import json as _json
            obj = _json.loads(text)
            if isinstance(obj, dict):
                for key in ("message", "msg", "status_reason", "error"):
                    value = obj.get(key)
                    if isinstance(value, str) and value.strip():
                        text = value
                        break
        except ValueError:
            pass
    cm = _CMTRACE.match(text)
    if cm:
        text = cm.group(1)
    else:
        text = _DAEMON.sub("", text)
    text = _LEADING_STAMP.sub("", text)
    for pattern, replacement in _NOISE:
        text = pattern.sub(replacement, text)
    return text.strip()[:width]
