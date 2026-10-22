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
    (re.compile(r'(?<![\w<])(?:[A-Za-z]:\\[^\s"\']*|~?/(?:[^\s"\'/]+/)+[^\s"\']*)'), "<path>"),
    (re.compile(r'\d+(?:\.\d+){2,}'), "<ver>"),
    (re.compile(r'\b\d+\b'), "<n>"),
    (re.compile(r'\s+'), " "),
)


# A leading timestamp in any of the shapes the tools write, raw or already
# replaced by its placeholder, with an optional UTC offset after it.
_PREFIX_STAMP = re.compile(
    r'^\[?(?:<ts>|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,:]\d+)?'
    r'|[A-Z][a-z]{2} \d{1,2} (?:\d{4} )?\d{2}:\d{2}:\d{2})'
    r'(?:\s*(?:Z|[+-]\d{2}:?\d{2}|[+-]<n>(?::<n>)?))?\]?\s*'
)
_PREFIX_OFFSET = re.compile(r'^(?:Z|[+-]\d{2}:?\d{2}|[+-]<n>(?::<n>)?)(?=\s)\s*')
_LEVEL_WORDS = r'ERROR|ERR|WARNING|WARN|WRN|INFO|INF|DEBUG|DBG|FATAL|CRITICAL|TRACE|VERBOSE|NOTICE'
_PREFIX_LEVEL = re.compile(
    r'^(?:\[(?:' + _LEVEL_WORDS + r'|E|W|I|D)\]|(?:' + _LEVEL_WORDS + r')(?=[\s:])):?\s*',
    re.IGNORECASE,
)
_PREFIX_SEPARATOR = re.compile(r'^[|:\-]\s+')


def strip_message_prefix(text: str) -> str:
    """Drop the leading timestamp, UTC offset, level and separators from a log
    message, raw or normalised: ``<ts> -<n>:<n> [ERR] Device registration
    failed`` and ``2026-10-22 13:44:00 -07:00 ERROR Device registration
    failed`` both become ``Device registration failed``."""
    for _ in range(6):
        before = text
        for pattern in (_PREFIX_STAMP, _PREFIX_OFFSET, _PREFIX_LEVEL, _PREFIX_SEPARATOR):
            text = pattern.sub("", text, count=1)
        if text == before:
            break
    return text.strip()


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
    text = strip_message_prefix(text)
    for pattern, replacement in _NOISE:
        text = pattern.sub(replacement, text)
    return strip_message_prefix(text.strip())[:width]


# ---------------------------------------------------------------------------
# Level summaries, stamped onto each log root at ingest
#
# The dashboard counts errors and warnings per management tool across the
# fleet. Classifying every tailed line of every device at query time would
# mean shipping all the tails to Python on every refresh, so ingest does it
# once per check-in and stores a few hundred bytes per root under
# ``levelSummary``: error and warning line counts per UTC hour, and the most
# frequent normalised error messages with the hour they were last seen. The
# fleet aggregate is then plain SQL over those summaries.
#
# Lines are parsed the way the Mac app's ManagementLogs.parseStructured reads
# them (convention, bracket stamp, CMTrace, Intune daemon, Munki, syslog, ISO
# stamp, JSONL events). The summary depends only on the payload, never on the
# clock, so a repeated identical check-in stamps identical JSON and ingest's
# unchanged-payload fast path still holds. Times without a zone are taken as
# UTC; a line with no time takes its root's newestModified hour.
# ---------------------------------------------------------------------------

from datetime import datetime, timezone

SUMMARY_FIELD = "levelSummary"
SUMMARY_VERSION = 1
SUMMARY_MAX_MESSAGES = 20
SUMMARY_MAX_HOURS = 168

_P_CONVENTION = re.compile(r'^\[(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})\]\s+(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\s+(.*)$', re.S)
_P_BRACKET_STAMP = re.compile(r'^\[(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:[.,]\d+)?\]\s*(.*)$', re.S)
_P_BRACKET_LEVEL = re.compile(r'^\[(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\]\s*(.*)$', re.I | re.S)
_P_CMTRACE = re.compile(r'^<!\[LOG\[(.*?)\]LOG\]!><time="([^"]*)"\s+date="([^"]*)"\s+component="([^"]*)"(?:\s+context="[^"]*")?\s+type="(\d)"', re.S)
_P_DAEMON = re.compile(r'^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}):(\d{3}) \| ([^|]+?) \| ([IWE]) \| ', re.S)
_P_MUNKI = re.compile(r'^([A-Z][a-z]{2}) (\d{2}) (\d{4}) (\d{2}:\d{2}:\d{2}) ([+-]\d{4}) (.*)$', re.S)
_P_SYSLOG = re.compile(r'^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?:[+-]\d{2})? (\S+) ([^\[:\s]+)(?:\[\d+\])?: (.*)$', re.S)
_P_STAMPED = re.compile(r'^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:[.,:]\d+)?(Z|[+-]\d{2}:?\d{2})?\s+(.*)$', re.S)
_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_CMTRACE_CLOSE = re.compile(r'\]LOG\]!>.*>\s*$', re.S)


def _level_word(value: Any) -> str:
    """``levelTone`` in the Mac app: a level field's value as a level."""
    v = str(value or "").upper()
    if v.startswith("ERR") or v in ("FAULT", "CRITICAL", "FATAL"):
        return "error"
    if v.startswith("WARN") or v == "WRN":
        return "warning"
    if v.startswith("DEBUG") or v in ("DBG", "VERBOSE", "TRACE"):
        return "debug"
    return "info"


def _utc(day: str, clock: str, zone: Optional[str] = None) -> Optional[datetime]:
    try:
        stamp = datetime.fromisoformat(f"{day}T{clock}")
    except ValueError:
        return None
    if zone:
        z = zone.replace(":", "")
        if z == "Z":
            return stamp.replace(tzinfo=timezone.utc)
        try:
            return datetime.fromisoformat(f"{day}T{clock}{z[:3]}:{z[3:5]}").astimezone(timezone.utc)
        except ValueError:
            pass
    return stamp.replace(tzinfo=timezone.utc)


def _parse_any_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_line(line: str, jsonl: bool = False):
    """``(time, level)`` for one tailed line; time is None when it carries none."""
    if jsonl:
        text = line.strip()
        if text.startswith("{"):
            try:
                import json as _json
                obj = _json.loads(text)
            except ValueError:
                obj = None
            if isinstance(obj, dict):
                when = next((obj[k] for k in ("timestamp", "time", "ts", "date") if isinstance(obj.get(k), str)), None)
                level = next((obj[k] for k in ("level", "severity") if isinstance(obj.get(k), str)), None)
                return _parse_any_time(when), _level_word(level)
        return None, classify_line(line)

    m = _P_CONVENTION.match(line)
    if m:
        return _utc(m.group(1), m.group(2)), _level_word(m.group(3))
    m = _P_BRACKET_STAMP.match(line)
    if m:
        rest = m.group(3)
        lv = _P_BRACKET_LEVEL.match(rest)
        return _utc(m.group(1), m.group(2)), (_level_word(lv.group(1)) if lv else classify_line(rest))
    m = _P_CMTRACE.match(line)
    if m:
        clock, date_ = re.sub(r"[+-]\d+$", "", m.group(2)), m.group(3).split("-")
        when = None
        if len(date_) == 3:
            when = _utc(f"{date_[2]}-{date_[0].zfill(2)}-{date_[1].zfill(2)}", clock.split(".")[0])
        return when, {"3": "error", "2": "warning"}.get(m.group(5), "info")
    m = _P_DAEMON.match(line)
    if m:
        return _utc(m.group(1), m.group(2)), {"E": "error", "W": "warning"}.get(m.group(5), "info")
    m = _P_MUNKI.match(line)
    if m:
        month = _MONTHS.get(m.group(1))
        when = _utc(f"{m.group(3)}-{month:02d}-{m.group(2)}", m.group(4), m.group(5)) if month else None
        return when, classify_line(m.group(6))
    m = _P_SYSLOG.match(line)
    if m:
        return _utc(m.group(1), m.group(2)), classify_line(m.group(5))
    m = _P_STAMPED.match(line)
    if m:
        return _utc(m.group(1), m.group(2), m.group(3)), classify_line(m.group(4))
    return None, classify_line(line)


def stitch_cmtrace(lines: List[str]) -> List[str]:
    """Rejoin a CMTrace record whose message spanned several tailed lines."""
    out: List[str] = []
    open_record: Optional[str] = None
    for line in lines:
        if open_record is not None:
            open_record += "\n" + line
            if _CMTRACE_CLOSE.search(line):
                out.append(open_record)
                open_record = None
            continue
        if line.startswith("<![LOG[") and not _CMTRACE_CLOSE.search(line):
            open_record = line
            continue
        out.append(line)
    if open_record is not None:
        out.append(open_record)
    return out


def _hour(when: Optional[datetime]) -> Optional[str]:
    return when.strftime("%Y-%m-%dT%H") if when else None


def summarize_root(root: Dict[str, Any]) -> Dict[str, Any]:
    """The ``levelSummary`` for one log root, from its tails."""
    fallback = _hour(_parse_any_time(root.get("newestModified")))
    hours: Dict[str, List[int]] = {}
    undated = [0, 0]
    messages: Dict[str, List[Any]] = {}
    tails = root.get("tails") if isinstance(root.get("tails"), list) else []
    for tail in tails:
        if not isinstance(tail, dict) or not isinstance(tail.get("lines"), list):
            continue
        name = str(tail.get("file") or "").lower()
        if name.endswith(".json"):
            continue
        jsonl = name.endswith(".jsonl")
        lines = [l for l in tail["lines"] if isinstance(l, str)]
        for line in (lines if jsonl else stitch_cmtrace(lines)):
            when, level = parse_line(line, jsonl)
            if level not in ("error", "warning"):
                continue
            slot = 0 if level == "error" else 1
            hour = _hour(when) or fallback
            if hour is None:
                undated[slot] += 1
                continue
            hours.setdefault(hour, [0, 0])[slot] += 1
            if level == "error":
                key = normalize_message(line)
                entry = messages.setdefault(key, [0, hour])
                entry[0] += 1
                if hour > entry[1]:
                    entry[1] = hour
    kept_hours = dict(sorted(hours.items())[-SUMMARY_MAX_HOURS:])
    top = sorted(messages.items(), key=lambda kv: (-kv[1][0], kv[0]))[:SUMMARY_MAX_MESSAGES]
    return {
        "v": SUMMARY_VERSION,
        "hours": kept_hours,
        "undated": undated,
        "errors": [{"m": m, "n": n, "last": last} for m, (n, last) in top],
    }


def stamp_log_summaries(management: Any) -> Any:
    """Write ``levelSummary`` onto every log root of a management module, in place."""
    target = management[0] if isinstance(management, list) and len(management) == 1 else management
    for root in _roots(target):
        try:
            root[SUMMARY_FIELD] = summarize_root(root)
        except Exception:
            root.pop(SUMMARY_FIELD, None)
    return management
