"""One definition of what a managed-software item's state is.

Munki and Cimian are the macOS and Windows halves of the same deployment story,
and their clients already agree on the wire: both fill ``currentStatus`` and
``mappedStatus`` from the same vocabulary -- Installed, Pending, Warning, Error,
Removed -- alongside ``lastAttemptStatus``, ``lastError`` and ``lastWarning``.
The Munki fork's session logger writes it in ``reports/items.json`` and the Mac
client copies it onto the item; Cimian writes it directly.

What did not agree was everything downstream. Ingest, the dashboard aggregate
and the web classified items with three different ladders, each carrying a
comment asserting that Munki "keeps status factual and never says warning" --
true of Munki before the fork's session reports, and false of every device that
now runs it. So the same fleet produced different counts depending on which
consumer was asked.

This module is the single ladder, applied identically to both platforms:

1. A status that names a problem or an intention -- Error, Warning, Pending --
   is the answer, from ``currentStatus``, ``mappedStatus`` or ``status``.
2. Otherwise the status only claims the package is *present* (Installed,
   Removed), which is not a claim that the last attempt went well. Both tools
   report an item as Installed while recording a failed or warned attempt
   against it, so ``lastAttemptStatus`` and then ``lastError`` / ``lastWarning``
   decide -- and they are also all that legacy Munki, which has no normalized
   status at all, ever provides.
3. Failing all of that, the presence status stands, or the item is left
   unclassified.

An item the install-loop guard has flagged is at least a warning, whatever its
status says. Both tools detect loops -- Cimian in its own items.json, Munki in
the fork's LoopGuard -- but neither reliably says so in the status: Cimian's
mapper takes a hasInstallLoop argument and never reads it, and the Mac client
only forwards the flag when the fork happened to set it. Deciding it here means
the fleet is right now, rather than after two client rollouts.

Anything the ladder cannot place is left unclassified rather than guessed.

Pending is a state of its own and is never counted as a warning. An item
waiting to install is outstanding work, not a problem, and conflating the two
is what made one endpoint report 108 devices with warnings where the dashboard
reported 23.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

#: The field ingest stamps on every item, so no consumer has to re-derive it.
STATE_FIELD = "reportmateStatus"

ERROR = "error"
WARNING = "warning"
PENDING = "pending"
INSTALLED = "installed"
REMOVED = "removed"

PLATFORM_SOURCES = ("cimian", "munki")

# Ordered: a status naming a failure is a failure even when it also contains
# "install" ("install_failed", "needs_reinstall", "install-error").
_ERROR_TOKENS = ("error", "failed", "failure", "problem")
_ERROR_EXACT = ("needs-reinstall",)
_WARNING_TOKENS = ("warning", "install-loop")
# Cimian's own mapper reads "not installed" as a warning: the package is
# managed, was expected, and is not there.
_WARNING_EXACT = ("needs-attention", "not-installed")
_PENDING_TOKENS = (
    "pending", "will-be-installed", "update-available", "will-be-removed",
    "scheduled", "install-requested", "removal-requested", "available",
    "downloading", "installing", "skipped", "unknown",
)
_REMOVED_TOKENS = ("removed", "uninstalled")
_INSTALLED_EXACT = ("installed", "install-succeeded", "completed", "success")


# Kept here so the clear-errors admin paths match the ladder above rather than
# carrying their own copies; they decide which stored fields to blank, not what
# a state is, so they stay pattern-based.
import re

_CIMIAN_ERROR_RE = re.compile(r"(error|failed|problem|install-error)")
_CIMIAN_WARNING_RE = re.compile(r"(warning|needs-attention)")
_MUNKI_ERROR_RE = re.compile(r"(error|failed)")


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _state_from_status(raw: Any) -> Optional[str]:
    """Map one status string onto a state, or None when it says nothing."""
    # Both tools spell the same state with spaces, hyphens or underscores
    # ("Update Available", "update-available", "update_available"); normalize so
    # one token list covers all three.
    status = _text(raw).lower().replace(" ", "-").replace("_", "-")
    if not status:
        return None
    if status in _ERROR_EXACT or any(t in status for t in _ERROR_TOKENS):
        return ERROR
    if status in _WARNING_EXACT or any(t in status for t in _WARNING_TOKENS):
        return WARNING
    if any(t in status for t in _PENDING_TOKENS):
        return PENDING
    if any(t in status for t in _REMOVED_TOKENS):
        return REMOVED
    if status in _INSTALLED_EXACT:
        return INSTALLED
    return None


def _has_install_loop(item: Dict[str, Any]) -> bool:
    """Whether the install-loop guard flagged this item, under either name.

    Cimian writes both hasInstallLoop and installLoopDetected; the Mac client
    forwards only the first, and only when the fork set it. Read either.
    """
    for key in ("hasInstallLoop", "installLoopDetected"):
        if item.get(key) is True:
            return True
    return False


def classify_item(item: Any) -> Optional[str]:
    """The state of one reported item, by the shared ladder."""
    if not isinstance(item, dict):
        return None

    presence = None
    for key in ("currentStatus", "mappedStatus", "status"):
        state = _state_from_status(item.get(key))
        if state in (ERROR, WARNING, PENDING):
            return WARNING if state != ERROR and _has_install_loop(item) else state
        if state is not None and presence is None:
            presence = state  # Installed / Removed: presence, not outcome.

    attempt = _state_from_status(item.get("lastAttemptStatus"))
    if attempt in (ERROR, WARNING):
        return WARNING if attempt != ERROR and _has_install_loop(item) else attempt

    # An error outranks a warning on the same item.
    if _text(item.get("lastError")):
        return ERROR
    if _text(item.get("lastWarning")) or _has_install_loop(item):
        return WARNING
    return presence


def _items(source: Dict[str, Any]) -> List[Dict[str, Any]]:
    items = source.get("items")
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []


def _run_problems(source: Dict[str, Any], key: str, legacy_key: str) -> List[Dict[str, Any]]:
    """Run-level problems the client could not attribute to an item.

    Both platforms get this. Cimian previously had no run-level fallback at all,
    so a Cimian run that failed without naming an item counted as nothing, while
    the same Munki run counted -- the two halves of one product disagreeing about
    whether a failed run had happened.
    """
    entries = source.get(key)
    if isinstance(entries, list):
        return [e for e in entries if isinstance(e, dict) and (e.get("message") or e.get("name"))]
    legacy = source.get(legacy_key)
    if isinstance(legacy, str) and legacy.strip():
        return [{"message": part.strip()} for part in legacy.split(";") if part.strip()]
    return []


def stamp_items(module_data: Any) -> Any:
    """Write each item's state onto it, in place, for both platforms.

    Deterministic: the same payload stamps to the same JSON, so ingest's
    unchanged-payload fast path still compares equal on a repeat check-in.
    """
    if not isinstance(module_data, dict):
        return module_data
    for platform in PLATFORM_SOURCES:
        source = module_data.get(platform)
        if not isinstance(source, dict):
            continue
        for item in _items(source):
            state = classify_item(item)
            if state is None:
                item.pop(STATE_FIELD, None)
            else:
                item[STATE_FIELD] = state
    return module_data


def _counts_for(source: Any) -> Tuple[int, int]:
    """(errors, warnings) for one platform's section of the installs module."""
    if not isinstance(source, dict):
        return (0, 0)
    states = [classify_item(i) for i in _items(source)]
    errors = sum(1 for s in states if s == ERROR)
    warnings = sum(1 for s in states if s == WARNING)
    # Run-level problems stand in only when no item carried one, so a run whose
    # problems are all attributed is not counted twice.
    if errors == 0:
        errors = len(_run_problems(source, "errorItems", "errors"))
    if warnings == 0:
        warnings = len(_run_problems(source, "warningItems", "warnings"))
    return (errors, warnings)


def install_issue_counts(module_data: Any) -> Tuple[int, int, int, int]:
    """(cimian_errors, cimian_warnings, munki_errors, munki_warnings).

    Feeds the precomputed columns the dashboard tiles count devices from.
    Pending never contributes.
    """
    data = module_data if isinstance(module_data, dict) else {}
    cimian_errors, cimian_warnings = _counts_for(data.get("cimian"))
    munki_errors, munki_warnings = _counts_for(data.get("munki"))
    return (cimian_errors, cimian_warnings, munki_errors, munki_warnings)


def item_state_totals(module_data: Any) -> Dict[str, int]:
    """Item counts per state across both platforms, for callers that want the
    whole picture rather than just the two problem states."""
    data = module_data if isinstance(module_data, dict) else {}
    totals: Dict[str, int] = {ERROR: 0, WARNING: 0, PENDING: 0, INSTALLED: 0, REMOVED: 0}
    for platform in PLATFORM_SOURCES:
        source = data.get(platform)
        if not isinstance(source, dict):
            continue
        for item in _items(source):
            state = classify_item(item)
            if state in totals:
                totals[state] += 1
    return totals
