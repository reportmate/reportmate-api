"""Read-only fleet OS update coverage: pending, installed and unreported updates per device."""

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from dependencies import (
    cache_get,
    cache_set,
    get_db_connection,
    infer_platform,
    load_sql,
    logger,
    verify_authentication,
)
from routers.system_services import (
    _list,
    _names,
    _platform,
    _time,
    collection_freshness,
)

router = APIRouter(tags=["fleet"])

STATES = {"pending", "installed", "not_reported", "none", "unknown"}
SCOPES = {
    "usages": "usage",
    "catalogs": "catalog",
    "areas": "area",
    "fleets": "fleet",
    "locations": "location",
    "rooms": "room",
}
_KB = re.compile(r"\bKB\s?(\d{4,8})\b", re.IGNORECASE)
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def flag(value):
    """Collected booleans arrive as true/false, 0/1 or strings; anything else is unknown (None)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value or "").strip().lower()
    return {
        "true": True,
        "1": True,
        "yes": True,
        "false": False,
        "0": False,
        "no": False,
    }.get(text)


def kb_number(*values):
    for value in values:
        match = _KB.search(str(value or ""))
        if match:
            return f"KB{match.group(1)}"
    return None


def update_key(platform, kb=None, title=None):
    """Stable selection key. Windows updates key on KB when one was collected, otherwise on title."""
    if platform == "windows":
        return (
            f"windows:{kb.lower()}"
            if kb
            else f"windows:title:{str(title or '').strip().lower()}"
        )
    return f"macos:{str(title or '').strip().lower()}"


def _platform_key(row):
    name = (infer_platform(row.get("platform")) or "").lower()
    if name in ("windows", "macos"):
        return name
    if isinstance(row.get("pendingWindowsUpdates"), list):
        return "windows"
    if isinstance(row.get("pendingAppleUpdates"), list):
        return "macos"
    return ""


def _age_days(value, now):
    when = _time(value)
    if when is None or when > now:
        return None
    return int((now - when).total_seconds() // 86400)


def windows_pending(entry, now):
    kb = kb_number(entry.get("kbNumber"), entry.get("kb_number"), entry.get("title"))
    title = entry.get("title") or entry.get("description") or kb or ""
    cves = sorted(
        {
            str(c).strip().upper()
            for c in entry.get("cves") or []
            if _CVE.match(str(c).strip())
        }
    )
    category = entry.get("category") or ""
    released = entry.get("releaseDate") or entry.get("release_date") or None
    return {
        "updateKey": update_key("windows", kb, title),
        "title": title,
        "kb": kb,
        "category": category,
        "severity": entry.get("severity") or None,
        "cves": cves,
        # MSRC severity and CVEs are set only on security updates; a title such as
        # "Security Intelligence Update" is a definition update, not a security fix.
        "isSecurity": bool(cves) or bool(entry.get("severity")) or "security" in category.lower(),
        "mandatory": flag(entry.get("isMandatory", entry.get("is_mandatory"))),
        "downloaded": flag(entry.get("isDownloaded", entry.get("is_downloaded"))),
        "rebootRequired": flag(
            entry.get("rebootRequired", entry.get("reboot_required"))
        ),
        "deferred": None,
        "deferredUntil": None,
        "firstOfferedAt": None,
        "releaseDate": released,
        "installDate": None,
        "version": None,
        "buildVersion": None,
        "updateType": None,
        "ageDays": _age_days(released, now),
        "ageSource": "released" if released else None,
    }


def windows_installed(entry):
    kb = kb_number(entry.get("id"), entry.get("updateId"), entry.get("title"))
    title = entry.get("title") or entry.get("name") or kb or ""
    return {
        "updateKey": update_key("windows", kb, title),
        "title": title,
        "kb": kb,
        "category": entry.get("category") or "",
        "severity": None,
        "cves": [],
        "isSecurity": "security" in f"{title} {entry.get('category') or ''}".lower(),
        "mandatory": None,
        "downloaded": None,
        "rebootRequired": flag(
            entry.get("requiresRestart", entry.get("requires_restart"))
        ),
        "deferred": None,
        "deferredUntil": None,
        "firstOfferedAt": None,
        "releaseDate": None,
        "installDate": entry.get("installDate") or entry.get("installed_date") or None,
        "version": None,
        "buildVersion": None,
        "updateType": None,
        "ageDays": None,
        "ageSource": None,
    }


def macos_pending(entry, now):
    label = (
        entry.get("name") or entry.get("display_name") or entry.get("productKey") or ""
    )
    offered = entry.get("firstOfferedAt") or entry.get("first_offered_at") or None
    return {
        "updateKey": update_key("macos", title=label),
        "title": label,
        "kb": None,
        "productKey": entry.get("productKey") or entry.get("product_key") or None,
        "category": entry.get("updateType") or entry.get("update_type") or "",
        "severity": None,
        "cves": [],
        "isSecurity": flag(entry.get("isSecurity", entry.get("is_security"))) is True,
        "mandatory": None,
        "downloaded": None,
        "rebootRequired": flag(
            entry.get(
                "restartRequired",
                entry.get("restart_required", entry.get("reboot_required")),
            )
        ),
        "deferred": flag(entry.get("deferred")),
        "deferredUntil": entry.get("deferredUntil")
        or entry.get("deferred_until")
        or None,
        "firstOfferedAt": offered,
        "releaseDate": None,
        "installDate": None,
        "version": entry.get("version") or None,
        "buildVersion": entry.get("buildVersion") or entry.get("build_version") or None,
        "updateType": entry.get("updateType") or entry.get("update_type") or None,
        "ageDays": _age_days(offered, now),
        "ageSource": "offered" if offered else None,
    }


def device_updates(row, now):
    """Return (platform, pending, installed, valid) for one device's system module.

    Valid means the client sent a pending-update list made only of objects (and, on
    Windows, a count that agrees with it). An empty valid list is what the clients
    send both when nothing is pending and when the update search failed, so a
    device-level "none" row is reported only as "none reported", never as patched.
    """
    platform = _platform_key(row)
    raw = (
        row.get("pendingWindowsUpdates")
        if platform == "windows"
        else row.get("pendingAppleUpdates")
    )
    valid = isinstance(raw, list) and all(isinstance(e, dict) for e in raw)
    if valid and platform == "windows":
        count = row.get("pendingWindowsUpdatesCount")
        if isinstance(count, int) and not isinstance(count, bool) and count != len(raw):
            valid = False
    pending, installed = [], []
    if valid:
        pending = [
            windows_pending(e, now) if platform == "windows" else macos_pending(e, now)
            for e in raw
        ]
    if platform == "windows" and isinstance(row.get("installedUpdates"), list):
        installed = [
            windows_installed(e) for e in row["installedUpdates"] if isinstance(e, dict)
        ]
    return platform, pending, installed, valid


EMPTY_UPDATE = {
    "updateKey": None,
    "title": None,
    "kb": None,
    "category": None,
    "severity": None,
    "cves": [],
    "isSecurity": None,
    "mandatory": None,
    "downloaded": None,
    "rebootRequired": None,
    "deferred": None,
    "deferredUntil": None,
    "firstOfferedAt": None,
    "releaseDate": None,
    "installDate": None,
    "version": None,
    "buildVersion": None,
    "updateType": None,
    "ageDays": None,
    "ageSource": None,
}
DEVICE_FIELDS = (
    "serialNumber",
    "deviceName",
    "hostname",
    "platform",
    "osVersion",
    "assetTag",
    "usage",
    "catalog",
    "area",
    "fleet",
    "location",
    "room",
    "archived",
    "inventoryState",
    "lastSeen",
    "collectedAt",
)


def _matches(update, keys, cves):
    if keys and update["updateKey"] in keys:
        return True
    return bool(cves) and any(c.lower() in cves for c in update["cves"])


def _passes(update, security_only, deferred, reboot_required, min_age_days):
    if security_only and update["isSecurity"] is not True:
        return False
    if deferred != "all" and update["deferred"] is not (deferred == "yes"):
        return False
    if reboot_required and update["rebootRequired"] is not True:
        return False
    if min_age_days and (update["ageDays"] is None or update["ageDays"] < min_age_days):
        return False
    return True


def shape_updates(
    rows,
    *,
    keys,
    cves,
    states,
    freshness,
    max_age_hours,
    platform,
    search,
    security_only,
    deferred,
    reboot_required,
    min_age_days,
    limit,
    offset,
    now,
):
    """One row per device and update, plus device-level rows when nothing matches.

    Pending and absence claims need a fresh, valid collection; otherwise the row is
    "unknown" and the reported state is kept alongside. An installed KB stays
    "installed" whatever its age, because the evidence is of a past install.
    """
    selection_platforms = {key.split(":", 1)[0] for key in keys} | (
        {"windows"} if cves else set()
    )
    attribute_filter = (
        security_only or deferred != "all" or reboot_required or bool(min_age_days)
    )
    results, summary = [], Counter()
    for row in rows:
        row = dict(row)
        row_platform, pending, installed, valid = device_updates(row, now)
        if platform and row_platform != platform:
            continue
        if selection_platforms and row_platform not in selection_platforms:
            continue
        if (
            search
            and search
            not in " ".join(
                str(row.get(k) or "")
                for k in ("deviceName", "hostname", "serialNumber", "assetTag")
            ).lower()
        ):
            continue
        fresh = collection_freshness(row.get("collectedAt"), now, max_age_hours)
        if freshness != "all" and fresh != freshness:
            continue
        base = {field: row.get(field) for field in DEVICE_FIELDS}
        base["platform"] = (
            infer_platform(row.get("platform")) or row.get("platform") or "Unknown"
        )
        base["freshness"] = fresh
        base["collectionValid"] = valid
        base["pendingCount"] = len(pending) if valid else None
        trusted = valid and fresh == "fresh"
        device_rows = []
        if keys or cves:
            pending_hits = [u for u in pending if _matches(u, keys, cves)]
            pending_keys = {u["updateKey"] for u in pending_hits}
            installed_hits = [
                u
                for u in installed
                if _matches(u, keys, cves) and u["updateKey"] not in pending_keys
            ]
            for update in pending_hits:
                device_rows.append(
                    (update, "pending", "pending" if trusted else "unknown")
                )
            for update in installed_hits:
                device_rows.append((update, "installed", "installed"))
            if not device_rows and not attribute_filter:
                device_rows.append(
                    (
                        EMPTY_UPDATE,
                        "not_reported" if valid else "missing",
                        "not_reported" if trusted else "unknown",
                    )
                )
        else:
            for update in pending:
                device_rows.append(
                    (update, "pending", "pending" if trusted else "unknown")
                )
            if not pending and not attribute_filter:
                device_rows.append(
                    (
                        EMPTY_UPDATE,
                        "none" if valid else "missing",
                        "none" if trusted else "unknown",
                    )
                )
        for update, reported, state in device_rows:
            if update is not EMPTY_UPDATE and not _passes(
                update, security_only, deferred, reboot_required, min_age_days
            ):
                continue
            summary[state] += 1
            if states and state not in states:
                continue
            results.append(
                {
                    **base,
                    **EMPTY_UPDATE,
                    **update,
                    "reportedState": reported,
                    "state": state,
                }
            )
    return {
        "generatedAt": now.isoformat(),
        "total": len(results),
        "limit": limit,
        "offset": offset,
        "summary": dict(summary),
        "rows": results[offset : offset + limit],
    }


def _query_rows(platform, include_archived):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            load_sql("devices/system_updates"),
            {"platform": platform, "include_archived": include_archived},
        )
        return [row[0] for row in cursor.fetchall()]
    finally:
        conn.close()


def _scope(rows, selected, inventory_states):
    return [
        row
        for row in rows
        if all(
            not values or str(row.get(field) or "").lower() in values
            for field, values in selected.items()
        )
        and (
            not inventory_states
            or (row.get("inventoryState") or "unknown").lower() in inventory_states
        )
    ]


def _options(rows):
    options = {
        key: sorted({row[field] for row in rows if row.get(field)}, key=str.lower)
        for key, field in SCOPES.items()
    }
    options["inventoryStates"] = sorted(
        {row.get("inventoryState") or "unknown" for row in rows}
    )
    return options


def build_update_options(rows, now):
    updates, cves = {}, {}
    for row in rows:
        platform, pending, installed, _ = device_updates(row, now)
        serial = row.get("serialNumber")
        for kind, entries in (("pending", pending), ("installed", installed)):
            for update in entries:
                if not update["title"] and not update["kb"]:
                    continue
                item = updates.setdefault(
                    update["updateKey"],
                    {
                        "key": update["updateKey"],
                        "platform": platform,
                        "kb": update["kb"],
                        "title": update["title"],
                        "category": update["category"],
                        "isSecurity": bool(update["isSecurity"]),
                        "pendingDevices": set(),
                        "installedDevices": set(),
                        "cves": set(),
                    },
                )
                if kind == "pending" and len(update["title"] or "") > len(
                    item["title"] or ""
                ):
                    item["title"] = update["title"]
                item["isSecurity"] = item["isSecurity"] or bool(update["isSecurity"])
                item[f"{kind}Devices"].add(serial)
                item["cves"].update(update["cves"])
                if kind == "pending":
                    for cve in update["cves"]:
                        cves.setdefault(cve, set()).add(serial)
    result = []
    for item in updates.values():
        result.append(
            {
                **item,
                "pendingDevices": len(item["pendingDevices"]),
                "installedDevices": len(item["installedDevices"]),
                "cves": sorted(item["cves"]),
            }
        )
    result.sort(key=lambda u: (u["platform"], (u["title"] or u["kb"] or "").lower()))
    return result, sorted(
        ({"cve": c, "devices": len(s)} for c, s in cves.items()), key=lambda c: c["cve"]
    )


@router.get("/system/updates/filters", dependencies=[Depends(verify_authentication)])
def get_update_options(
    platform: str = Query(default="", max_length=30),
    include_archived: bool = Query(default=False, alias="includeArchived"),
):
    """Collected update titles, KBs and CVEs (pending or installed) for the report picker."""
    normalized = _platform(platform)
    key = (normalized, include_archived)
    cached = cache_get("system_update_options", key)
    if cached is not None:
        return cached
    try:
        rows = _query_rows(normalized, include_archived)
        updates, cves = build_update_options(rows, datetime.now(timezone.utc))
        result = {"updates": updates, "cves": cves, "options": _options(rows)}
        cache_set("system_update_options", result, key)
        return result
    except Exception:
        logger.exception("Update report options unavailable")
        raise HTTPException(status_code=500, detail="Update report options unavailable")


@router.get("/system/updates", dependencies=[Depends(verify_authentication)])
def get_system_updates(
    updates: str = Query(
        default="",
        max_length=8000,
        description="Selected update keys from /system/updates/filters as a JSON array",
    ),
    cves: str = Query(
        default="",
        max_length=8000,
        description="Selected CVE ids as a JSON array; Windows only",
    ),
    states: str = Query(default="", max_length=100),
    security_only: bool = Query(default=False, alias="securityOnly"),
    deferred: Literal["all", "yes", "no"] = "all",
    reboot_required: bool = Query(default=False, alias="rebootRequired"),
    min_age_days: int = Query(default=0, ge=0, le=3650, alias="minAgeDays"),
    freshness: Literal["all", "fresh", "stale", "unknown"] = "all",
    max_age_hours: int = Query(default=24, ge=1, le=8760, alias="maxAgeHours"),
    platform: str = Query(default="", max_length=30),
    search: str = Query(default="", max_length=200),
    usages: str = Query(default="", max_length=500),
    catalogs: str = Query(default="", max_length=500),
    areas: str = Query(default="", max_length=1000),
    fleets: str = Query(default="", max_length=1000),
    locations: str = Query(default="", max_length=1000),
    rooms: str = Query(default="", max_length=1000),
    inventory_states: str = Query(default="", max_length=100, alias="inventoryStates"),
    include_archived: bool = Query(default=False, alias="includeArchived"),
    limit: int = Query(default=1000, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
):
    """One row per device and pending update, plus device-level rows.

    With a selection (update keys or CVEs), each in-scope device gets the matching
    pending and installed rows, or one "not_reported" row. Installed history is the
    collected recent-update list, so "not_reported" is not proof the update is
    absent. With no selection, every pending update is a row and devices with an
    empty valid list get a "none" row. Stale, missing or malformed collection is
    "unknown". Age is days since macOS first offered the update, or since the
    Windows update was released.
    """
    state = _list(states)
    if state - STATES:
        raise HTTPException(status_code=422, detail="Invalid update state")
    normalized = _platform(platform)
    keys = _names(updates)
    if any(not key.startswith(("windows:", "macos:")) for key in keys):
        raise HTTPException(
            status_code=422, detail="Update keys must come from the update filters"
        )
    selected_cves = _names(cves)
    if any(not _CVE.match(c) for c in selected_cves):
        raise HTTPException(
            status_code=422, detail="CVE ids must look like CVE-YYYY-NNNN"
        )
    selected = {"usage": _list(usages), "catalog": _list(catalogs), "area": _list(areas),
                "fleet": _list(fleets), "location": _list(locations), "room": _list(rooms)}
    try:
        rows = _query_rows(normalized, include_archived)
        now = datetime.now(timezone.utc)
        result = shape_updates(
            _scope(rows, selected, _list(inventory_states)),
            keys=keys,
            cves=selected_cves,
            states=state,
            freshness=freshness,
            max_age_hours=max_age_hours,
            platform=normalized,
            search=search.strip().lower(),
            security_only=security_only,
            deferred=deferred,
            reboot_required=reboot_required,
            min_age_days=min_age_days,
            limit=limit,
            offset=offset,
            now=now,
        )
        result["options"] = _options(rows)
        return result
    except HTTPException:
        raise
    except Exception:
        logger.exception("Fleet updates report failed")
        raise HTTPException(status_code=500, detail="Fleet updates report unavailable")
