"""Read-only fleet coverage for configuration profiles and managed preferences.

macOS reports ``installed_profiles`` (mobileconfig profiles) and
``managed_policies`` (managed preference domains); Windows reports
``configurationProfiles`` (one entry per policy branch). Rows are one per
device and selected profile: installed, missing, or unknown when the device's
management inventory is absent, empty or stale.
"""

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
from routers.system_services import _list, _names, _platform, collection_freshness

router = APIRouter(tags=["fleet"])

MAX_SELECTIONS = 50
SCOPES = {
    "usages": "usage",
    "catalogs": "catalog",
    "areas": "area",
    "fleets": "fleet",
    "locations": "location",
    "rooms": "room",
}
STATES = {"installed", "missing", "unknown"}


def profile_state(matched, freshness, inventory_available):
    """A profile is missing only against a fresh, nonempty inventory."""
    if matched:
        return "installed"
    return (
        "missing" if freshness == "fresh" and inventory_available is True else "unknown"
    )


def profile_scope(entry):
    """System or user scope as recorded; unknown when the client did not say."""
    if not isinstance(entry, dict):
        return "unknown"
    user = _text(entry.get("user")) or ""
    user = user.strip()
    kind = (_text(entry.get("type")) or "").strip().lower()
    if user:
        return "system" if user.lower() == "system level" else "user"
    if kind in ("device", "system"):
        return "system"
    if kind == "user":
        return "user"
    return "unknown"


TEXT_FIELDS = ("serialNumber", "deviceName", "platform", "osName", "assetTag", "usage", "catalog",
               "area", "fleet", "location", "room", "inventoryState", "lastSeen", "collectedAt")


def _text(value):
    if value is None or isinstance(value, (dict, list)):
        return None
    return str(value)


def _count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def clean_row(row):
    """Coerce untrusted device JSON; a malformed payload degrades to unknown, never a 500."""
    if not isinstance(row, dict):
        row = {}
    clean = {field: _text(row.get(field)) for field in TEXT_FIELDS}
    clean["archived"] = row.get("archived") is True
    try:
        clean["platform"] = (infer_platform(clean["platform"]) or infer_platform(clean["osName"])
                             or clean["platform"] or "Unknown")
        count = row.get("inventoryCount")
        clean["inventoryCount"] = count if isinstance(count, int) and not isinstance(count, bool) else 0
        clean["inventoryAvailable"] = row.get("inventoryAvailable") is True
        matches = row.get("matches")
        clean["matches"] = [
            {**match, "key": str(match["key"])}
            for match in (matches if isinstance(matches, list) else [])
            if isinstance(match, dict) and match.get("key") is not None
        ]
    except Exception:
        logger.warning("Malformed management profile payload for one device; reporting it as unknown")
        clean.update(platform=clean.get("platform") if isinstance(clean.get("platform"), str) else "Unknown",
                     inventoryCount=0, inventoryAvailable=False, matches=[])
    return clean


def preference_scope(scopes):
    if not isinstance(scopes, list):
        return "unknown"
    names = {str(s).strip().lower() for s in scopes or [] if str(s).strip()}
    if not names:
        return "unknown"
    has_system = "system level" in names
    has_user = bool(names - {"system level"})
    return (
        "system+user" if has_system and has_user else "system" if has_system else "user"
    )


@router.get(
    "/management/profiles/filters", dependencies=[Depends(verify_authentication)]
)
def get_profile_options(
    include_archived: bool = Query(default=False, alias="includeArchived")
):
    """Collected profile identifiers, managed preference domains and inventory scope values."""
    key = (include_archived,)
    cached = cache_get("management_profile_options", key)
    if cached is not None:
        return cached
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            load_sql("devices/management_profile_options"),
            {"include_archived": include_archived},
        )
        result = {
            "profiles": [],
            "preferences": [],
            "options": {k: [] for k in (*SCOPES, "inventoryStates")},
        }
        for kind, value, label, devices, platforms, keys in cursor.fetchall():
            names = sorted({infer_platform(str(p)) or str(p) for p in (platforms if isinstance(platforms, list) else []) if p is not None})
            value, label = _text(value) or "", _text(label)
            if not value:
                continue
            if kind == "profile":
                result["profiles"].append(
                    {
                        "identifier": value,
                        "name": label or value,
                        "devices": devices,
                        "platforms": names,
                    }
                )
            elif kind == "preference":
                result["preferences"].append(
                    {
                        "identifier": value,
                        "name": value,
                        "devices": devices,
                        "platforms": names,
                        "keys": sorted({str(k) for k in keys if k is not None}, key=str.lower) if isinstance(keys, list) else [],
                    }
                )
            elif kind == "scope" and value in result["options"] and label:
                result["options"][value].append(label)
        result["profiles"].sort(
            key=lambda p: (p["name"].lower(), p["identifier"].lower())
        )
        result["preferences"].sort(key=lambda p: p["identifier"].lower())
        for values in result["options"].values():
            values.sort(key=str.lower)
        cache_set("management_profile_options", result, key)
        return result
    except Exception:
        logger.exception("Profile report options unavailable")
        raise HTTPException(
            status_code=500, detail="Profile report options unavailable"
        )
    finally:
        conn.close()


def shape_profiles(
    rows,
    *,
    kind,
    selected,
    labels,
    state,
    freshness,
    max_age_hours,
    platform,
    search,
    scopes,
    inventory_states,
    limit,
    offset,
    now,
):
    """Expand device rows into one row per (device, selected identifier)."""
    rows = [clean_row(row) for row in rows]
    # A Windows device cannot lack a macOS-only profile: each selected identifier
    # is evaluated for absence only on platforms where it was observed.
    applicable = {}
    for row in rows:
        for match in row["matches"]:
            if match["key"] in selected:
                applicable.setdefault(match["key"], set()).add(row["platform"])
    results, summary = [], Counter()
    for row in rows:
        if platform and row["platform"].lower() != platform:
            continue
        keys = sorted(key for key in selected if row["platform"] in applicable.get(key, ()))
        if not keys:
            continue
        if any(
            values and str(row.get(field) or "").lower() not in values
            for field, values in scopes.items()
        ):
            continue
        if (
            inventory_states
            and (row.get("inventoryState") or "unknown").lower() not in inventory_states
        ):
            continue
        if (
            search
            and search
            not in " ".join(
                str(row.get(k) or "")
                for k in ("deviceName", "serialNumber", "assetTag")
            ).lower()
        ):
            continue
        row_freshness = collection_freshness(row.get("collectedAt"), now, max_age_hours)
        if freshness != "all" and row_freshness != freshness:
            continue
        by_key = {}
        for match in row["matches"]:
            by_key.setdefault(match["key"], []).append(match)
        base = {
            k: row.get(k)
            for k in (
                "serialNumber",
                "deviceName",
                "platform",
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
        }
        base["freshness"] = row_freshness
        base["inventoryCount"] = row.get("inventoryCount") or 0
        for key in keys:
            matches = by_key.get(key) or [None]
            for match in matches:
                item_state = profile_state(
                    match is not None, row_freshness, row.get("inventoryAvailable")
                )
                summary[item_state] += 1
                if state and item_state not in state:
                    continue
                entry = dict(base)
                entry["state"] = item_state
                label = labels.get(key) or {}
                entry["identifier"] = _text((match or {}).get("identifier")) or label.get("identifier") or key
                entry["name"] = _text((match or {}).get("name")) or label.get("name") or entry["identifier"]
                if match is None:
                    entry["scope"] = None
                elif kind == "profile":
                    entry["scope"] = profile_scope(match)
                    entry["user"] = _text(match.get("user")) if entry["scope"] == "user" else None
                    for field in ("uuid", "version", "organization", "installDate", "source", "status", "verificationState"):
                        entry[field] = _text(match.get(field))
                    removal = match.get("removalDisallowed")
                    entry["removalDisallowed"] = removal in (True, 1, "1", "true") if removal is not None else None
                    entry["payloadCount"] = _count(match.get("payloadCount"))
                else:
                    entry["scope"] = preference_scope(match.get("scopes"))
                    entry["settingCount"] = _count(match.get("settingCount"))
                    values = match.get("values")
                    entry["values"] = None if not isinstance(values, list) else [
                        {"scope": _text(v.get("scope")), "value": _text(v.get("value"))}
                        for v in values if isinstance(v, dict)
                    ]
                results.append(entry)
    return {
        "generatedAt": now.isoformat(),
        "kind": kind,
        "queryRequired": not selected,
        "total": len(results),
        "limit": limit,
        "offset": offset,
        "summary": dict(summary),
        "devices": results[offset : offset + limit],
    }


@router.get("/management/profiles", dependencies=[Depends(verify_authentication)])
def get_management_profiles(
    kind: Literal["profile", "preference"] = "profile",
    identifiers: str = Query(
        default="",
        max_length=20000,
        description="Exact profile identifiers or preference domains as a JSON array",
    ),
    preference_key: str = Query(
        default="",
        max_length=300,
        alias="preferenceKey",
        description="Managed preference key whose values to report",
    ),
    states: str = Query(default="", max_length=100),
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
    limit: int = Query(default=500, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
):
    """One row per device and selected profile or preference domain.

    No per-device cap: every matching entry is returned, paged by limit/offset.
    A profile is reported missing only when the device's management inventory is
    fresh and nonempty; otherwise the row is unknown.
    """
    state = _list(states)
    if state - STATES:
        raise HTTPException(status_code=422, detail="Invalid profile state")
    if preference_key.strip() and kind != "preference":
        raise HTTPException(
            status_code=422, detail="preferenceKey applies to managed preferences only"
        )
    normalized_platform = _platform(platform)
    selected = _names(identifiers)
    if len(selected) > MAX_SELECTIONS:
        raise HTTPException(
            status_code=422, detail=f"Select at most {MAX_SELECTIONS} profiles"
        )
    if not selected:
        return {
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            "queryRequired": True,
            "total": 0,
            "limit": limit,
            "offset": offset,
            "summary": {},
            "devices": [],
        }
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            load_sql("devices/management_profiles"),
            {
                "kind": kind,
                "identifiers": sorted(selected),
                "preference_key": preference_key.strip().lower(),
                "include_archived": include_archived,
            },
        )
        rows = [clean_row(row[0]) for row in cursor.fetchall()]
        labels = {}
        for row in rows:
            for match in row["matches"]:
                labels.setdefault(
                    match["key"],
                    {"identifier": _text(match.get("identifier")), "name": _text(match.get("name"))},
                )
        return shape_profiles(
            rows,
            kind=kind,
            selected=selected,
            labels=labels,
            state=state,
            freshness=freshness,
            max_age_hours=max_age_hours,
            platform=normalized_platform,
            search=search.strip().lower(),
            scopes={
                field: _list(locals_value)
                for field, locals_value in (
                    ("usage", usages),
                    ("catalog", catalogs),
                    ("area", areas),
                    ("fleet", fleets),
                    ("location", locations),
                    ("room", rooms),
                )
            },
            inventory_states=_list(inventory_states),
            limit=limit,
            offset=offset,
            now=datetime.now(timezone.utc),
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("Fleet profile report failed")
        raise HTTPException(status_code=500, detail="Fleet profile report unavailable")
    finally:
        conn.close()
