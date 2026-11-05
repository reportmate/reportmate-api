"""Shared plumbing for the per-item System fleet reports (background items, extensions).

Each report returns one row per device and collected item. Rows only describe
items a device actually reported; a device that does not list an item is never
claimed to lack it, because its inventory may be stale or missing.
"""

import json
from collections import Counter
from datetime import datetime, timezone

from fastapi import HTTPException, Query

from dependencies import (
    cache_get,
    cache_set,
    get_db_connection,
    infer_platform,
    load_sql,
    logger,
)
from routers.system_services import _list, _platform, collection_freshness

SCOPE_FIELDS = {
    "usages": "usage",
    "catalogs": "catalog",
    "areas": "area",
    "fleets": "fleet",
    "locations": "location",
    "rooms": "room",
    "inventoryStates": "inventoryState",
}
DEVICE_SEARCH_FIELDS = ("deviceName", "hostname", "serialNumber", "assetTag")


def _text(value):
    return "" if value is None else str(value)


def scope_query(
    platform: str = Query(default="", max_length=30),
    include_archived: bool = Query(default=False, alias="includeArchived"),
    usages: str = Query(default="", max_length=500),
    catalogs: str = Query(default="", max_length=500),
    areas: str = Query(default="", max_length=1000),
    fleets: str = Query(default="", max_length=1000),
    locations: str = Query(default="", max_length=1000),
    rooms: str = Query(default="", max_length=1000),
    inventory_states: str = Query(default="", max_length=100, alias="inventoryStates"),
):
    """Device scope shared by both reports and their option pickers."""
    return {
        "platform": _platform(platform),
        "include_archived": include_archived,
        "usages": sorted(_list(usages)),
        "catalogs": sorted(_list(catalogs)),
        "areas": sorted(_list(areas)),
        "fleets": sorted(_list(fleets)),
        "locations": sorted(_list(locations)),
        "rooms": sorted(_list(rooms)),
        "inventory_states": sorted(_list(inventory_states)),
    }


def selected_items(value, kinds):
    """Parse a JSON array of "<kind>:<collected key>" strings into lowercase keys per kind."""
    result = {kind: set() for kind in kinds}
    if not value.strip():
        return result
    try:
        entries = json.loads(value)
        if not isinstance(entries, list) or any(
            not isinstance(entry, str) for entry in entries
        ):
            raise ValueError()
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=422, detail="items must be a JSON array of strings"
        )
    for entry in entries:
        kind, separator, key = entry.partition(":")
        if not separator or kind not in result or not key.strip():
            raise HTTPException(
                status_code=422, detail=f"Unknown item selection: {entry[:80]}"
            )
        result[kind].add(key.strip().lower())
    return result


def boolean(value):
    """Collected booleans arrive as true/false, 1/0 or strings; anything else is unknown."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    text = str(value or "").strip().lower()
    return {
        "true": True,
        "1": True,
        "yes": True,
        "false": False,
        "0": False,
        "no": False,
    }.get(text)


def load_options(namespace, sql_name, scope, item_kinds, extra_kinds=()):
    key = tuple(
        (name, tuple(value) if isinstance(value, list) else value)
        for name, value in scope.items()
    )
    cached = cache_get(namespace, key)
    if cached is not None:
        return cached
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            load_sql("devices/system_report_scope") + load_sql(f"devices/{sql_name}"),
            scope,
        )
        result = {"items": [], "options": {name: [] for name in SCOPE_FIELDS}}
        for kind in extra_kinds:
            result[kind] = []
        for kind, value, label, devices in cursor.fetchall():
            value = _text(value)
            label = None if label is None else _text(label)
            if kind in item_kinds:
                result["items"].append(
                    {"kind": kind, "key": value, "label": label, "devices": devices}
                )
            elif kind in extra_kinds:
                result[kind].append({"value": value, "devices": devices})
            elif kind == "scope":
                result["options"][value].append(label)
        result["items"].sort(
            key=lambda item: (item_kinds.index(item["kind"]), str(item["key"]).lower())
        )
        for kind in extra_kinds:
            result[kind].sort(key=lambda entry: entry["value"].lower())
        for values in result["options"].values():
            values.sort(key=str.lower)
        cache_set(namespace, result, key)
        return result
    except Exception:
        logger.exception("System report options unavailable: %s", sql_name)
        raise HTTPException(status_code=500, detail="Report selections unavailable")
    finally:
        conn.close()


def load_devices(sql_name, params):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            load_sql("devices/system_report_scope") + load_sql(f"devices/{sql_name}"),
            params,
        )
        return [row[0] for row in cursor.fetchall()]
    finally:
        conn.close()


DEVICE_FIELDS = (
    "serialNumber",
    "deviceName",
    "hostname",
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


def flatten(devices, *, shape_item, keep_item, search, freshness, max_age_hours, now):
    """One row per device and matching item, plus device-level coverage counts.

    Device JSON is untrusted: a malformed device or item is skipped and counted
    as a device without usable inventory rather than failing the whole report.
    """
    rows, devices_without_inventory = [], 0
    for device in devices:
        if not isinstance(device, dict):
            devices_without_inventory += 1
            continue
        try:
            items = device.get("items")
            if not device.get("inventoryAvailable") or not isinstance(items, list):
                devices_without_inventory += 1
                items = items if isinstance(items, list) else []
            if search and search not in " ".join(_text(device.get(k)) for k in DEVICE_SEARCH_FIELDS).lower():
                continue
            device_freshness = collection_freshness(device.get("collectedAt"), now, max_age_hours)
            if freshness != "all" and device_freshness != freshness:
                continue
            base = {field: device.get(field) for field in DEVICE_FIELDS}
            base["platform"] = infer_platform(_text(device.get("platform"))) or _text(device.get("platform")) or "Unknown"
            base["freshness"] = device_freshness
            for item in items:
                if not isinstance(item, dict):
                    continue
                try:
                    row = {**base, **shape_item(dict(item))}
                    if keep_item(row):
                        rows.append(row)
                except Exception:
                    logger.warning("Skipped a malformed item for one device in a system report")
        except Exception:
            devices_without_inventory += 1
            logger.warning("Skipped a malformed device in a system report")
    rows.sort(key=lambda r: (_text(r.get("deviceName")).lower(), _text(r.get("serialNumber")),
                             _text(r.get("kind")), _text(r.get("name")).lower()))
    return rows, devices_without_inventory


def page(
    rows,
    *,
    summary_keys,
    devices_in_scope,
    devices_without_inventory,
    limit,
    offset,
    now,
    query_required=False,
):
    summary = Counter()
    for row in rows:
        for key in summary_keys:
            if row.get(key) is not None:
                summary[f"{key}:{row[key]}"] += 1
    return {
        "generatedAt": now.isoformat(),
        "queryRequired": query_required,
        "total": len(rows),
        "limit": limit,
        "offset": offset,
        "devicesInScope": devices_in_scope,
        "devicesWithoutInventory": devices_without_inventory,
        "devicesReporting": len({_text(row.get("serialNumber")) for row in rows}),
        "summary": dict(summary),
        "rows": rows[offset : offset + limit],
    }


def now_utc():
    return datetime.now(timezone.utc)
