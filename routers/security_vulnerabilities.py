"""Read-only fleet vulnerability (CVE) and threat detection reports.

Rows are the entries clients collected, normalized across platforms without
filling gaps: Windows clients report MSRC entries with a status and severity,
macOS clients report SOFA unpatched CVEs with no severity, and only Windows
clients report individual threat detections. A field that was not collected
stays null; a device that did not report the list counts as not reporting,
never as clean.
"""

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Literal
from urllib.parse import urlparse

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
from routers.system_services import _list, _platform, _time, collection_freshness

router = APIRouter(tags=["fleet"])

# The macOS client keeps at most this many SOFA entries per device, actively
# exploited first, so a list of this length may be incomplete.
MAC_CVE_LIST_LIMIT = 50

SCOPES = {
    "usages": "usage",
    "catalogs": "catalog",
    "areas": "area",
    "fleets": "fleet",
    "locations": "location",
    "rooms": "room",
}
DEVICE_FIELDS = (
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
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
UNREPORTED = {"", "unknown", "none", "n/a", "null"}


def _text(value):
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value).strip()
    return text or None


def _reported(value):
    """A collected label, or None when the client sent a placeholder."""
    text = _text(value)
    return None if text is None or text.lower() in UNREPORTED else text


def safe_url(value):
    """A device-supplied link, kept only when it is an absolute http(s) URL."""
    text = _reported(value)
    if not text:
        return None
    try:
        parsed = urlparse(text)
    except ValueError:
        return None
    return text if parsed.scheme.lower() in ("http", "https") and parsed.netloc else None


def cve_id(value):
    text = _text(value)
    return text.upper() if text and CVE_PATTERN.match(text) else None


def exploited_flag(value):
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower() if value is not None else ""
    return (
        True
        if text in ("true", "1", "yes")
        else False if text in ("false", "0", "no") else None
    )


def cve_status(value):
    text = (_text(value) or "").lower()
    return text if text in ("patched", "unpatched") else "unknown"


def normalize_cve(entry, source_list):
    """One collected CVE entry. source_list is 'windows' (securityCves) or 'mac' (unpatchedCVEs)."""
    if not isinstance(entry, dict):
        return None
    raw = _text(entry.get("cve"))
    cve = cve_id(raw)
    kb = _reported(entry.get("kbArticle") or entry.get("kb_article"))
    if source_list == "mac":
        product = _reported(entry.get("product_name")) or "macOS"
        status = "unpatched"
        severity = _reported(entry.get("severity"))
        source = "SOFA"
    else:
        product = _reported(entry.get("description")) or _reported(entry.get("product"))
        status = cve_status(entry.get("status"))
        severity = _reported(entry.get("severity"))
        source = (_reported(entry.get("source")) or "MSRC").upper()
    identifier = cve or kb or _reported(raw) or _reported(entry.get("product_name"))
    if not identifier:
        return None
    return {
        "identifier": identifier,
        "cve": cve,
        "kbArticle": kb,
        "label": raw,
        "source": source,
        "status": status,
        "severity": severity,
        "product": product,
        "affectedVersion": _reported(entry.get("osVersion") or entry.get("os_version")),
        "fixedIn": _reported(
            entry.get("patchedVersion") or entry.get("patched_version")
        ),
        "activelyExploited": exploited_flag(
            entry.get("activelyExploited", entry.get("actively_exploited"))
        ),
        "installedDate": _reported(entry.get("installedDate")),
        "url": safe_url(entry.get("url")),
    }


def normalize_detection(entry):
    if not isinstance(entry, dict):
        return None
    detected = _text(entry.get("detectedAt"))
    last = _text(entry.get("lastSeenAt")) or detected
    count = entry.get("count")
    return {
        "threatName": _reported(entry.get("threatName")),
        "threatId": _reported(entry.get("threatId")),
        "severity": _reported(entry.get("severity")),
        "vendor": _reported(entry.get("source")),
        "category": _reported(entry.get("category")),
        "status": _reported(entry.get("status")),
        "actionTaken": _reported(entry.get("actionTaken")),
        "detectedAt": detected,
        "firstSeenAt": _text(entry.get("firstSeenAt")) or detected,
        "lastSeenAt": last,
        "count": (
            count
            if isinstance(count, int) and not isinstance(count, bool) and count >= 0
            else None
        ),
        "path": _reported(entry.get("filePath") or entry.get("path")),
        "processName": _reported(entry.get("processName")),
        "user": _reported(entry.get("user")),
        "eventId": (
            entry.get("eventId") if isinstance(entry.get("eventId"), int) else None
        ),
    }


def _device(row):
    """Device fields as text; device JSON is untrusted, so nothing is assumed to be a string."""
    row = row if isinstance(row, dict) else {}
    device = {key: _text(row.get(key)) for key in DEVICE_FIELDS}
    device["serialNumber"] = device["serialNumber"] or "Unknown"
    device["archived"] = row.get("archived") is True
    device["platform"] = infer_platform(device["platform"]) or device["platform"] or "Unknown"
    device["inventoryState"] = device["inventoryState"] or "unknown"
    return device


def _names(value):
    if not value.strip():
        return set()
    if not value.lstrip().startswith("["):
        return {part.strip().lower() for part in value.split(",") if part.strip()}
    try:
        names = json.loads(value)
        if not isinstance(names, list) or any(
            not isinstance(name, str) for name in names
        ):
            raise ValueError()
        return {name.strip().lower() for name in names if name.strip()}
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=422, detail="Names must be a JSON array of strings"
        )


def _load(kind, platform, include_archived):
    key = (platform, include_archived)
    cached = cache_get(f"security_{kind}_rows", key)
    if cached is not None:
        return cached
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            load_sql(f"devices/security_{kind}"),
            {"platform": platform, "include_archived": include_archived},
        )
        rows = [row[0] for row in cursor.fetchall()]
    finally:
        conn.close()
    cache_set(f"security_{kind}_rows", rows, key)
    return rows


def _scope_options(devices):
    options = {
        key: sorted({d[field] for d in devices if d.get(field)}, key=str.lower)
        for key, field in SCOPES.items()
    }
    options["inventoryStates"] = sorted(
        {d.get("inventoryState") or "unknown" for d in devices}
    )
    return options


def _scope_selection(usages, catalogs, areas, fleets, locations, rooms):
    values = (usages, catalogs, areas, fleets, locations, rooms)
    return {field: _list(value) for field, value in zip(SCOPES.values(), values)}


def _in_scope(device, selected, inventory_states, search):
    if any(
        values and str(device.get(field) or "").lower() not in values
        for field, values in selected.items()
    ):
        return False
    if (
        inventory_states
        and (device.get("inventoryState") or "unknown").lower() not in inventory_states
    ):
        return False
    if (
        search
        and search
        not in " ".join(
            str(device.get(k) or "") for k in ("deviceName", "serialNumber", "assetTag")
        ).lower()
    ):
        return False
    return True


def vulnerability_devices(rows, now, max_age_hours):
    """Devices with their normalized CVE entries and collection coverage.

    A device whose payload cannot be read reports "unknown" coverage instead
    of failing the whole report.
    """
    devices = []
    for row in rows:
        device = _device(row)
        device.update(cveReporting="unknown", listMayBeIncomplete=False, entries=[])
        device["freshness"] = collection_freshness(device.get("collectedAt"), now, max_age_hours)
        try:
            windows, mac = row.get("windowsCves"), row.get("macCves")
            entries = []
            if isinstance(windows, list):
                entries += [e for e in (normalize_cve(x, "windows") for x in windows) if e]
            if isinstance(mac, list):
                entries += [e for e in (normalize_cve(x, "mac") for x in mac) if e]
            device["cveReporting"] = "reported" if isinstance(windows, list) or isinstance(mac, list) else "not_reported"
            device["listMayBeIncomplete"] = isinstance(mac, list) and len(mac) >= MAC_CVE_LIST_LIMIT
            device["entries"] = entries
        except Exception:
            logger.warning("Unreadable CVE list for one device; reporting it as unknown")
        devices.append(device)
    return devices


def _matches_cve(entry, identifiers, statuses, severities, exploited):
    if identifiers and entry["identifier"].lower() not in identifiers:
        return False
    if statuses and entry["status"] not in statuses:
        return False
    if severities and (entry["severity"] or "not_reported").lower() not in severities:
        return False
    flag = entry["activelyExploited"]
    if exploited == "yes" and flag is not True:
        return False
    if exploited == "no" and flag is not False:
        return False
    if exploited == "unknown" and flag is not None:
        return False
    return True


def summarize_cves(pairs):
    """Group (device, entry) pairs by identifier; counts are distinct devices."""
    groups = {}
    for device, entry in pairs:
        group = groups.setdefault(
            entry["identifier"],
            {
                "identifier": entry["identifier"],
                "cve": entry["cve"],
                "kbArticle": entry["kbArticle"],
                "serials": set(),
                "unpatched": set(),
                "patched": set(),
                "severities": set(),
                "exploited": set(),
                "fixedIn": set(),
                "products": set(),
                "platforms": set(),
                "sources": set(),
            },
        )
        serial = device["serialNumber"]
        group["serials"].add(serial)
        if entry["status"] == "unpatched":
            group["unpatched"].add(serial)
        elif entry["status"] == "patched":
            group["patched"].add(serial)
        for key, value in (
            ("severities", entry["severity"]),
            ("fixedIn", entry["fixedIn"]),
            ("products", entry["product"]),
            ("platforms", device["platform"]),
            ("sources", entry["source"]),
        ):
            if value:
                group[key].add(value)
        group["exploited"].add(entry["activelyExploited"])
    result = []
    for group in groups.values():
        flags = group.pop("exploited")
        result.append(
            {
                "identifier": group["identifier"],
                "cve": group["cve"],
                "kbArticle": group["kbArticle"],
                "devices": len(group.pop("serials")),
                "unpatchedDevices": len(group.pop("unpatched")),
                "patchedDevices": len(group.pop("patched")),
                # Any device reporting it exploited marks the CVE exploited; otherwise unknown wins over false.
                "activelyExploited": (
                    True if True in flags else None if None in flags else False
                ),
                **{
                    key: sorted(group[key], key=str.lower)
                    for key in (
                        "severities",
                        "fixedIn",
                        "products",
                        "platforms",
                        "sources",
                    )
                },
            }
        )
    result.sort(key=lambda g: (g["activelyExploited"] is not True, -g["unpatchedDevices"], -g["devices"], g["identifier"].lower()))
    return result


@router.get("/security/vulnerabilities", dependencies=[Depends(verify_authentication)])
def get_security_vulnerabilities(
    view: Literal["devices", "summary"] = "devices",
    cves: str = Query(
        default="",
        max_length=8000,
        description="Exact CVE ids or update identifiers as a JSON array",
    ),
    statuses: str = Query(default="", max_length=100),
    severities: str = Query(default="", max_length=300),
    exploited: Literal["all", "yes", "no", "unknown"] = "all",
    freshness: Literal["all", "fresh", "stale", "unknown"] = "all",
    max_age_hours: int = Query(default=168, ge=1, le=8760, alias="maxAgeHours"),
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
    limit: int = Query(default=1000, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
):
    """Collected CVE entries across the fleet.

    view=devices returns one row per device and entry, paged; view=summary groups
    the same filtered entries by CVE with distinct device counts. Severity is
    only what the client collected (macOS SOFA entries carry none). Coverage
    counts devices that did not report a CVE list; they are not treated as clean.
    """
    status = _list(statuses)
    if status - {"patched", "unpatched", "unknown"}:
        raise HTTPException(status_code=422, detail="Invalid CVE status")
    identifiers = _names(cves)
    normalized_platform = _platform(platform)
    selected = _scope_selection(usages, catalogs, areas, fleets, locations, rooms)
    try:
        rows = _load("vulnerabilities", normalized_platform, include_archived)
    except Exception:
        logger.exception("Fleet vulnerability report failed")
        raise HTTPException(
            status_code=500, detail="Fleet vulnerability report unavailable"
        )
    now = datetime.now(timezone.utc)
    devices = vulnerability_devices(rows, now, max_age_hours)
    scoped = [
        d
        for d in devices
        if _in_scope(d, selected, _list(inventory_states), search.strip().lower())
        and (freshness == "all" or d["freshness"] == freshness)
    ]
    coverage = {
        "devices": len(scoped),
        "reporting": sum(d["cveReporting"] == "reported" for d in scoped),
        "notReporting": sum(d["cveReporting"] == "not_reported" for d in scoped),
        "unknown": sum(d["cveReporting"] == "unknown" for d in scoped),
        "listMayBeIncomplete": sum(d["listMayBeIncomplete"] for d in scoped),
    }
    pairs = [
        (d, e)
        for d in scoped
        for e in d["entries"]
        if _matches_cve(e, identifiers, status, _list(severities), exploited)
    ]
    result = {
        "generatedAt": now.isoformat(),
        "view": view,
        "coverage": coverage,
        "options": _scope_options(devices),
    }
    if view == "summary":
        summary = summarize_cves(pairs)
        return {
            **result,
            "total": len(summary),
            "limit": len(summary),
            "offset": 0,
            "cves": summary,
        }
    out = []
    for device, entry in pairs[offset : offset + limit]:
        base = {key: device[key] for key in DEVICE_FIELDS}
        base.update(
            freshness=device["freshness"],
            listMayBeIncomplete=device["listMayBeIncomplete"],
            **entry,
        )
        out.append(base)
    return {
        **result,
        "total": len(pairs),
        "limit": limit,
        "offset": offset,
        "rows": out,
    }


@router.get(
    "/security/vulnerabilities/filters", dependencies=[Depends(verify_authentication)]
)
def get_security_vulnerability_options(
    platform: str = Query(default="", max_length=30),
    include_archived: bool = Query(default=False, alias="includeArchived"),
):
    """Collected CVE identifiers, severities and scope values for the report pickers."""
    normalized_platform = _platform(platform)
    try:
        rows = _load("vulnerabilities", normalized_platform, include_archived)
    except Exception:
        logger.exception("Fleet vulnerability options failed")
        raise HTTPException(
            status_code=500, detail="Fleet vulnerability selections unavailable"
        )
    devices = vulnerability_devices(rows, datetime.now(timezone.utc), 168)
    pairs = [(d, e) for d in devices for e in d["entries"]]
    severities = Counter((e["severity"] or "not_reported") for _, e in pairs)
    return {
        "cves": [
            {
                key: g[key]
                for key in (
                    "identifier",
                    "cve",
                    "devices",
                    "severities",
                    "activelyExploited",
                )
            }
            for g in summarize_cves(pairs)
        ],
        "severities": [
            {"value": k, "entries": v}
            for k, v in sorted(severities.items(), key=lambda kv: kv[0].lower())
        ],
        "options": _scope_options(devices),
    }


def detection_devices(rows):
    devices = []
    for row in rows:
        device = _device(row)
        device.update(detectionReporting="unknown", entries=[])
        try:
            raw = row.get("detections")
            if isinstance(raw, list):
                device["entries"] = [e for e in (normalize_detection(x) for x in raw) if e]
                device["detectionReporting"] = "reported"
            else:
                device["detectionReporting"] = "not_reported"
        except Exception:
            logger.warning("Unreadable detection list for one device; reporting it as unknown")
        devices.append(device)
    return devices


def within_window(entry, since):
    if since is None:
        return True
    seen = _time(entry.get("lastSeenAt") or entry.get("detectedAt"))
    return seen is not None and seen >= since


@router.get("/security/detections", dependencies=[Depends(verify_authentication)])
def get_security_detections(
    days: int = Query(
        default=0,
        ge=0,
        le=3650,
        description="Only detections last seen within this many days; 0 for all collected",
    ),
    vendors: str = Query(default="", max_length=1000),
    categories: str = Query(default="", max_length=1000),
    severities: str = Query(default="", max_length=300),
    statuses: str = Query(default="", max_length=300),
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
    limit: int = Query(default=1000, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
):
    """One row per collected threat detection and device.

    A detection whose time is missing or malformed is excluded from a time
    window rather than assumed recent. Devices that do not report detections
    are counted in coverage, not listed as clean.
    """
    normalized_platform = _platform(platform)
    selected = _scope_selection(usages, catalogs, areas, fleets, locations, rooms)
    try:
        rows = _load("detections", normalized_platform, include_archived)
    except Exception:
        logger.exception("Fleet detection report failed")
        raise HTTPException(
            status_code=500, detail="Fleet detection report unavailable"
        )
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days) if days else None
    devices = detection_devices(rows)
    scoped = [
        d
        for d in devices
        if _in_scope(d, selected, _list(inventory_states), search.strip().lower())
    ]
    filters = {
        "vendor": _list(vendors),
        "category": _list(categories),
        "severity": _list(severities),
        "status": _list(statuses),
    }
    pairs = [
        (d, e)
        for d in scoped
        for e in d["entries"]
        if within_window(e, since)
        and all(
            not values or (e[field] or "not_reported").lower() in values
            for field, values in filters.items()
        )
    ]
    pairs.sort(
        key=lambda p: (
            _time(p[1]["lastSeenAt"]) or datetime.min.replace(tzinfo=timezone.utc)
        ),
        reverse=True,
    )
    out = []
    for device, entry in pairs[offset : offset + limit]:
        base = {key: device[key] for key in DEVICE_FIELDS}
        base.update(entry)
        out.append(base)
    return {
        "generatedAt": now.isoformat(),
        "days": days,
        "coverage": {
            "devices": len(scoped),
            "reporting": sum(d["detectionReporting"] == "reported" for d in scoped),
            "notReporting": sum(
                d["detectionReporting"] == "not_reported" for d in scoped
            ),
            "unknown": sum(d["detectionReporting"] == "unknown" for d in scoped),
            "devicesWithDetections": len({d["serialNumber"] for d, _ in pairs}),
        },
        "options": _scope_options(devices),
        "total": len(pairs),
        "limit": limit,
        "offset": offset,
        "rows": out,
    }


@router.get(
    "/security/detections/filters", dependencies=[Depends(verify_authentication)]
)
def get_security_detection_options(
    platform: str = Query(default="", max_length=30),
    include_archived: bool = Query(default=False, alias="includeArchived"),
):
    """Collected vendors, categories, severities and statuses for the detection pickers."""
    normalized_platform = _platform(platform)
    try:
        rows = _load("detections", normalized_platform, include_archived)
    except Exception:
        logger.exception("Fleet detection options failed")
        raise HTTPException(
            status_code=500, detail="Fleet detection selections unavailable"
        )
    devices = detection_devices(rows)
    counts = defaultdict(lambda: defaultdict(set))
    for device in devices:
        for entry in device["entries"]:
            for field in ("vendor", "category", "severity", "status"):
                counts[field][entry[field] or "not_reported"].add(
                    device["serialNumber"]
                )
    plural = {"vendor": "vendors", "category": "categories", "severity": "severities", "status": "statuses"}
    return {
        **{
            plural[field]: [{"value": value, "devices": len(counts[field][value])}
                            for value in sorted(counts[field], key=str.lower)]
            for field in plural
        },
        "options": _scope_options(devices),
    }
