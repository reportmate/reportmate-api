"""Read-only fleet service coverage, with independent application inventory."""

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from dependencies import cache_get, cache_set, get_db_connection, infer_platform, load_sql, logger, verify_authentication

router = APIRouter(tags=["fleet"])


def _time(value):
    if not value:
        return None
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result
    except (ValueError, TypeError):
        return None


def service_state(value):
    """Normalize recorded SCM/launchd status; retain the raw value in the result."""
    return {"running": "running", "4": "running", "stopped": "stopped", "1": "stopped"}.get(
        str(value or "").strip().lower(), "unknown"
    )


def startup_type(value):
    return {
        "auto_start": "automatic", "automatic": "automatic", "auto": "automatic",
        "demand_start": "manual", "manual": "manual",
        "disabled": "disabled", "boot_start": "boot", "boot": "boot",
        "system_start": "system", "system": "system",
    }.get(str(value or "").strip().lower(), "unknown")


def collection_freshness(value, now, max_age_hours):
    collected = _time(value)
    if collected is None or collected > now:
        return "unknown"
    return "fresh" if (now - collected).total_seconds() <= max_age_hours * 3600 else "stale"


def coverage_state(reported_state, freshness, inventory_available):
    return reported_state if freshness == "fresh" and inventory_available is True else "unknown"


def _list(value):
    return {part.strip().lower() for part in (value or "").split(",") if part.strip()}


def _names(value):
    if not value.lstrip().startswith("["):
        return _list(value)
    try:
        names = json.loads(value)
        if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
            raise ValueError()
        return {name.strip().lower() for name in names if name.strip()}
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="Names must be a JSON array of strings")


def _platform(value):
    result = {"win": "windows", "windows": "windows", "mac": "macos", "macos": "macos", "all": "", "": ""}.get(value.lower())
    if result is None:
        raise HTTPException(status_code=422, detail="platform must be Windows or macOS")
    return result


@router.get("/system/services/filters", dependencies=[Depends(verify_authentication)])
def get_service_options(
    platform: str = Query(default="", max_length=30),
    include_archived: bool = Query(default=False, alias="includeArchived"),
    usages: str = Query(default="", max_length=500), catalogs: str = Query(default="", max_length=500),
    areas: str = Query(default="", max_length=1000), fleets: str = Query(default="", max_length=1000),
    locations: str = Query(default="", max_length=1000), rooms: str = Query(default="", max_length=1000),
    inventory_states: str = Query(default="", max_length=100, alias="inventoryStates"),
):
    """Collected service names and installed applications/versions for the report picker."""
    params = {"platform": _platform(platform), "include_archived": include_archived,
              "usages": sorted(_list(usages)), "catalogs": sorted(_list(catalogs)),
              "areas": sorted(_list(areas)), "fleets": sorted(_list(fleets)),
              "locations": sorted(_list(locations)), "rooms": sorted(_list(rooms)),
              "inventory_states": sorted(_list(inventory_states))}
    key = tuple((name, tuple(value) if isinstance(value, list) else value) for name, value in params.items())
    cached = cache_get("system_service_options", key)
    if cached is not None:
        return cached
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(load_sql("devices/system_service_options"), params)
        result = {"services": [], "applications": [], "options": {k: [] for k in
                  ("usages", "catalogs", "areas", "fleets", "locations", "rooms", "inventoryStates")}}
        for kind, value, label, devices, versions in cursor.fetchall():
            if kind == "service":
                result["services"].append({"name": value, "displayName": label, "devices": devices,
                                           "startups": sorted({startup_type(v) for v in versions or []})})
            elif kind == "application":
                result["applications"].append({"name": value, "devices": devices, "versions": sorted(versions or [])})
            elif kind == "scope":
                result["options"][value].append(label)
        result["services"].sort(key=lambda s: (s["displayName"] or s["name"]).lower())
        result["applications"].sort(key=lambda a: a["name"].lower())
        for values in result["options"].values():
            values.sort(key=str.lower)
        cache_set("system_service_options", result, key)
        return result
    except Exception:
        logger.exception("Service report options unavailable")
        raise HTTPException(status_code=500, detail="Service report options unavailable")
    finally:
        conn.close()


def shape_services(rows, *, service, application, version, state, startup, freshness,
                   max_age_hours, platform, search, scopes, limit, offset, now):
    options = {key: set() for key in scopes}
    options["inventoryStates"] = set()
    results = []
    summary = Counter()
    for row in rows:
        row = dict(row)
        row["platform"] = infer_platform(row.get("platform")) or row.get("platform") or "Unknown"
        if platform and row["platform"].lower() != platform:
            continue
        inventory = row.get("inventoryState") or "unknown"
        for key, field in scopes.items():
            if row.get(field):
                options[key].add(row[field])
        options["inventoryStates"].add(inventory)
        if not service:
            continue
        # Device dimensions are explicit query filters, not service identity heuristics.
        if search and search not in " ".join(str(row.get(k) or "") for k in
                                              ("deviceName", "hostname", "serialNumber", "assetTag")).lower():
            continue
        services = row.get("services") or []
        for entry in services:
            entry["state"] = service_state(entry.get("status"))
            entry["startup"] = startup_type(entry.get("startType"))
        reported = {entry["state"] for entry in services}
        row["reportedState"] = next(iter(reported)) if len(reported) == 1 else "mixed" if reported else "missing"
        row["freshness"] = collection_freshness(row.get("collectedAt"), now, max_age_hours)
        row["state"] = coverage_state(row["reportedState"], row["freshness"], row.get("serviceInventoryAvailable"))
        row["applicationsFreshness"] = collection_freshness(row.get("applicationsCollectedAt"), now, max_age_hours)
        if application:
            row["applicationState"] = "installed" if row["applications"] else "not_reported"
        else:
            row["applicationState"] = "not_selected"
        if version and not any(str(a.get("version") or "").lower() in version for a in row["applications"]):
            continue
        if startup and not any(s["startup"] in startup for s in services):
            continue
        if freshness != "all" and row["freshness"] != freshness:
            continue
        summary[row["state"]] += 1
        if state and row["state"] not in state:
            continue
        results.append(row)
    return {
        "generatedAt": now.isoformat(),
        "queryRequired": not bool(service),
        "total": len(results), "limit": limit, "offset": offset,
        "summary": dict(summary),
        "options": {key: sorted(values, key=str.lower) for key, values in options.items()},
        "devices": results[offset:offset + limit],
    }


@router.get("/system/services", dependencies=[Depends(verify_authentication)])
def get_system_services(
    service: str = Query(default="", max_length=200, description="Literal substring of service name, display name or executable path"),
    application: str = Query(default="", max_length=200, description="Independent installed-application name substring"),
    service_names: str = Query(default="", max_length=8000, alias="serviceNames", description="Exact collected service names as a JSON array; legacy comma-separated lists accepted"),
    application_names: str = Query(default="", max_length=8000, alias="applicationNames", description="Exact installed application names as a JSON array; legacy comma-separated lists accepted"),
    versions: str = Query(default="", max_length=500, description="Exact versions of the selected application; comma separated"),
    states: str = Query(default="", max_length=100),
    startups: str = Query(default="", max_length=100),
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
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """One row per device, including unknown coverage and last-reported evidence.

    Service search is required to run a report. With no search, returns only
    inventory filter options. Service absence is only reported against a fresh,
    nonempty service inventory. A running service does not prove vendor connectivity.
    Application versions are independent observations, never executable file versions.
    """
    state = _list(states)
    startup = _list(startups)
    if state - {"running", "stopped", "mixed", "missing", "unknown"}:
        raise HTTPException(status_code=422, detail="Invalid service state")
    if startup - {"automatic", "manual", "disabled", "boot", "system", "unknown"}:
        raise HTTPException(status_code=422, detail="Invalid startup type")
    normalized_platform = _platform(platform)
    selected_services, selected_applications = _names(service_names), _names(application_names)
    if versions.strip() and not application.strip() and not selected_applications:
        raise HTTPException(status_code=422, detail="Select an application before filtering its versions")
    dimensions = {"usages": "usage", "catalogs": "catalog", "areas": "area", "fleets": "fleet", "locations": "location", "rooms": "room"}
    selected = {"usage": _list(usages), "catalog": _list(catalogs), "area": _list(areas), "fleet": _list(fleets), "location": _list(locations), "room": _list(rooms)}
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(load_sql("devices/system_services"), {
            "service": service.strip().lower(), "application": application.strip().lower(),
            "include_archived": include_archived,
            "platform": normalized_platform,
            "service_names": sorted(selected_services),
            "application_names": sorted(selected_applications),
        })
        rows = [row[0] for row in cursor.fetchall()]
        # Query returns only matching service/app entries, never full module documents.
        scoped = [row for row in rows if all(not values or str(row.get(field) or "").lower() in values
                                             for field, values in selected.items())
                  and (not inventory_states or (row.get("inventoryState") or "unknown").lower() in _list(inventory_states))]
        result = shape_services(
            scoped, service=bool(selected_services) or service.strip(), application=bool(selected_applications) or application.strip(), version=_list(versions),
            state=state, startup=startup, freshness=freshness, max_age_hours=max_age_hours,
            platform=normalized_platform, search=search.strip().lower(), scopes=dimensions,
            limit=limit, offset=offset, now=datetime.now(timezone.utc),
        )
        # Facets stay available when a scope is narrowed to zero devices.
        for key, field in dimensions.items():
            result["options"][key] = sorted({row[field] for row in rows if row.get(field)}, key=str.lower)
        result["options"]["inventoryStates"] = sorted({row.get("inventoryState") or "unknown" for row in rows})
        return result
    except HTTPException:
        raise
    except Exception:
        logger.exception("Fleet services report failed")
        raise HTTPException(status_code=500, detail="Fleet services report unavailable")
    finally:
        conn.close()
