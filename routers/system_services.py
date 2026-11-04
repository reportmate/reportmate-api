"""Read-only fleet service coverage, with independent application inventory."""

from collections import Counter
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from dependencies import get_db_connection, infer_platform, load_sql, logger, verify_authentication

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
    if versions.strip() and not application.strip():
        raise HTTPException(status_code=422, detail="Select an application before filtering its versions")
    normalized_platform = {"win": "windows", "windows": "windows", "mac": "macos", "macos": "macos", "all": "", "": ""}.get(platform.lower())
    if normalized_platform is None:
        raise HTTPException(status_code=422, detail="platform must be Windows or macOS")
    dimensions = {"usages": "usage", "catalogs": "catalog", "areas": "area", "fleets": "fleet", "locations": "location", "rooms": "room"}
    selected = {"usage": _list(usages), "catalog": _list(catalogs), "area": _list(areas), "fleet": _list(fleets), "location": _list(locations), "room": _list(rooms)}
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(load_sql("devices/system_services"), {
            "service": service.strip().lower(), "application": application.strip().lower(),
            "include_archived": include_archived,
            "platform": normalized_platform,
        })
        rows = [row[0] for row in cursor.fetchall()]
        # Query returns only matching service/app entries, never full module documents.
        scoped = [row for row in rows if all(not values or str(row.get(field) or "").lower() in values
                                             for field, values in selected.items())
                  and (not inventory_states or (row.get("inventoryState") or "unknown").lower() in _list(inventory_states))]
        result = shape_services(
            scoped, service=service.strip(), application=application.strip(), version=_list(versions),
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
