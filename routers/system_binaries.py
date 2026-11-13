"""Read-only fleet report of system binaries on macOS and Windows.

Each row is one device and one reported binary: a web server, database, TLS
library, language runtime or command-line tool, with its path, version, the
package or source it came from, and whether it was running when collected.

Rows only describe binaries a device reported. A version is never inferred:
the clients leave it out when they could not read it without running a file a
standard user could have replaced, and the report shows it as not reported.
"""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from dependencies import logger, verify_authentication
from routers.system_item_reports import (
    boolean,
    flatten,
    load_devices,
    load_options,
    now_utc,
    page,
    scope_query,
    selected_items,
)
from routers.system_services import _list

router = APIRouter(tags=["fleet"])

ITEM_KINDS = ["binary"]
CATEGORIES = {"server", "database", "library", "runtime", "tool"}
SOURCES = {
    "os",
    "package",
    "homebrew",
    "macports",
    "developertools",
    "chocolatey",
    "unknown",
}
RUNNING = {"yes", "no", "unknown"}


def running_state(item):
    value = boolean(item.get("running"))
    return "unknown" if value is None else "yes" if value else "no"


def shape_item(item):
    item["running"] = boolean(item.get("running"))
    item["runningState"] = running_state(item)
    count = item.get("processCount")
    item["processCount"] = (
        count
        if isinstance(count, int) and not isinstance(count, bool) and count >= 0
        else None
    )
    item["source"] = (
        item.get("source")
        if isinstance(item.get("source"), str) and item.get("source")
        else "unknown"
    )
    return item


@router.get("/system/binaries/filters", dependencies=[Depends(verify_authentication)])
def get_binary_options(scope: dict = Depends(scope_query)):
    """Collected binary names with the number of devices reporting each."""
    result = load_options(
        "system_binary_options", "system_binaries_options", scope, ITEM_KINDS
    )
    return {"applicable": True, **result}


@router.get("/system/binaries", dependencies=[Depends(verify_authentication)])
def get_system_binaries(
    scope: dict = Depends(scope_query),
    items: str = Query(
        default="",
        max_length=16000,
        description='Selected binaries as a JSON array of "binary:<name>", e.g. ["binary:httpd"]',
    ),
    categories: str = Query(
        default="",
        max_length=80,
        description="server, database, library, runtime, tool; comma separated",
    ),
    sources: str = Query(
        default="",
        max_length=120,
        description="os, package, homebrew, macports, developerTools, chocolatey, unknown; comma separated",
    ),
    running: str = Query(
        default="",
        max_length=30,
        description="Observed running when collected: yes, no, unknown",
    ),
    versions: str = Query(
        default="",
        max_length=2000,
        description="Exact reported versions; comma separated",
    ),
    freshness: Literal["all", "fresh", "stale", "unknown"] = "all",
    max_age_hours: int = Query(default=24, ge=1, le=8760, alias="maxAgeHours"),
    search: str = Query(default="", max_length=200),
    limit: int = Query(default=1000, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
):
    """One row per device and reported binary.

    Runs when binaries are selected, or fleet-wide for chosen categories or for
    binaries observed running.
    """
    category_filter, source_filter, running_filter = (
        _list(categories),
        _list(sources),
        _list(running),
    )
    version_filter = {value.strip() for value in versions.split(",") if value.strip()}
    if category_filter - CATEGORIES:
        raise HTTPException(status_code=422, detail="Invalid category")
    if source_filter - SOURCES:
        raise HTTPException(status_code=422, detail="Invalid source")
    if running_filter - RUNNING:
        raise HTTPException(status_code=422, detail="Invalid running state")
    selected = selected_items(items, ITEM_KINDS)
    running_only = running_filter == {"yes"}
    now = now_utc()
    if not selected["binary"] and not category_filter and not running_only:
        result = page(
            [],
            summary_keys=(),
            devices_in_scope=0,
            devices_without_inventory=0,
            limit=limit,
            offset=offset,
            now=now,
            query_required=True,
        )
        return {**result, "applicable": True}
    try:
        devices = load_devices(
            "system_binaries",
            {
                **scope,
                "binary_keys": sorted(selected["binary"]),
                "categories": sorted(category_filter),
                "running_only": running_only,
            },
        )
    except Exception:
        logger.exception("Fleet binaries report failed")
        raise HTTPException(status_code=500, detail="Binaries report unavailable")

    def keep(row):
        return (
            (
                not selected["binary"]
                or str(row.get("key") or "").lower() in selected["binary"]
            )
            and (
                not category_filter
                or str(row.get("category") or "").lower() in category_filter
            )
            and (
                not source_filter
                or str(row.get("source") or "").lower() in source_filter
            )
            and (not running_filter or row["runningState"] in running_filter)
            and (not version_filter or str(row.get("version") or "") in version_filter)
        )

    rows, without = flatten(
        devices,
        shape_item=shape_item,
        keep_item=keep,
        search=search.strip().lower(),
        freshness=freshness,
        max_age_hours=max_age_hours,
        now=now,
    )
    result = page(
        rows,
        summary_keys=("category", "source", "runningState"),
        devices_in_scope=len(devices),
        devices_without_inventory=without,
        limit=limit,
        offset=offset,
        now=now,
    )
    return {**result, "applicable": True}
