"""Read-only fleet report of background items: Windows scheduled tasks, macOS launchd jobs and Open at Login items.

The Services report already covers Windows services and the launchd jobs macOS
reports as loaded, with their running state. This report covers what Services
does not: the launchd property lists configured on disk (whether loaded or
not), Open at Login items, and Windows scheduled tasks with their last result.
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

ITEM_KINDS = ["task", "launchd", "loginItem"]
LAST_RUN_STATES = {
    "succeeded",
    "failed",
    "running",
    "notRun",
    "informational",
    "unknown",
    "notApplicable",
}
ORIGINS = {"builtIn", "thirdParty", "unknown"}
ENABLED_STATES = {"enabled", "disabled", "unknown"}

# Task Scheduler SCHED_S_* informational results: the task has not run, is
# running, or has no further runs. They are not failures.
SCHEDULER_INFORMATIONAL = {
    0x41300: "informational",  # ready
    0x41301: "running",
    0x41302: "informational",  # disabled
    0x41303: "notRun",
    0x41304: "notRun",  # no more runs
    0x41305: "notRun",  # not scheduled
    0x41307: "notRun",  # no valid triggers
    0x41308: "informational",  # event trigger
}
OK_CODES = sorted(
    {"0", "0x0"}
    | {str(code) for code in SCHEDULER_INFORMATIONAL}
    | {hex(code) for code in SCHEDULER_INFORMATIONAL}
)


def last_run_state(code):
    """Classify a recorded Task Scheduler last result; unparseable or missing results are unknown."""
    text = str(code if code is not None else "").strip()
    if not text:
        return "unknown"
    try:
        value = int(text, 0)
    except ValueError:
        return "unknown"
    if value == 0:
        return "succeeded"
    return SCHEDULER_INFORMATIONAL.get(value, "failed")


def origin(item):
    """Built in (Microsoft or Apple) versus third party, from collected path, source and bundle id only."""
    kind = item.get("kind")
    if kind == "task":
        path = str(item.get("path") or "")
        if not path:
            return "unknown"
        return "builtIn" if path.lower().startswith("\\microsoft\\") else "thirdParty"
    if kind == "launchd":
        source = str(item.get("source") or "").lower()
        if source == "apple" or str(item.get("name") or "").startswith("com.apple."):
            return "builtIn"
        return "thirdParty" if source in ("system", "user") else "unknown"
    bundle = str(item.get("bundleId") or "")
    if not bundle:
        return "unknown"
    return "builtIn" if bundle.startswith("com.apple.") else "thirdParty"


def enabled_state(item):
    if item.get("kind") == "launchd":
        status = str(item.get("state") or "").lower()
        value = (
            False
            if status == "disabled"
            else True if status in ("enabled", "loaded") else None
        )
    else:
        value = boolean(item.get("enabled"))
    return "unknown" if value is None else "enabled" if value else "disabled"


def shape_item(item):
    item["enabledState"] = enabled_state(item)
    item["origin"] = origin(item)
    item["lastRun"] = (
        last_run_state(item.get("lastRunCode"))
        if item["kind"] == "task"
        else "notApplicable"
    )
    for field in ("runAtLoad", "keepAlive", "hidden"):
        if field in item:
            item[field] = boolean(item[field])
    if "enabled" in item:
        item["enabled"] = boolean(item["enabled"])
    return item


@router.get("/system/background/filters", dependencies=[Depends(verify_authentication)])
def get_background_options(scope: dict = Depends(scope_query)):
    """Collected scheduled task paths, launchd labels and Open at Login names for the report picker."""
    return load_options(
        "system_background_options", "system_background_options", scope, ITEM_KINDS
    )


@router.get("/system/background", dependencies=[Depends(verify_authentication)])
def get_system_background(
    scope: dict = Depends(scope_query),
    items: str = Query(
        default="",
        max_length=16000,
        description='Selected items as a JSON array of "task:<path>", "launchd:<label>" or "loginItem:<name>"',
    ),
    enabled: str = Query(
        default="",
        max_length=60,
        description="enabled, disabled, unknown; comma separated",
    ),
    last_runs: str = Query(
        default="",
        max_length=120,
        alias="lastRuns",
        description="Task last result: succeeded, failed, running, notRun, informational, unknown, notApplicable",
    ),
    origins: str = Query(
        default="", max_length=60, description="builtIn, thirdParty, unknown"
    ),
    kinds: str = Query(
        default="", max_length=60, description="task, launchd, loginItem"
    ),
    freshness: Literal["all", "fresh", "stale", "unknown"] = "all",
    max_age_hours: int = Query(default=24, ge=1, le=8760, alias="maxAgeHours"),
    search: str = Query(default="", max_length=200),
    limit: int = Query(default=1000, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
):
    """One row per device and reported background item.

    Runs when items are selected, or fleet-wide for scheduled tasks whose last
    result is a failure. Rows describe reported items only; a device that does
    not list an item is not claimed to lack it.
    """
    enabled_filter, last_run_filter, origin_filter, kind_filter = (
        _list(enabled),
        set(_list(last_runs)),
        _list(origins),
        _list(kinds),
    )
    last_run_filter = {
        value for value in LAST_RUN_STATES if value.lower() in last_run_filter
    }
    if _list(enabled) - ENABLED_STATES:
        raise HTTPException(status_code=422, detail="Invalid enabled state")
    if set(_list(last_runs)) - {value.lower() for value in LAST_RUN_STATES}:
        raise HTTPException(status_code=422, detail="Invalid last run state")
    if origin_filter - {value.lower() for value in ORIGINS}:
        raise HTTPException(status_code=422, detail="Invalid source")
    if kind_filter - {value.lower() for value in ITEM_KINDS}:
        raise HTTPException(status_code=422, detail="Invalid item kind")
    selected = selected_items(items, ITEM_KINDS)
    failed_fleetwide = "failed" in last_run_filter
    now = now_utc()
    if not any(selected.values()) and not failed_fleetwide:
        return page(
            [],
            summary_keys=(),
            devices_in_scope=0,
            devices_without_inventory=0,
            limit=limit,
            offset=offset,
            now=now,
            query_required=True,
        )
    try:
        devices = load_devices(
            "system_background",
            {
                **scope,
                "task_keys": sorted(selected["task"]),
                "launchd_keys": sorted(selected["launchd"]),
                "login_keys": sorted(selected["loginItem"]),
                "failed_tasks": failed_fleetwide,
                "ok_codes": OK_CODES,
            },
        )
    except Exception:
        logger.exception("Fleet background items report failed")
        raise HTTPException(
            status_code=500, detail="Background items report unavailable"
        )

    def keep(row):
        return (
            (not kind_filter or row["kind"].lower() in kind_filter)
            and (not enabled_filter or row["enabledState"] in enabled_filter)
            and (not last_run_filter or row["lastRun"] in last_run_filter)
            and (not origin_filter or row["origin"].lower() in origin_filter)
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
    return page(
        rows,
        summary_keys=("enabledState", "lastRun", "origin", "kind"),
        devices_in_scope=len(devices),
        devices_without_inventory=without,
        limit=limit,
        offset=offset,
        now=now,
    )
