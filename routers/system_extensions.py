"""Read-only fleet report of macOS system extensions, kernel extensions and privileged helper tools.

Windows devices collect none of these, so the report only covers macOS.
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

ITEM_KINDS = ["systemExtension", "kernelExtension", "helper"]
ACTIVATIONS = {"activated", "notactivated", "unknown"}
SIGNATURES = {"signed", "unsigned", "unknown"}
MANAGED = {"yes", "no", "unknown"}


def activation(item):
    """System extension activation from the recorded systemextensionsctl state; other kinds have none."""
    if item.get("kind") != "systemExtension":
        return None
    state = item.get("state")
    state = state.strip().lower() if isinstance(state, str) else ""
    if not state:
        return "unknown"
    return "activated" if state in ("activated_enabled", "enabled") else "notActivated"


def signature(item):
    if item.get("kind") != "helper":
        return None
    value = boolean(item.get("signed"))
    return "unknown" if value is None else "signed" if value else "unsigned"


def managed(item):
    if item.get("kind") != "systemExtension":
        return None
    value = boolean(item.get("managedByProfile"))
    return "unknown" if value is None else "yes" if value else "no"


def shape_item(item):
    item["activation"] = activation(item)
    item["signature"] = signature(item)
    item["managed"] = managed(item)
    for field in ("signed", "loaded", "managedByProfile"):
        if field in item:
            item[field] = boolean(item[field])
    return item


@router.get("/system/extensions/filters", dependencies=[Depends(verify_authentication)])
def get_extension_options(scope: dict = Depends(scope_query)):
    """Collected extension identifiers, kernel extension names, helper tool names and team ids."""
    if scope["platform"] == "windows":
        return {"applicable": False, "items": [], "team": [], "options": {}}
    result = load_options(
        "system_extension_options",
        "system_extensions_options",
        scope,
        ITEM_KINDS,
        extra_kinds=("team",),
    )
    return {"applicable": True, **result}


@router.get("/system/extensions", dependencies=[Depends(verify_authentication)])
def get_system_extensions(
    scope: dict = Depends(scope_query),
    items: str = Query(
        default="",
        max_length=16000,
        description='Selected items as a JSON array of "systemExtension:<identifier>", "kernelExtension:<name>" or "helper:<name>"',
    ),
    activations: str = Query(
        default="",
        max_length=60,
        description="System extensions: activated, notActivated, unknown",
    ),
    signatures: str = Query(
        default="", max_length=60, description="Helper tools: signed, unsigned, unknown"
    ),
    managed_states: str = Query(
        default="",
        max_length=60,
        alias="managed",
        description="System extensions managed by a profile: yes, no, unknown",
    ),
    team_ids: str = Query(
        default="",
        max_length=2000,
        alias="teamIds",
        description="Developer team ids; comma separated",
    ),
    kinds: str = Query(
        default="",
        max_length=80,
        description="systemExtension, kernelExtension, helper",
    ),
    freshness: Literal["all", "fresh", "stale", "unknown"] = "all",
    max_age_hours: int = Query(default=24, ge=1, le=8760, alias="maxAgeHours"),
    search: str = Query(default="", max_length=200),
    limit: int = Query(default=1000, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
):
    """One row per Mac and reported extension or helper tool.

    Runs when items or team ids are selected, or fleet-wide for system
    extensions that are not activated and helper tools reported as unsigned.
    """
    activation_filter, signature_filter, managed_filter = (
        _list(activations),
        _list(signatures),
        _list(managed_states),
    )
    kind_filter, teams = _list(kinds), _list(team_ids)
    if activation_filter - ACTIVATIONS:
        raise HTTPException(status_code=422, detail="Invalid activation state")
    if signature_filter - SIGNATURES:
        raise HTTPException(status_code=422, detail="Invalid signature state")
    if managed_filter - MANAGED:
        raise HTTPException(status_code=422, detail="Invalid managed state")
    if kind_filter - {kind.lower() for kind in ITEM_KINDS}:
        raise HTTPException(status_code=422, detail="Invalid item kind")
    selected = selected_items(items, ITEM_KINDS)
    not_activated, unsigned = (
        "notactivated" in activation_filter,
        "unsigned" in signature_filter,
    )
    now = now_utc()
    if scope["platform"] == "windows" or (
        not any(selected.values()) and not teams and not not_activated and not unsigned
    ):
        result = page(
            [],
            summary_keys=(),
            devices_in_scope=0,
            devices_without_inventory=0,
            limit=limit,
            offset=offset,
            now=now,
            query_required=scope["platform"] != "windows",
        )
        return {**result, "applicable": scope["platform"] != "windows"}
    try:
        devices = load_devices(
            "system_extensions",
            {
                **scope,
                "system_keys": sorted(selected["systemExtension"]),
                "kernel_keys": sorted(selected["kernelExtension"]),
                "helper_keys": sorted(selected["helper"]),
                "team_ids": sorted(teams),
                "not_activated": not_activated,
                "unsigned": unsigned,
            },
        )
    except Exception:
        logger.exception("Fleet extensions report failed")
        raise HTTPException(status_code=500, detail="Extensions report unavailable")

    def keep(row):
        return (
            (not kind_filter or row["kind"].lower() in kind_filter)
            and (not teams or str(row.get("teamId") or "").lower() in teams)
            and (
                not activation_filter
                or str(row.get("activation") or "").lower() in activation_filter
            )
            and (
                not signature_filter or (row.get("signature") or "") in signature_filter
            )
            and (not managed_filter or (row.get("managed") or "") in managed_filter)
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
        summary_keys=("kind", "activation", "signature", "managed"),
        devices_in_scope=len(devices),
        devices_without_inventory=without,
        limit=limit,
        offset=offset,
        now=now,
    )
    return {**result, "applicable": True}
