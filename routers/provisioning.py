"""Fleet provisioning record: when each device was last wiped, and whether it came up built.

A wipe leaves three witnesses in what devices already report, and none of them is
enough alone:

- ``installDate`` from the system module is the OS-install timestamp. A wipe moves
  it, but so does an in-place feature update, and a device can also carry a stale one.
- ``autopilotConfig.policyDate`` from the management module is the Autopilot
  policy-cache write during OOBE. It moves when a device is re-provisioned and does
  not move for a feature update, so a policy write within minutes of the install
  date corroborates the install as a provisioning event. On clean wipes the two agree
  to within seconds; where they disagree they are days apart, not minutes.
- The ``Source OS (Updated on ...)`` markers under ``HKLM\\SYSTEM\\Setup``, projected
  as ``lastInPlaceUpgrade`` and ``inPlaceUpgradeCount``. Windows writes one per
  in-place upgrade. The wipe path has been seen writing one at the install date too,
  so a marker cannot rule a wipe out; it only explains an install date that
  Autopilot did not corroborate.

None of these is dropped or used to hold a device out of the result. Every device is
returned with each witness recorded beside it, so a consumer decides how strict to
be instead of inheriting a threshold it cannot see.

Convergence comes from the Cimian sessions /installs/full projects (the last five
per device). A device converged when any finished session in that window completed
cleanly. Asking only whether the latest session was clean reads a device as broken
for the hour one item happened to fail, and Cimian runs hourly forever, so the
answer would depend on the minute the request was made. Sessions still marked
running carry no verdict either way: a run cut off by a reboot never finishes.

The record is composed from the existing bulk projections in-process, so it shares
their caches and reads exactly what /system, /management and /installs/full serve.
"""

from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from dependencies import logger, paginate, verify_authentication
from pagination import add_pagination_headers
from routers import fleet

router = APIRouter(tags=["provisioning"])

# How close the Autopilot policy write has to sit to the OS install before the pair
# counts as one provisioning event. Loose next to the observed agreement (seconds)
# and tight next to the observed disagreements (days at the least).
CORROBORATION_WINDOW = timedelta(minutes=5)

# How close an in-place upgrade marker has to sit to the OS install before the
# install is attributed to that upgrade. Wider than the corroboration window because
# the marker is named from the machine's local clock in an unknown time zone, so the
# two can disagree by hours while describing the same event.
UPGRADE_ATTRIBUTION_WINDOW = timedelta(hours=36)

# A Cimian session in any of these states finished cleanly. Anything else -- most
# often ``partial_failure`` -- means at least one item did not install.
CLEAN_SESSION_STATES = frozenset({"success", "completed", "clean", "ok"})

# A session in one of these states has not finished, so it carries no verdict.
NON_TERMINAL_SESSION_STATES = frozenset(
    {"running", "started", "in_progress", "pending"}
)


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse an API timestamp to an aware UTC datetime, or None.

    /system has projected installDate without an offset, while Cimian session times
    carry one, so a naive value is read as UTC rather than dropped.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _status(session: Dict[str, Any]) -> str:
    return str(session.get("status") or "").lower()


def _session_time(session: Dict[str, Any]) -> Optional[datetime]:
    return parse_timestamp(
        session.get("end_time") or session.get("endTime")
    ) or parse_timestamp(session.get("start_time") or session.get("startTime"))


def _session_start(session: Dict[str, Any]) -> str:
    return str(session.get("start_time") or session.get("startTime") or "")


def convergence(cimian: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Convergence fields for one device from its projected Cimian sessions.

    ``converged`` is None when the device reports no Cimian data at all (a Mac, or
    a Windows device that never got as far as the management stack): no data is not
    the same claim as no clean run.
    """
    if not isinstance(cimian, dict) or not cimian:
        return {
            "converged": None,
            "lastCleanSessionAt": None,
            "lastSessionStatus": None,
            "lastSessionAt": None,
            "sessionsSeen": 0,
            "sessionsUnfinished": 0,
        }

    sessions = [s for s in (cimian.get("sessions") or []) if isinstance(s, dict)]
    finished = sorted(
        (s for s in sessions if _status(s) not in NON_TERMINAL_SESSION_STATES),
        key=_session_start,
    )
    clean_times = [
        t
        for t in (
            _session_time(s) for s in finished if _status(s) in CLEAN_SESSION_STATES
        )
        if t is not None
    ]
    clean_count = sum(1 for s in finished if _status(s) in CLEAN_SESSION_STATES)
    last = finished[-1] if finished else None
    return {
        "converged": clean_count > 0,
        "lastCleanSessionAt": _iso(max(clean_times)) if clean_times else None,
        "lastSessionStatus": (last.get("status") if last else None),
        "lastSessionAt": _iso(_session_time(last)) if last else None,
        "sessionsSeen": len(finished),
        "sessionsUnfinished": len(sessions) - len(finished),
    }


def derive_records(
    systems: Iterable[Dict[str, Any]],
    management: Iterable[Dict[str, Any]],
    installs: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """One provisioning record per device in the system projection.

    The system projection is the spine: it is where installDate and lastSeen come
    from, and every reporting device has one. Management and installs are joined on
    serial number and may be missing for any given device.
    """
    autopilot_by_serial = {
        d["serialNumber"]: (d.get("autopilotConfig") or {})
        for d in management
        if isinstance(d, dict) and d.get("serialNumber")
    }
    cimian_by_serial = {
        d["serialNumber"]: ((d.get("modules") or {}).get("installs") or {}).get(
            "cimian"
        )
        for d in installs
        if isinstance(d, dict) and d.get("serialNumber")
    }

    records = []
    for device in systems:
        if not isinstance(device, dict):
            continue
        serial = device.get("serialNumber")
        if not serial:
            continue

        installed = parse_timestamp(device.get("installDate"))
        autopilot = autopilot_by_serial.get(serial) or {}
        policy_written = parse_timestamp(autopilot.get("policyDate"))
        corroborated = (
            None
            if installed is None
            else policy_written is not None
            and abs(policy_written - installed) <= CORROBORATION_WINDOW
        )

        upgraded = parse_timestamp(device.get("lastInPlaceUpgrade"))
        upgrade_at_install = (
            None
            if installed is None or upgraded is None
            else abs(upgraded - installed) <= UPGRADE_ATTRIBUTION_WINDOW
        )

        record = {
            "serialNumber": serial,
            "deviceId": device.get("deviceId") or serial,
            "deviceName": device.get("deviceName") or serial,
            "assetTag": device.get("assetTag"),
            "platform": device.get("platform"),
            "usage": device.get("usage"),
            "catalog": device.get("catalog"),
            "location": device.get("location"),
            "area": device.get("area"),
            "fleet": device.get("fleet"),
            "lastSeen": device.get("lastSeen"),
            "installDate": device.get("installDate"),
            "wipedAt": _iso(installed),
            "autopilotPolicyDate": autopilot.get("policyDate"),
            "autopilotStatus": autopilot.get("status"),
            "corroborated": corroborated,
            "lastInPlaceUpgrade": device.get("lastInPlaceUpgrade"),
            # None means the client has not reported the markers yet; only 0 says
            # the OS has never been upgraded over.
            "inPlaceUpgradeCount": device.get("inPlaceUpgradeCount"),
            "upgradeAtInstall": upgrade_at_install,
        }
        record.update(convergence(cimian_by_serial.get(serial)))
        if device.get("inventoryState"):
            record["inventoryState"] = device["inventoryState"]
        records.append(record)
    return records


def parse_bound(
    value: Optional[str], name: str, end_of_day: bool
) -> Optional[datetime]:
    """Parse a wipe-range bound given as a date or a timestamp.

    A bare date as the upper bound covers that whole day, so
    ``wipedFrom=2026-08-01&wipedTo=2026-08-31`` means all of August.
    """
    if value is None or value == "":
        return None
    try:
        day = date.fromisoformat(value)
    except ValueError:
        day = None
    if day is not None:
        start = datetime.combine(day, time.min, tzinfo=timezone.utc)
        return (
            start + timedelta(days=1) - timedelta(microseconds=1)
            if end_of_day
            else start
        )
    parsed = parse_timestamp(value)
    if parsed is None:
        raise HTTPException(
            status_code=422,
            detail=f"{name} must be an ISO-8601 date or timestamp, got {value!r}",
        )
    return parsed


def filter_records(
    records: List[Dict[str, Any]],
    *,
    wiped_from: Optional[datetime] = None,
    wiped_to: Optional[datetime] = None,
    platform: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Apply the wipe date range and platform filters.

    A device with no install date cannot be placed in a range, so it falls out of
    any ranged query and stays in an unranged one.
    """
    wanted_platform = (platform or "").strip().lower()
    out = []
    for record in records:
        if (
            wanted_platform
            and (record.get("platform") or "").lower() != wanted_platform
        ):
            continue
        if wiped_from is not None or wiped_to is not None:
            wiped = parse_timestamp(record.get("wipedAt"))
            if wiped is None:
                continue
            if wiped_from is not None and wiped < wiped_from:
                continue
            if wiped_to is not None and wiped > wiped_to:
                continue
        out.append(record)
    return out


@router.get(
    "/provisioning",
    dependencies=[Depends(verify_authentication)],
    tags=["provisioning"],
)
def get_fleet_provisioning(
    request: Request,
    response: Response,
    wiped_from: Optional[str] = Query(
        default=None,
        alias="wipedFrom",
        description="Only devices whose OS install date is at or after this date or timestamp",
    ),
    wiped_to: Optional[str] = Query(
        default=None,
        alias="wipedTo",
        description="Only devices whose OS install date is at or before this; a bare date covers the whole day",
    ),
    platform: Optional[str] = Query(
        default=None,
        description="Only devices on this platform, e.g. Windows or macOS",
    ),
    include_archived: bool = Query(
        default=False,
        alias="includeArchived",
        description="Include archived devices",
    ),
    limit: Optional[int] = Query(
        default=None, ge=1, le=5000, description="Maximum items to return"
    ),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Per-device provisioning record for the whole fleet.

    For each device: the OS install date (the wipe proxy) as ``wipedAt``, whether the
    Autopilot policy write corroborates it (``corroborated``), the in-place upgrade
    markers and whether one sits at the install date (``upgradeAtInstall``), Cimian
    convergence over the projected sessions (``converged``, ``lastCleanSessionAt``,
    ``lastSessionStatus``, ``sessionsSeen``, ``sessionsUnfinished``), and ``lastSeen``.

    ``corroborated`` and ``upgradeAtInstall`` are null when there is no install date
    to compare against; ``converged`` is null when the device reports no Cimian data.

    Filter by wipe date range with ``wipedFrom``/``wipedTo``. Paged with
    ``limit``/``offset``; ``X-Total-Count`` carries the filtered total.
    """
    lower = parse_bound(wiped_from, "wipedFrom", end_of_day=False)
    upper = parse_bound(wiped_to, "wipedTo", end_of_day=True)
    if lower is not None and upper is not None and lower > upper:
        raise HTTPException(status_code=422, detail="wipedFrom is after wipedTo")

    systems = fleet.get_bulk_system(
        request=request,
        response=Response(),
        include_archived=include_archived,
        limit=None,
        offset=0,
    )
    management = fleet.get_bulk_management(
        include_archived=include_archived,
        limit=None,
        offset=0,
    )
    installs = fleet.get_bulk_installs_full(
        include_archived=include_archived,
        limit=None,
        offset=0,
    )

    records = filter_records(
        derive_records(systems, management, installs),
        wiped_from=lower,
        wiped_to=upper,
        platform=platform,
    )
    logger.info(f"Provisioning record: {len(records)} devices after filters")
    add_pagination_headers(
        response, request, total=len(records), limit=limit, offset=offset
    )
    return paginate(records, limit, offset)
