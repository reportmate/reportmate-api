"""Fleet-wide bulk data endpoints for analytics dashboards."""

import json
import time as _time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from pagination import add_pagination_headers
from log_tails import classify_line, normalize_message, parse_levels, sql_pattern_for_levels

from dependencies import (
    cache_get, cache_set, get_db_connection, load_sql, logger,
    canonicalize_app_name, normalize_app_name, paginate, verify_authentication,
    build_os_summary, infer_platform,
)

router = APIRouter(tags=["fleet"])

# Well-known Windows service principals. Matched on the portion after the
# domain separator so the localized authority names (NT-AUTORITAET, AUTORITE NT)
# fall out too.
_SERVICE_PRINCIPAL_NAMES = frozenset({
    "system", "local service", "network service", "localsystem",
    "trustedinstaller", "local system",
})


# A managed-software agent that has stopped running is invisible in every
# per-item metric, because the device keeps re-uploading the last report it
# managed to produce. Its records stay whatever they were on the day the agent
# died -- overwhelmingly "installed" -- so it contributes nothing to error or
# warning counts and reads as one of the healthiest machines in the fleet while
# receiving no software updates at all.
#
# The tell is the gap between a device still checking in and its agent's last
# completed session. Measured against lastSeen rather than now on purpose: a
# device that is simply powered off has BOTH timestamps old and is not stale,
# it is just absent. Only a device reporting in while its agent is silent is
# actually broken, and that is what this measures.
STALE_AGENT_THRESHOLD_DAYS = 1.0


def _parse_iso(raw: Any) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp to an aware UTC datetime, or None.

    Mirrors the parsing already used for install-item timestamps in the admin
    router: tolerate a trailing Z, and treat a naive timestamp as UTC so that
    comparisons against tz-aware check-in times cannot raise.
    """
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# The two agents record their last run in different shapes, and reading only
# one of them yields None for every device on the other platform -- parity in
# code and a silent no-op in practice. Cimian carries a sessions[] list with
# per-session end_time/start_time; Munki reports a single endTime/startTime on
# the module itself and has no sessions[] at all.
_RUN_TIME_KEYS = ("end_time", "endTime", "start_time", "startTime")


def _newest_run_time(record: Dict[str, Any]) -> Optional[datetime]:
    """Best available run timestamp from one session or module record.

    Prefers an end time and falls back to a start time, so a run that was cut
    short still counts as evidence the agent ran.
    """
    for key in _RUN_TIME_KEYS:
        parsed = _parse_iso(record.get(key))
        if parsed is not None:
            return parsed
    return None


def agent_last_run(agent: Optional[Dict[str, Any]]) -> Optional[datetime]:
    """Newest completed-run timestamp for a management agent, either shape.

    Sessions arrive newest-first, but that is the producer's ordering rather
    than a guarantee, so take the maximum instead of the first element. When
    an agent reports no sessions[], fall back to the run timestamps on the
    module itself.
    """
    if not isinstance(agent, dict) or not agent:
        return None

    sessions = agent.get("sessions")
    newest = None
    if isinstance(sessions, list):
        for session in sessions:
            if not isinstance(session, dict):
                continue
            parsed = _newest_run_time(session)
            if parsed is not None and (newest is None or parsed > newest):
                newest = parsed
    if newest is not None:
        return newest

    return _newest_run_time(agent)


def agent_stale_days(
    last_run: Optional[datetime], last_seen: Optional[datetime]
) -> Optional[float]:
    """Days a device kept checking in after its agent last completed a run.

    None when either timestamp is missing -- a device with no session history
    has nothing to compare and must not be reported as stale. Negative drift
    (a run recorded after the last check-in) clamps to 0.0 rather than
    surfacing as a nonsensical negative age.
    """
    if last_run is None or last_seen is None:
        return None
    return max(0.0, (last_seen - last_run).total_seconds() / 86400.0)


def is_human_principal(username: Optional[str]) -> bool:
    """
    True when a usage_history user entry plausibly names a person.

    The Security Log path records the subject of event 4688, which is the
    account that created the process -- for anything launched by a service, a
    scheduled task or the machine itself that is DOMAIN\\COMPUTER$, not the
    person at the keyboard. Lab and render machines therefore dominated both
    uniqueUsers and topUsers: 253 of 513 principals in a 2-day fleet window
    were computer accounts, and the three heaviest "users" of software on
    campus were machines. Work item 4522.

    Only unambiguous non-humans are excluded. Shared local accounts such as
    `student` and service accounts such as `dl-worker` are real logins that
    happen not to be one person, which is a policy question rather than a
    detectable property, so they are left in and tracked separately.
    """
    if not username:
        return False
    name = username.strip()
    if not name:
        return False
    # Computer accounts always end in $ in Windows.
    if name.endswith("$"):
        return False
    leaf = name.split("\\")[-1].strip().lower()
    if leaf in _SERVICE_PRINCIPAL_NAMES:
        return False
    if name.split("\\")[0].strip().lower() == "nt authority":
        return False
    return True

@router.get("/applications/filters", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_applications_filters(
    include_archived: bool = Query(default=False, alias="includeArchived")
):
    """
    Lightweight endpoint for application filter options.
    
    Returns unique application names, publishers, categories, and inventory
    filter values using SQL DISTINCT queries — without downloading all records.
    Also returns a lightweight device list (serial, name, inventory fields)
    for the "missing" report mode.
    
    This replaces the pattern of calling /api/devices/applications?loadAll=true
    and processing 200K+ records client-side.
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("applications_filters", _ckey)
        if _cached is not None:
            return _cached
        _t0 = _time.monotonic()
        logger.info(f"Fetching applications filter options (includeArchived={include_archived})")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Extract unique app names, publishers, categories via JSONB unnesting
        options_query = load_sql("devices/applications_filter_options")
        cursor.execute(options_query, {"include_archived": include_archived})
        option_rows = cursor.fetchall()
        
        app_names = set()
        windows_app_names = set()
        mac_app_names = set()
        publishers = set()
        categories = set()
        
        for app_name, publisher, category, platform in option_rows:
            if app_name and app_name.strip():
                app_names.add(app_name.strip())
                if platform in ('Windows NT', 'Windows'):
                    windows_app_names.add(app_name.strip())
                elif platform in ('Darwin', 'macOS'):
                    mac_app_names.add(app_name.strip())
            if publisher and publisher.strip():
                publishers.add(publisher.strip())
            if category and category.strip():
                categories.add(category.strip())
        
        # 2. Get lightweight device list with inventory metadata
        devices_query = load_sql("devices/applications_filter_devices")
        cursor.execute(devices_query, {"include_archived": include_archived})
        device_rows = cursor.fetchall()
        
        conn.close()
        
        usages = set()
        catalogs = set()
        locations = set()
        areas = set()
        fleets = set()
        devices = []

        for serial, device_name, usage, catalog, location, department, fleet in device_rows:
            devices.append({
                'serialNumber': serial,
                'name': device_name or serial,
                'usage': usage or '',
                'catalog': catalog or '',
                'location': location or '',
                'room': location or '',
                'department': department or '',
                'area': department or '',
                'fleet': fleet or ''
            })
            if usage:
                usages.add(usage)
            if catalog:
                catalogs.add(catalog)
            if location:
                locations.add(location)
            if department:
                areas.add(department)
            if fleet:
                fleets.add(fleet)

        logger.info(f"Applications filters: {len(app_names)} unique apps, {len(publishers)} publishers, {len(devices)} devices")

        _result = {
            'applicationNames': sorted(app_names),
            'windowsApplicationNames': sorted(windows_app_names),
            'macApplicationNames': sorted(mac_app_names),
            'publishers': sorted(publishers),
            'categories': sorted(categories),
            'usages': sorted(usages),
            'catalogs': sorted(catalogs),
            'locations': sorted(locations),
            'rooms': sorted(locations),
            'areas': sorted(areas),
            'fleets': sorted(fleets),
            'devices': devices,
            'devicesWithData': len(devices)
        }
        cache_set("applications_filters", _result, _ckey)
        logger.info(f"[PERF] /api/devices/applications/filters: {_time.monotonic()-_t0:.3f}s")
        return _result
        
    except Exception as e:
        logger.error(f"Failed to get applications filters: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve applications filters: {str(e)}")


def fold_installed_devices(rows, picked_by_lower: Dict[str, str]) -> Dict[str, set]:
    """
    Fold (installed app name, [serials]) rows into device sets keyed by the
    lowercased usage bucket name.

    With an explicit pick list the usage buckets are the caller's raw names,
    so an installed name counts only when it matches a pick exactly (case-
    insensitively). Fleet-wide, the same canonical alias map that folds usage
    rows folds the inventory, so "Adobe Illustrator 2025" lands on the
    "Adobe Illustrator" bucket and "Adobe Acrobat (64-bit)" on "Adobe Acrobat".
    A device with several matching entries counts once per bucket.
    """
    folded: Dict[str, set] = {}
    for raw_name, serials in rows:
        raw = (raw_name or "").strip()
        # macOS inventories the bundle filename ("Microsoft Outlook.app");
        # the watcher reports the bundle name. Without this only the names an
        # alias regex happens to catch (Chrome, Firefox) fold, and every other
        # Mac app reads 0 installed.
        if raw.lower().endswith(".app"):
            raw = raw[:-4].strip()
        if not raw:
            continue
        if picked_by_lower:
            key = picked_by_lower.get(raw.lower())
            if key is None:
                continue
        else:
            key = canonicalize_app_name(raw) or raw
        folded.setdefault(key.lower(), set()).update(serials or [])
    return folded


@router.get("/applications/usage", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_fleet_applications_usage(
    request: Request,
    days: int = Query(default=30, ge=1, le=548, description="Lookback window in days"),
    applicationNames: Optional[str] = Query(default=None, description="Comma-separated app names to include"),
    usages: Optional[str] = Query(default=None, description="Comma-separated inventory usages"),
    catalogs: Optional[str] = Query(default=None, description="Comma-separated inventory catalogs"),
    locations: Optional[str] = Query(default=None, description="Comma-separated inventory locations"),
    areas: Optional[str] = Query(default=None, description="Comma-separated inventory areas (department)"),
    fleets: Optional[str] = Query(default=None, description="Comma-separated inventory fleets"),
    rooms: Optional[str] = Query(default=None, description="Comma-separated inventory rooms"),
    platforms: Optional[str] = Query(default=None, description="Comma-separated platforms (windows/macos)"),
    minHours: Optional[float] = Query(default=None, ge=0, description="Minimum total hours to include an app"),
    minLaunches: Optional[int] = Query(default=None, ge=0, description="Minimum launch count to include an app"),
    include_archived: bool = Query(default=False, alias="includeArchived"),
):
    """
    Fleet-wide application usage aggregation from `usage_history`.

    Aggregates per-app totals across all devices within the lookback window,
    with optional inventory-based scoping (usages/catalogs/locations) and
    per-app filtering. Returns the shape consumed by the Generate Report ->
    Utilization view on /devices/applications.

    Which number to quote, because two of them look interchangeable and are not:

    - **activeHours** is the faculty-facing figure: foreground *and* user input
      within the prior 300s. **totalHours** is summed process lifetime with no
      wall-clock ceiling and is diagnostic only.
    - **activeDeviceCount / activeUserCount** count only devices and users that
      contributed non-zero active time. **deviceCount / userCount** count every
      device and user that produced any usage row at all, including rows that
      are pure background process time.
    - **installedDeviceCount** is the number of in-scope devices whose
      applications inventory lists the app, folded with the same alias rules.
      It is the only install figure here; deviceCount is not one.

    For a licence or seat question, use the active counts. The plain counts
    describe installation footprint, which for a background service is close to
    the whole managed fleet -- Houdini reported 184 devices and 229 users
    against 0.5 active hours over 30 days, and Chrome 218 devices against 13
    users. Both are returned because footprint is a legitimate question; it is
    just not the same question, and the names are the only thing distinguishing
    them.

    `isSingleActiveUser` is the seat-relevant form of `isSingleUser`, which is
    retained unchanged for existing callers.
    """
    conn = None
    try:
        _ckey = (str(dict(sorted(request.query_params.items()))),)
        _cached = cache_get("applications_usage", _ckey)
        if _cached is not None:
            return _cached

        _t0 = _time.monotonic()

        app_name_list = [s.strip() for s in applicationNames.split(',')] if applicationNames else []
        usage_list = [s.strip() for s in usages.split(',')] if usages else []
        catalog_list = [s.strip() for s in catalogs.split(',')] if catalogs else []
        location_list = [s.strip() for s in locations.split(',')] if locations else []
        area_list = [s.strip() for s in areas.split(',')] if areas else []
        fleet_list = [s.strip() for s in fleets.split(',')] if fleets else []
        room_list = [s.strip() for s in rooms.split(',')] if rooms else []
        platform_list = [s.strip().lower() for s in platforms.split(',')] if platforms else []

        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days)).date()

        conn = get_db_connection()
        cursor = conn.cursor()

        where = [
            "uh.date >= %s",
            "d.serial_number IS NOT NULL",
            "d.serial_number NOT LIKE 'TEST-%%'",
            "d.serial_number != 'localhost'",
        ]
        params: List[Any] = [cutoff_date]

        if not include_archived:
            where.append("d.archived = FALSE")

        if app_name_list:
            # Exact (case-insensitive) match. The user picked specific apps from
            # the report-builder chip cloud and expects the report to show
            # *exactly* those apps — not also Maya plugins that happen to
            # contain "motion", or "Final Cut Pro Creator Studio" rolled into
            # "Final Cut Pro" via aliasing. Substring + alias rules conflate
            # distinct inventory products; exact match keeps a 1:1 mapping
            # between picker chips and report rows.
            where.append("LOWER(uh.app_name) = ANY(%s)")
            params.append([n.lower() for n in app_name_list])

        # Inventory and platform scope is kept apart from the usage_history
        # conditions because the installed-footprint query below has to
        # apply the same scope to the applications table.
        scope_where: List[str] = []
        scope_params: List[Any] = []
        if usage_list:
            scope_where.append("LOWER(inv.data->>'usage') = ANY(%s)")
            scope_params.append([s.lower() for s in usage_list])

        if catalog_list:
            scope_where.append("LOWER(inv.data->>'catalog') = ANY(%s)")
            scope_params.append([s.lower() for s in catalog_list])

        if location_list:
            scope_where.append("LOWER(inv.data->>'location') = ANY(%s)")
            scope_params.append([s.lower() for s in location_list])

        if area_list:
            scope_where.append("LOWER(inv.data->>'department') = ANY(%s)")
            scope_params.append([s.lower() for s in area_list])

        if fleet_list:
            scope_where.append("LOWER(inv.data->>'fleet') = ANY(%s)")
            scope_params.append([s.lower() for s in fleet_list])

        if room_list:
            # Filter-options endpoint exposes "rooms" populated from
            # inv.data->>'location', so match against the same field with
            # 'room' as a fallback for clients that send both keys.
            scope_where.append("LOWER(COALESCE(inv.data->>'location', inv.data->>'room')) = ANY(%s)")
            scope_params.append([s.lower() for s in room_list])

        if platform_list:
            # Expand user-facing labels into the raw platform tokens we store
            # (Darwin for macOS clients, "Windows" / "Windows NT" / "Microsoft Windows ..." for Windows).
            def _expand_platform(p: str) -> list[str]:
                p = p.strip().lower()
                if p in ('mac', 'macos', 'darwin'):
                    return ['%macos%', '%darwin%', '%os x%']
                if p in ('win', 'windows'):
                    return ['%windows%']
                return [f'%{p}%']
            patterns: list[str] = []
            for p in platform_list:
                patterns.extend(_expand_platform(p))
            scope_where.append("LOWER(COALESCE(d.platform, '')) ILIKE ANY(%s)")
            scope_params.append(patterns)

        where.extend(scope_where)
        params.extend(scope_params)
        where_clause = " AND ".join(where)

        # Per-app aggregate. Avoid correlated subqueries — they balloon cost
        # on unfiltered queries. Get per-app totals here; users list comes from
        # a separate, single-pass jsonb unnest below.
        app_query = f"""
            SELECT
                uh.app_name,
                SUM(uh.launches)::bigint                                              AS launch_count,
                SUM(uh.total_seconds)::double precision                               AS total_seconds,
                SUM(COALESCE(uh.active_seconds, 0))::double precision                 AS active_seconds,
                SUM(COALESCE(uh.foreground_seconds, 0))::double precision             AS foreground_seconds,
                COUNT(DISTINCT uh.device_id)::int                                     AS device_count,
                MIN(uh.date)::text                                                    AS first_used,
                MAX(uh.date)::text                                                    AS last_used,
                ARRAY_AGG(DISTINCT uh.device_id)                                      AS devices,
                ARRAY_AGG(DISTINCT uh.device_id)
                    FILTER (WHERE COALESCE(uh.active_seconds, 0) > 0)                 AS active_devices
            FROM usage_history uh
            JOIN devices d ON d.serial_number = uh.device_id
            LEFT JOIN inventory inv ON inv.device_id = d.id
            WHERE {where_clause}
            GROUP BY uh.app_name
            ORDER BY total_seconds DESC
        """
        cursor.execute(app_query, tuple(params))
        app_rows = cursor.fetchall()

        # Per-app distinct user list. Single unnest pass over the same scope.
        users_by_app_query = f"""
            SELECT uh.app_name,
                   ARRAY_AGG(DISTINCT u) AS users,
                   ARRAY_AGG(DISTINCT u)
                       FILTER (WHERE COALESCE(uh.active_seconds, 0) > 0) AS active_users
            FROM usage_history uh
            JOIN devices d ON d.serial_number = uh.device_id
            LEFT JOIN inventory inv ON inv.device_id = d.id
            CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(uh.users, '[]'::jsonb)) AS u
            WHERE {where_clause}
              AND u IS NOT NULL AND u <> ''
            GROUP BY uh.app_name
        """
        cursor.execute(users_by_app_query, tuple(params))
        _user_rows = cursor.fetchall()
        users_by_app: Dict[str, List[str]] = {
            row[0]: list(row[1] or []) for row in _user_rows
        }
        # FILTER yields NULL rather than an empty array when nothing matches,
        # which is the common case for a pure background service.
        active_users_by_app: Dict[str, List[str]] = {
            row[0]: list(row[2] or []) for row in _user_rows
        }

        # Group rows into report buckets. Behavior depends on whether the
        # caller asked for specific apps:
        #
        #  - Explicit list (chip-cloud pick): keep raw app names distinct so
        #    each chip → exactly one row, no aliasing surprises like
        #    "Final Cut Pro Creator Studio" being silently merged into
        #    "Final Cut Pro" via the canonical alias map.
        #  - No list (fleet-wide view): canonicalize and fold variants like
        #    "Houdini Launcher" + "hindie.exe" into one "Houdini" row.
        #
        # minHours / minLaunches apply after rollup so they reflect bucket
        # totals, not pre-rollup fragments — but only when there's no explicit
        # pick list (an explicit pick should always show, even with zero data).
        # For explicit picks: build a lookup from lowercase -> the caller's
        # exact-cased pick. SQL matched case-insensitively, so different
        # clients can report the same app with different casing ("Logic Pro"
        # vs "logic pro") — fold them into one bucket keyed by the caller's
        # canonical casing so the chip cloud and the report row stay 1:1.
        picked_by_lower: Dict[str, str] = {}
        if app_name_list:
            for picked in app_name_list:
                picked_by_lower.setdefault(picked.lower(), picked)

        canonical_apps: Dict[str, Dict[str, Any]] = {}
        for (app_name, launch_count, total_secs, active_secs, foreground_secs,
             _device_count, first_used, last_used, devices, active_devices) in app_rows:
            if app_name_list:
                bucket_key = picked_by_lower.get((app_name or '').lower(), app_name)
            else:
                bucket_key = canonicalize_app_name(app_name) or app_name
            entry = canonical_apps.setdefault(bucket_key, {
                "totalSeconds": 0.0,
                "activeSeconds": 0.0,
                "foregroundSeconds": 0.0,
                "launchCount": 0,
                "deviceSet": set(),
                "userSet": set(),
                "activeDeviceSet": set(),
                "activeUserSet": set(),
                "firstUsed": first_used,
                "lastUsed": last_used,
                "aliasedFrom": set(),
            })
            entry["totalSeconds"] += float(total_secs or 0)
            entry["activeSeconds"] += float(active_secs or 0)
            entry["foregroundSeconds"] += float(foreground_secs or 0)
            entry["launchCount"] += int(launch_count or 0)
            entry["deviceSet"].update(devices or [])
            entry["userSet"].update(
                u for u in users_by_app.get(app_name, []) if is_human_principal(u)
            )
            entry["activeDeviceSet"].update(active_devices or [])
            entry["activeUserSet"].update(
                u for u in active_users_by_app.get(app_name, []) if is_human_principal(u)
            )
            if first_used and (not entry["firstUsed"] or first_used < entry["firstUsed"]):
                entry["firstUsed"] = first_used
            if last_used and (not entry["lastUsed"] or last_used > entry["lastUsed"]):
                entry["lastUsed"] = last_used
            if app_name and app_name != bucket_key:
                entry["aliasedFrom"].add(app_name)

        # For explicit picks, ensure every chip the user selected appears in
        # the report — even with zero data. Without this, an app with no
        # usage_history rows in the lookback window is silently dropped, which
        # is confusing when the chip is right there in the picker.
        if app_name_list:
            existing_lower = {k.lower() for k in canonical_apps.keys()}
            for picked in app_name_list:
                if picked.lower() not in existing_lower:
                    canonical_apps[picked] = {
                        "totalSeconds": 0.0,
                        "activeSeconds": 0.0,
                        "foregroundSeconds": 0.0,
                        "launchCount": 0,
                        "deviceSet": set(),
                        "userSet": set(),
                        "activeDeviceSet": set(),
                        "activeUserSet": set(),
                        "firstUsed": None,
                        "lastUsed": None,
                        "aliasedFrom": set(),
                    }

        # Installed footprint from the applications inventory, folded with the
        # same alias rules as the usage buckets. deviceCount above is the set
        # of devices that produced a usage row in the window, which the web
        # used to label "installed": on macOS the watcher only records GUI
        # sessions, and on both platforms the window bottoms out at the last
        # baseline reset, so it undercounts installs by most of the fleet
        # (Chrome read 105 devices against 847 installs the day after the
        # 2026-09-01 reset). Installs are a different question with a direct
        # answer in the inventory, and the April active-vs-installed gap
        # needs that answer as its denominator.
        installed_where = [
            "d.serial_number IS NOT NULL",
            "d.serial_number NOT LIKE 'TEST-%%'",
            "d.serial_number != 'localhost'",
            "a.data IS NOT NULL",
        ] + scope_where
        if not include_archived:
            installed_where.append("d.archived = FALSE")
        installed_query = f"""
            WITH device_base AS (
                SELECT DISTINCT ON (d.serial_number)
                    d.serial_number AS serial,
                    CASE
                        WHEN a.data ? 'installedApplications' THEN a.data->'installedApplications'
                        WHEN a.data ? 'InstalledApplications' THEN a.data->'InstalledApplications'
                        WHEN a.data ? 'installed_applications' THEN a.data->'installed_applications'
                        WHEN jsonb_typeof(a.data) = 'array' THEN a.data
                        ELSE '[]'::jsonb
                    END AS apps_array
                FROM devices d
                JOIN applications a ON d.id = a.device_id
                LEFT JOIN inventory inv ON inv.device_id = d.id
                WHERE {" AND ".join(installed_where)}
                ORDER BY d.serial_number, a.updated_at DESC
            )
            SELECT COALESCE(elem->>'name', elem->>'displayName', '') AS app_name,
                   ARRAY_AGG(DISTINCT db.serial)                      AS devices
            FROM device_base db
            CROSS JOIN LATERAL jsonb_array_elements(db.apps_array) AS elem
            WHERE COALESCE(elem->>'name', elem->>'displayName', '') <> ''
            GROUP BY 1
        """
        cursor.execute(installed_query, tuple(scope_params))
        installed_by_bucket = fold_installed_devices(cursor.fetchall(), picked_by_lower)

        applications: List[Dict[str, Any]] = []
        total_seconds_sum = 0.0
        # Summed separately from total_seconds because the two answer different
        # questions. total_seconds is process lifetime summed over concurrent
        # processes and has no wall-clock ceiling, so its fleet sum routinely
        # exceeds devices x 24 x days by more than an order of magnitude and is
        # not reportable on its own. Work item 4251; surfaced by 4521.
        total_active_seconds_sum = 0.0
        total_launches_sum = 0
        single_user_apps: List[Dict[str, Any]] = []
        all_users: set = set()
        all_devices: set = set()
        # Devices that survived the minHours / minLaunches cutoff. Used below
        # to narrow devicesAggregate so the widget device count matches the
        # per-app table count exactly (otherwise apps dropped here would still
        # contribute their devices to the widget aggregate).
        kept_device_set: set = set()

        for canonical_name, agg in canonical_apps.items():
            total_secs = agg["totalSeconds"]
            active_secs = agg["activeSeconds"]
            foreground_secs = agg["foregroundSeconds"]
            launch_count = agg["launchCount"]
            devices = sorted(agg["deviceSet"])
            users = sorted(agg["userSet"])
            device_count = len(devices)
            user_count = len(users)
            # Devices and users that contributed real attention, not merely a
            # process that ran. deviceCount/userCount answer "where is this
            # installed and running", which for a background service is the
            # whole managed fleet: Houdini read 184 devices and 229 users
            # against 0.5 active hours over 30 days, and Chrome 218 devices
            # against 13 users. Quoted as seats those numbers are simply wrong,
            # and seats are what a licence review buys. Both are kept, because
            # install footprint is a real question too -- it just is not this
            # one.
            active_devices = sorted(agg["activeDeviceSet"])
            active_users = sorted(agg["activeUserSet"])
            active_device_count = len(active_devices)
            active_user_count = len(active_users)
            installed_device_count = len(installed_by_bucket.get(canonical_name.lower(), ()))
            total_hours = round(total_secs / 3600, 2)
            active_hours = round(active_secs / 3600, 2)
            foreground_hours = round(foreground_secs / 3600, 2)
            # Engagement ratio: how much of the "open" time was actually active use.
            # Null when total is 0 OR no client in the fleet has reported active_seconds yet.
            active_ratio = round(active_secs / total_secs, 3) if total_secs > 0 and active_secs > 0 else None

            # minHours / minLaunches only apply in fleet-wide mode. When the
            # caller picked specific apps, we always include them even with
            # zero data so the report mirrors the chip-cloud selection.
            if not app_name_list:
                if minHours is not None and total_hours < minHours:
                    continue
                if minLaunches is not None and launch_count < minLaunches:
                    continue

            kept_device_set.update(devices)
            # Now counts humans only, which is what this flag was always meant
            # to mean: an application one *person* uses is a single-seat licence
            # candidate. Counting machine accounts made it read "installed on
            # one lab machine" instead, and that is the evidence the software
            # value reviews depend on. Apps driven only by service or computer
            # accounts land at zero users and are correctly not single-user.
            is_single_user = user_count == 1
            # Deliberately a second field rather than a redefinition of
            # isSingleUser. That one is load bearing for existing callers,
            # and silently changing what it means would be worse than
            # adding a field that says what it means in its name.
            is_single_active_user = active_user_count == 1
            applications.append({
                "name": canonical_name,
                "totalSeconds": total_secs,
                "totalHours": total_hours,
                "activeSeconds": active_secs,
                "activeHours": active_hours,
                "foregroundSeconds": foreground_secs,
                "foregroundHours": foreground_hours,
                "activeRatio": active_ratio,
                "launchCount": launch_count,
                "deviceCount": device_count,
                "userCount": user_count,
                "activeDeviceCount": active_device_count,
                "activeUserCount": active_user_count,
                "installedDeviceCount": installed_device_count,
                "lastUsed": agg["lastUsed"],
                "firstUsed": agg["firstUsed"],
                "devices": devices,
                "users": users,
                "isSingleUser": is_single_user,
                "isSingleActiveUser": is_single_active_user,
                "activeDevices": active_devices,
                "activeUsers": active_users,
                "aliasedFrom": sorted(agg["aliasedFrom"]),
            })

            total_seconds_sum += total_secs
            total_active_seconds_sum += active_secs
            total_launches_sum += launch_count
            all_users.update(users)
            all_devices.update(devices)

            if is_single_user:
                single_user_apps.append({"name": canonical_name, "totalHours": total_hours})

        applications.sort(key=lambda a: a["totalSeconds"], reverse=True)

        # Top users: same WHERE scope, unnest users JSONB once.
        user_query = f"""
            SELECT
                u                                       AS username,
                SUM(uh.total_seconds)::double precision AS total_seconds,
                SUM(uh.launches)::bigint                AS launch_count,
                COUNT(DISTINCT uh.app_name)::int        AS apps_used,
                COUNT(DISTINCT uh.device_id)::int       AS devices_used
            FROM usage_history uh
            JOIN devices d ON d.serial_number = uh.device_id
            LEFT JOIN inventory inv ON inv.device_id = d.id
            CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(uh.users, '[]'::jsonb)) AS u
            WHERE {where_clause}
              AND u IS NOT NULL AND u <> ''
              -- Computer accounts always end in $. Excluded here rather than
              -- only in Python so the row cap below is spent on candidate
              -- humans; the remaining service principals are rejected by
              -- is_human_principal, which owns the full rule.
              AND u NOT LIKE '%%$'
            GROUP BY u
            ORDER BY total_seconds DESC
            LIMIT 200
        """
        cursor.execute(user_query, tuple(params))
        top_users = []
        for username, total_secs, launch_count, apps_used, devices_used in cursor.fetchall():
            if not is_human_principal(username):
                continue
            if len(top_users) >= 50:
                break
            total_secs = float(total_secs or 0)
            top_users.append({
                "username": username,
                "totalSeconds": total_secs,
                "totalHours": round(total_secs / 3600, 2),
                "launchCount": int(launch_count or 0),
                "appsUsed": int(apps_used or 0),
                "devicesUsed": int(devices_used or 0),
            })

        # Per-device rollup across the selected app scope. Each device contributes
        # one row carrying its inventory dimensions (location/catalog/usage/area/
        # fleet) so the frontend can compute Hours-by-X widgets that match the
        # single-app view. Each device's hours flow once into its dimension
        # bucket regardless of how many of the selected apps it touched.
        device_agg_query = f"""
            SELECT
                uh.device_id                                                    AS serial_number,
                COALESCE(inv.data->>'device_name', inv.data->>'deviceName',
                         inv.data->>'computer_name', inv.data->>'computerName',
                         uh.device_id)                                          AS device_name,
                inv.data->>'usage'                                              AS usage,
                inv.data->>'catalog'                                            AS catalog,
                inv.data->>'location'                                           AS location,
                inv.data->>'department'                                         AS department,
                inv.data->>'fleet'                                              AS fleet,
                SUM(uh.total_seconds)::double precision                         AS total_seconds,
                SUM(uh.launches)::bigint                                        AS launch_count
            FROM usage_history uh
            JOIN devices d ON d.serial_number = uh.device_id
            LEFT JOIN inventory inv ON inv.device_id = d.id
            WHERE {where_clause}
            GROUP BY uh.device_id, inv.data
            ORDER BY total_seconds DESC
        """
        cursor.execute(device_agg_query, tuple(params))
        devices_aggregate: List[Dict[str, Any]] = []
        for (d_serial, d_name, d_usage, d_catalog, d_location,
             d_department, d_fleet, d_total_secs, d_launches) in cursor.fetchall():
            d_total_secs = float(d_total_secs or 0)
            devices_aggregate.append({
                "serialNumber": d_serial,
                "deviceName": d_name,
                "usage": d_usage,
                "catalog": d_catalog,
                "location": d_location,
                # Alias for callers that bucket by the global area/room dims
                # — consistent with the bulk applications endpoint and frontend
                # filter wiring that uses `area` interchangeably with
                # `department` and `room` interchangeably with `location`.
                "room": d_location,
                "department": d_department,
                "area": d_department,
                "fleet": d_fleet,
                "totalSeconds": d_total_secs,
                "totalHours": round(d_total_secs / 3600, 2),
                "launchCount": int(d_launches or 0),
            })

        # Narrow devicesAggregate to the devices behind the apps actually in
        # the `applications` list — covers both explicit-pick mode and the
        # fleet-wide case where minHours/minLaunches dropped some apps. The
        # device count badge on the Widgets accordion now matches the row
        # count behind the data table.
        if app_name_list or minHours is not None or minLaunches is not None:
            devices_aggregate = [
                d for d in devices_aggregate
                if d["serialNumber"] in kept_device_set
            ]

        conn.close()
        conn = None

        single_user_apps.sort(key=lambda x: x["totalHours"], reverse=True)

        summary = {
            "totalAppsTracked": len(applications),
            "totalActiveHours": round(total_active_seconds_sum / 3600, 2),
            "totalUsageHours": round(total_seconds_sum / 3600, 2),
            "totalLaunches": total_launches_sum,
            "uniqueUsers": len(all_users),
            "uniqueDevices": len(all_devices),
            "singleUserAppCount": len(single_user_apps),
            "unusedAppCount": 0,
            # How many applications drew no active use at all in the window.
            # Overwhelmingly background services, which is why a report headed
            # by total hours reads as though the fleet's busiest software is a
            # set of daemons nobody has opened.
            "noActiveUseAppCount": sum(1 for a in applications if not a["activeSeconds"]),
        }

        result = {
            "status": "ok",
            "applications": applications,
            "topUsers": top_users,
            "singleUserApps": single_user_apps,
            "unusedApps": [],
            "devicesAggregate": devices_aggregate,
            "summary": summary,
            "filters": {
                "days": days,
                "applicationNames": app_name_list,
                "usages": usage_list,
                "catalogs": catalog_list,
                "locations": location_list,
                "minHours": minHours,
                "minLaunches": minLaunches,
            },
            "lastUpdated": datetime.now(timezone.utc).isoformat(),
        }

        cache_set("applications_usage", result, _ckey)
        logger.info(
            f"[PERF] /api/devices/applications/usage: {_time.monotonic()-_t0:.3f}s "
            f"({len(applications)} apps, {len(top_users)} users, days={days})"
        )
        return result

    except Exception as e:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        logger.error(f"Failed to get fleet applications usage: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve fleet usage: {str(e)}")


@router.get("/applications/usage/by-device", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_application_usage_by_device(
    request: Request,
    app: str = Query(..., description="Application name pattern (substring, case-insensitive)"),
    days: int = Query(default=30, ge=1, le=548, description="Lookback window in days"),
    usages: Optional[str] = Query(default=None, description="Comma-separated inventory usages"),
    catalogs: Optional[str] = Query(default=None, description="Comma-separated inventory catalogs"),
    locations: Optional[str] = Query(default=None, description="Comma-separated inventory locations"),
    include_archived: bool = Query(default=False, alias="includeArchived"),
):
    """
    Per-device usage breakdown for one application (substring match on name).

    Returns one row per device that contributed usage of any app matching the
    given name pattern within the lookback window. Backs the drill-down view
    from the fleet usage report.
    """
    conn = None
    try:
        _ckey = (str(dict(sorted(request.query_params.items()))),)
        _cached = cache_get("applications_usage_by_device", _ckey)
        if _cached is not None:
            return _cached

        _t0 = _time.monotonic()

        usage_list = [s.strip() for s in usages.split(',')] if usages else []
        catalog_list = [s.strip() for s in catalogs.split(',')] if catalogs else []
        location_list = [s.strip() for s in locations.split(',')] if locations else []

        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days)).date()

        conn = get_db_connection()
        cursor = conn.cursor()

        # Match the same set of rows the fleet report rolled into this name.
        #
        # This used to be an exact match on app_name, to stop a substring
        # drill-down on "Motion" silently including MotionBuilder. It did stop
        # that, but it also returned NOTHING for every app whose report row is
        # a canonical alias bucket: no usage_history row is literally named
        # "Houdini" -- they are "Houdini 21.0.440", "Houdini Launcher", and so
        # on -- so the drill-down behind such a row was always empty.
        #
        # Resolving through canonicalize_app_name() keeps the guarantee that
        # made exact-match attractive (Motion and MotionBuilder canonicalize
        # differently, so they still cannot mix) while making the drill-down
        # show the rows the report actually counted. Passing a raw variant
        # name still works: it resolves to its own bucket.
        target_canonical = (canonicalize_app_name(app) or app).lower()

        cursor.execute(
            "SELECT DISTINCT app_name FROM usage_history WHERE date >= %s AND app_name IS NOT NULL",
            (cutoff_date,),
        )
        member_names = sorted({
            name.lower()
            for (name,) in cursor.fetchall()
            if name
            and (
                name.lower() == app.lower()
                or (canonicalize_app_name(name) or name).lower() == target_canonical
            )
        })

        # An unknown name matches nothing rather than everything.
        if not member_names:
            member_names = [app.lower()]

        where = [
            "uh.date >= %s",
            "LOWER(uh.app_name) = ANY(%s)",
            "d.serial_number IS NOT NULL",
            "d.serial_number NOT LIKE 'TEST-%%'",
            "d.serial_number != 'localhost'",
        ]
        params: List[Any] = [cutoff_date, member_names]

        if not include_archived:
            where.append("d.archived = FALSE")
        if usage_list:
            where.append("LOWER(inv.data->>'usage') = ANY(%s)")
            params.append([s.lower() for s in usage_list])
        if catalog_list:
            where.append("LOWER(inv.data->>'catalog') = ANY(%s)")
            params.append([s.lower() for s in catalog_list])
        if location_list:
            where.append("LOWER(inv.data->>'location') = ANY(%s)")
            params.append([s.lower() for s in location_list])

        where_clause = " AND ".join(where)

        device_query = f"""
            SELECT
                uh.device_id                                                    AS serial_number,
                COALESCE(inv.data->>'device_name', inv.data->>'deviceName',
                         inv.data->>'computer_name', inv.data->>'computerName',
                         uh.device_id)                                          AS device_name,
                inv.data->>'usage'                                              AS usage,
                inv.data->>'catalog'                                            AS catalog,
                inv.data->>'location'                                           AS location,
                inv.data->>'department'                                         AS department,
                inv.data->>'fleet'                                              AS fleet,
                COALESCE(inv.data->>'asset_tag', inv.data->>'assetTag')         AS asset_tag,
                SUM(uh.launches)::bigint                                        AS launch_count,
                SUM(uh.total_seconds)::double precision                         AS total_seconds,
                COUNT(DISTINCT uh.app_name)::int                                AS app_variant_count,
                ARRAY_AGG(DISTINCT uh.app_name)                                 AS app_variants,
                MIN(uh.date)::text                                              AS first_used,
                MAX(uh.date)::text                                              AS last_used
            FROM usage_history uh
            JOIN devices d ON d.serial_number = uh.device_id
            LEFT JOIN inventory inv ON inv.device_id = d.id
            WHERE {where_clause}
            GROUP BY uh.device_id, inv.data
            ORDER BY total_seconds DESC
        """
        cursor.execute(device_query, tuple(params))
        device_rows = cursor.fetchall()

        # Per-device user lists via a single unnest pass.
        users_query = f"""
            SELECT uh.device_id, ARRAY_AGG(DISTINCT u) AS users
            FROM usage_history uh
            JOIN devices d ON d.serial_number = uh.device_id
            LEFT JOIN inventory inv ON inv.device_id = d.id
            CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(uh.users, '[]'::jsonb)) AS u
            WHERE {where_clause}
              AND u IS NOT NULL AND u <> ''
            GROUP BY uh.device_id
        """
        cursor.execute(users_query, tuple(params))
        users_by_device: Dict[str, List[str]] = {
            row[0]: list(row[1] or []) for row in cursor.fetchall()
        }

        conn.close()
        conn = None

        devices_out: List[Dict[str, Any]] = []
        total_seconds_sum = 0.0
        total_launches_sum = 0
        all_users: set = set()

        for (serial, device_name, usage, catalog, location, department, fleet, asset_tag,
             launch_count, total_secs, _variant_count, variants,
             first_used, last_used) in device_rows:
            total_secs = float(total_secs or 0)
            launch_count = int(launch_count or 0)
            users = [u for u in users_by_device.get(serial, []) if is_human_principal(u)]
            raw_variants = [v for v in (variants or []) if v]
            # Collapse "Houdini 21.0.440" + "Houdini 22.0.368" + "hindie.exe"
            # to a single canonical entry per device. "Houdini Launcher" is a
            # separate product and keeps its own entry.
            canonical_variants = sorted({canonicalize_app_name(v) or v for v in raw_variants})
            total_seconds_sum += total_secs
            total_launches_sum += launch_count
            all_users.update(users)
            devices_out.append({
                "serialNumber": serial,
                "deviceName": device_name,
                "usage": usage,
                "catalog": catalog,
                "location": location,
                "room": location,
                "department": department,
                # Mirror of department, matching the alias the other fleet
                # endpoints use so consumers don't need endpoint-specific casing.
                "area": department,
                "fleet": fleet,
                "assetTag": asset_tag,
                "totalSeconds": total_secs,
                "totalHours": round(total_secs / 3600, 2),
                "launchCount": launch_count,
                "userCount": len(users),
                "users": users,
                "appVariants": canonical_variants,
                "appVariantCount": len(canonical_variants),
                "rawAppVariants": sorted(raw_variants),
                "firstUsed": first_used,
                "lastUsed": last_used,
            })

        result = {
            "status": "ok",
            "appPattern": app,
            "days": days,
            "devices": devices_out,
            "summary": {
                "deviceCount": len(devices_out),
                "totalUsageHours": round(total_seconds_sum / 3600, 2),
                "totalLaunches": total_launches_sum,
                "uniqueUsers": len(all_users),
            },
            "filters": {
                "usages": usage_list,
                "catalogs": catalog_list,
                "locations": location_list,
            },
            "lastUpdated": datetime.now(timezone.utc).isoformat(),
        }

        cache_set("applications_usage_by_device", result, _ckey)
        logger.info(
            f"[PERF] /api/devices/applications/usage/by-device: {_time.monotonic()-_t0:.3f}s "
            f"(app={app!r}, {len(devices_out)} devices, days={days})"
        )
        return result

    except Exception as e:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        logger.error(f"Failed to get per-device usage for app={app!r}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve per-device usage: {str(e)}")


@router.get("/applications/collection-health", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_applications_collection_health(
    request: Request,
    freshDays: int = Query(default=7, ge=1, le=90, description="Days within which a device is considered healthy"),
    staleDays: int = Query(default=30, ge=1, le=180, description="Days beyond which a device is considered dark"),
    include_archived: bool = Query(default=False, alias="includeArchived"),
):
    """
    Per-device application-usage collection health.

    Infers coverage from `usage_history` activity without requiring client
    audit-state telemetry. Each non-archived device is bucketed into:
      - healthy: usage_history row dated within freshDays
      - stale:   usage_history row dated within staleDays but older than freshDays
      - dark:    has usage_history rows but most recent is older than staleDays
      - never:   no usage_history rows ever

    Use to spot devices that are silently not collecting (audit policy off
    on Windows, watcher daemon missing on Mac, etc.) — they appear in the
    `dark` or `never` buckets.
    """
    conn = None
    try:
        _ckey = (freshDays, staleDays, include_archived)
        _cached = cache_get("applications_collection_health", _ckey)
        if _cached is not None:
            return _cached

        _t0 = _time.monotonic()

        conn = get_db_connection()
        cursor = conn.cursor()

        archived_clause = "" if include_archived else " AND d.archived = FALSE"

        # One pass: aggregate usage_history per device, LEFT JOIN with devices
        # so "never" devices appear. Bucket logic happens in Python so we can
        # tweak thresholds without touching SQL.
        cursor.execute(f"""
            WITH usage_summary AS (
                SELECT
                    device_id,
                    MAX(date)::text       AS last_usage_date,
                    SUM(total_seconds)    AS total_seconds_all,
                    COUNT(*)::int         AS row_count
                FROM usage_history
                GROUP BY device_id
            )
            SELECT
                d.serial_number,
                COALESCE(inv.data->>'device_name', inv.data->>'deviceName',
                         inv.data->>'computer_name', inv.data->>'computerName',
                         d.name, d.serial_number)               AS device_name,
                d.platform                                       AS platform,
                d.os_name                                        AS os_name,
                d.last_seen::text                                AS last_seen,
                inv.data->>'usage'                               AS inventory_usage,
                inv.data->>'catalog'                             AS catalog,
                inv.data->>'location'                            AS location,
                us.last_usage_date,
                COALESCE(us.row_count, 0)                        AS row_count,
                COALESCE(us.total_seconds_all, 0)::double precision AS total_seconds_all
            FROM devices d
            LEFT JOIN usage_summary us ON us.device_id = d.serial_number
            LEFT JOIN inventory inv    ON inv.device_id = d.id
            WHERE d.serial_number IS NOT NULL
              AND d.serial_number NOT LIKE 'TEST-%%'
              AND d.serial_number != 'localhost'
              {archived_clause}
        """)
        rows = cursor.fetchall()

        conn.close()
        conn = None

        today = datetime.now(timezone.utc).date()
        fresh_cutoff = today - timedelta(days=freshDays)
        stale_cutoff = today - timedelta(days=staleDays)

        bucket_counts = {"healthy": 0, "stale": 0, "dark": 0, "never": 0}
        bucket_counts_by_platform: Dict[str, Dict[str, int]] = {}
        dark_devices: List[Dict[str, Any]] = []

        for (serial, device_name, platform, os_name, last_seen,
             inv_usage, catalog, location, last_usage_date,
             row_count, total_secs) in rows:

            # Normalize platform label for grouping.
            plat = infer_platform(platform or os_name) or (platform or 'Unknown')

            if last_usage_date is None:
                bucket = "never"
                days_since = None
            else:
                try:
                    last_date = datetime.strptime(last_usage_date, "%Y-%m-%d").date()
                    days_since = (today - last_date).days
                except (ValueError, TypeError):
                    last_date = None
                    days_since = None

                if last_date is None:
                    bucket = "never"
                elif last_date >= fresh_cutoff:
                    bucket = "healthy"
                elif last_date >= stale_cutoff:
                    bucket = "stale"
                else:
                    bucket = "dark"

            bucket_counts[bucket] += 1
            plat_counts = bucket_counts_by_platform.setdefault(
                plat, {"healthy": 0, "stale": 0, "dark": 0, "never": 0, "total": 0}
            )
            plat_counts[bucket] += 1
            plat_counts["total"] += 1

            if bucket in ("dark", "never"):
                dark_devices.append({
                    "serialNumber": serial,
                    "deviceName": device_name,
                    "platform": plat,
                    "osName": os_name,
                    "lastSeen": last_seen,
                    "usage": inv_usage,
                    "catalog": catalog,
                    "location": location,
                    "lastUsageDate": last_usage_date,
                    "daysSinceUsage": days_since,
                    "totalHoursEver": round(float(total_secs or 0) / 3600, 2),
                    "rowCount": int(row_count),
                    "bucket": bucket,
                })

        # Sort dark/never devices: never first (most concerning), then
        # by daysSinceUsage descending (longest-gone first).
        dark_devices.sort(
            key=lambda d: (0 if d["bucket"] == "never" else 1, -(d["daysSinceUsage"] or 0))
        )

        total = sum(bucket_counts.values())
        result = {
            "status": "ok",
            "summary": {
                "totalDevices": total,
                **bucket_counts,
                "freshDays": freshDays,
                "staleDays": staleDays,
            },
            "byPlatform": bucket_counts_by_platform,
            "darkDevices": dark_devices,
            "lastUpdated": datetime.now(timezone.utc).isoformat(),
        }

        cache_set("applications_collection_health", result, _ckey)
        logger.info(
            f"[PERF] /api/devices/applications/collection-health: {_time.monotonic()-_t0:.3f}s "
            f"({total} devices, {bucket_counts['dark']} dark, {bucket_counts['never']} never)"
        )
        return result

    except Exception as e:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        logger.error(f"Failed to get collection health: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve collection health: {str(e)}")


@router.get("/applications/distribution", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_applications_distribution(
    request: Request,
    applicationNames: str = Query(..., description="Comma-separated app names to aggregate (required)"),
    usages: Optional[str] = Query(default=None, description="Comma-separated inventory usages"),
    catalogs: Optional[str] = Query(default=None, description="Comma-separated inventory catalogs"),
    areas: Optional[str] = Query(default=None, description="Comma-separated inventory areas (department)"),
    fleets: Optional[str] = Query(default=None, description="Comma-separated inventory fleets"),
    rooms: Optional[str] = Query(default=None, description="Comma-separated inventory rooms"),
    locations: Optional[str] = Query(default=None, description="Comma-separated inventory locations"),
    platforms: Optional[str] = Query(default=None, description="Comma-separated platforms (windows/macos)"),
    include_archived: bool = Query(default=False, alias="includeArchived"),
):
    """
    Server-side version distribution for selected applications.

    Aggregates installed-app counts per (app bucket, version) directly in SQL
    so the response size is bounded by `distinct versions`, not fleet size.
    Each requested app name acts as a case-insensitive substring bucket,
    mirroring the matching used by the bulk applications endpoint, so chips
    selected in the filter UI map 1:1 to chart cards.

    A device is counted at most once per (bucket, version) — duplicate app
    entries on a single device (32/64-bit, MSI + Squirrel installers) collapse
    into one tally so the chart matches "devices with vX" rather than
    "installer rows for vX".

    Returns:
        {
          "<requested app name>": {
            "totalDevices": <int>,            # devices with at least one matching install
            "versions": { "<version>": <int>, ... }
          },
          ...
        }
    """
    conn = None
    try:
        _ckey = (str(dict(sorted(request.query_params.items()))),)
        _cached = cache_get("applications_distribution", _ckey)
        if _cached is not None:
            return _cached
        _t0 = _time.monotonic()

        # Dedupe app names case-insensitively while preserving first-seen casing
        # for the response keys. Two buckets that differ only in case would
        # otherwise produce two SQL rows but overwrite each other in the
        # response dict, silently dropping one bucket's counts.
        raw_names = [s.strip() for s in applicationNames.split(',') if s.strip()]
        if not raw_names:
            raise HTTPException(status_code=400, detail="applicationNames must contain at least one non-empty value")
        app_name_list: List[str] = []
        _seen_lower: set = set()
        for name in raw_names:
            key = name.lower()
            if key in _seen_lower:
                continue
            _seen_lower.add(key)
            app_name_list.append(name)

        usage_list = [s.strip() for s in usages.split(',')] if usages else []
        catalog_list = [s.strip() for s in catalogs.split(',')] if catalogs else []
        area_list = [s.strip() for s in areas.split(',')] if areas else []
        fleet_list = [s.strip() for s in fleets.split(',')] if fleets else []
        room_list = [s.strip() for s in rooms.split(',')] if rooms else []
        location_list = [s.strip() for s in locations.split(',')] if locations else []
        platform_list = [s.strip().lower() for s in platforms.split(',')] if platforms else []

        logger.info(f"Fetching applications distribution (apps={len(app_name_list)}, filters={dict(request.query_params)})")

        where_conditions = [
            "d.serial_number IS NOT NULL",
            "d.serial_number NOT LIKE 'TEST-%'",
            "d.serial_number != 'localhost'",
            "a.data IS NOT NULL",
        ]
        if not include_archived:
            where_conditions.append("d.archived = FALSE")

        query_params: List[Any] = []

        if usage_list:
            where_conditions.append("LOWER(inv.data->>'usage') = ANY(%s)")
            query_params.append([s.lower() for s in usage_list])
        if catalog_list:
            where_conditions.append("LOWER(inv.data->>'catalog') = ANY(%s)")
            query_params.append([s.lower() for s in catalog_list])
        if area_list:
            where_conditions.append("LOWER(inv.data->>'department') = ANY(%s)")
            query_params.append([s.lower() for s in area_list])
        if fleet_list:
            where_conditions.append("LOWER(inv.data->>'fleet') = ANY(%s)")
            query_params.append([s.lower() for s in fleet_list])
        if room_list:
            where_conditions.append("LOWER(COALESCE(inv.data->>'location', inv.data->>'room')) = ANY(%s)")
            query_params.append([s.lower() for s in room_list])
        if location_list:
            where_conditions.append("LOWER(inv.data->>'location') = ANY(%s)")
            query_params.append([s.lower() for s in location_list])

        if platform_list:
            def _expand_platform(p: str) -> list[str]:
                p = p.strip().lower()
                if p in ('mac', 'macos', 'darwin'):
                    return ['%macos%', '%darwin%', '%os x%']
                if p in ('win', 'windows'):
                    return ['%windows%']
                return [f'%{p}%']
            patterns: list[str] = []
            for p in platform_list:
                patterns.extend(_expand_platform(p))
            where_conditions.append("LOWER(COALESCE(sys.data->'operatingSystem'->>'name', d.platform, '')) ILIKE ANY(%s)")
            query_params.append(patterns)

        # One bucket per requested app name; each device's apps are matched
        # against every bucket so a device with both Chrome and Edge counts
        # once in each. Lowercased for case-insensitive LIKE matching.
        bucket_patterns = [name.lower() for name in app_name_list]
        bucket_originals = list(app_name_list)  # preserve user-provided casing for response keys

        where_clause = ' AND '.join(where_conditions)

        # DISTINCT collapses duplicate installer rows so a device with two
        # Chrome entries at the same version contributes 1, not 2.
        #
        # strpos() rather than LIKE: LIKE would treat `%` / `_` in user-supplied
        # bucket patterns as wildcards, diverging from the bulk endpoint's
        # Python `in`-style substring check and turning `applicationNames=%`
        # into a fleet-wide match. strpos() always compares literals.
        #
        # NULLIF(BTRIM(...), '') normalizes empty/whitespace version strings
        # to NULL so they collapse into the 'Unknown' bucket here rather than
        # producing a separate '' group that would silently overwrite the
        # 'Unknown' count in the Python aggregation below.
        query = f"""
        WITH device_base AS (
            SELECT DISTINCT ON (d.serial_number)
                d.id AS device_pk,
                CASE
                    WHEN a.data ? 'installedApplications' THEN a.data->'installedApplications'
                    WHEN a.data ? 'InstalledApplications' THEN a.data->'InstalledApplications'
                    WHEN a.data ? 'installed_applications' THEN a.data->'installed_applications'
                    WHEN jsonb_typeof(a.data) = 'array' THEN a.data
                    ELSE '[]'::jsonb
                END AS apps_array
            FROM devices d
            JOIN applications a ON d.id = a.device_id
            LEFT JOIN inventory inv ON d.id = inv.device_id
            LEFT JOIN system sys ON d.id = sys.device_id
            WHERE {where_clause}
            ORDER BY d.serial_number, a.updated_at DESC
        ),
        matched AS (
            SELECT DISTINCT
                db.device_pk,
                bucket.idx AS bucket_idx,
                COALESCE(
                    NULLIF(BTRIM(elem->>'version'), ''),
                    NULLIF(BTRIM(elem->>'bundle_version'), ''),
                    'Unknown'
                ) AS version
            FROM device_base db
            CROSS JOIN LATERAL jsonb_array_elements(db.apps_array) AS elem
            CROSS JOIN LATERAL unnest(%s::text[]) WITH ORDINALITY AS bucket(pattern, idx)
            WHERE strpos(LOWER(COALESCE(elem->>'name', elem->>'displayName', '')), bucket.pattern) > 0
        ),
        version_counts AS (
            SELECT bucket_idx, version, COUNT(*) AS device_count
            FROM matched
            GROUP BY bucket_idx, version
        ),
        bucket_totals AS (
            SELECT bucket_idx, COUNT(DISTINCT device_pk) AS device_count
            FROM matched
            GROUP BY bucket_idx
        )
        SELECT 'v' AS kind, bucket_idx, version, device_count FROM version_counts
        UNION ALL
        SELECT 't' AS kind, bucket_idx, NULL AS version, device_count FROM bucket_totals
        """
        query_params.append(bucket_patterns)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query, tuple(query_params))
        rows = cursor.fetchall()
        conn.close()
        conn = None

        result: Dict[str, Dict[str, Any]] = {}
        for name in bucket_originals:
            result[name] = {"totalDevices": 0, "versions": {}}

        for kind, bucket_idx, version, device_count in rows:
            # bucket_idx is 1-based from WITH ORDINALITY
            key = bucket_originals[bucket_idx - 1]
            if kind == 'v':
                result[key]["versions"][version or "Unknown"] = int(device_count)
            else:
                result[key]["totalDevices"] = int(device_count)

        cache_set("applications_distribution", result, _ckey)
        logger.info(
            f"[PERF] /api/devices/applications/distribution: {_time.monotonic()-_t0:.3f}s "
            f"({sum(b['totalDevices'] for b in result.values())} device matches across {len(result)} buckets)"
        )
        return result

    except HTTPException:
        raise
    except Exception as e:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        logger.error(f"Failed to get applications distribution: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve applications distribution: {str(e)}")


@router.get("/applications", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_bulk_applications(
    request: Request,
    deviceNames: Optional[str] = None,
    applicationNames: Optional[str] = None,
    publishers: Optional[str] = None,
    categories: Optional[str] = None,
    versions: Optional[str] = None,
    search: Optional[str] = None,
    installDateFrom: Optional[str] = None,
    installDateTo: Optional[str] = None,
    sizeMin: Optional[int] = None,
    sizeMax: Optional[int] = None,
    usages: Optional[str] = Query(default=None, description="Comma-separated inventory usages"),
    catalogs: Optional[str] = Query(default=None, description="Comma-separated inventory catalogs"),
    areas: Optional[str] = Query(default=None, description="Comma-separated inventory areas (department)"),
    fleets: Optional[str] = Query(default=None, description="Comma-separated inventory fleets"),
    rooms: Optional[str] = Query(default=None, description="Comma-separated inventory rooms"),
    locations: Optional[str] = Query(default=None, description="Comma-separated inventory locations"),
    platforms: Optional[str] = Query(default=None, description="Comma-separated platforms (windows/macos)"),
    loadAll: bool = False,
    include_archived: bool = Query(default=False, alias="includeArchived"),
    limit: int = Query(default=500, ge=1, le=5000, description="Maximum items to return (default 500, max 5000)"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    deviceLimit: int = Query(default=2000, ge=1, le=5000, description="Maximum devices to scan (default 2000)"),
):
    """
    Bulk applications endpoint with filtering support.
    
    Returns flattened list of applications across all devices with filtering.
    Frontend is responsible for search/filtering logic - this is just data retrieval.
    
    By default, archived devices are excluded. Use includeArchived=true to include them.
    """
    conn = None
    try:
        _ckey = (str(dict(sorted(request.query_params.items()))),)
        _cached = cache_get("applications", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info(f"Fetching bulk applications (loadAll={loadAll}, includeArchived={include_archived}, filters={dict(request.query_params)})")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Parse comma-separated filter values
        device_name_list = deviceNames.split(',') if deviceNames else []
        app_name_list = applicationNames.split(',') if applicationNames else []
        publisher_list = publishers.split(',') if publishers else []
        category_list = categories.split(',') if categories else []
        version_list = versions.split(',') if versions else []
        usage_list = [s.strip() for s in usages.split(',')] if usages else []
        catalog_list = [s.strip() for s in catalogs.split(',')] if catalogs else []
        area_list = [s.strip() for s in areas.split(',')] if areas else []
        fleet_list = [s.strip() for s in fleets.split(',')] if fleets else []
        room_list = [s.strip() for s in rooms.split(',')] if rooms else []
        location_list = [s.strip() for s in locations.split(',')] if locations else []
        platform_list = [s.strip().lower() for s in platforms.split(',')] if platforms else []

        # Build WHERE clause for device filtering (including archive filter)
        where_conditions = [
            "d.serial_number IS NOT NULL",
            "d.serial_number NOT LIKE 'TEST-%'",
            "d.serial_number != 'localhost'"
        ]

        # Add archive filter
        if not include_archived:
            where_conditions.append("d.archived = FALSE")

        query_params: List[Any] = []

        if device_name_list:
            # Use %s placeholders to match the rest of this query — the new
            # inventory-dimension filters below also use %s, and mixing
            # paramstyles in a single SQL string can fail binding in pg8000.
            placeholders = ', '.join(['%s'] * len(device_name_list))
            where_conditions.append(
                f"(COALESCE(inv.data->>'device_name', inv.data->>'deviceName') IN ({placeholders}) "
                f"OR COALESCE(inv.data->>'computer_name', inv.data->>'computerName') IN ({placeholders}) "
                f"OR d.serial_number IN ({placeholders}))"
            )
            query_params.extend(device_name_list * 3)

        if usage_list:
            where_conditions.append("LOWER(inv.data->>'usage') = ANY(%s)")
            query_params.append([s.lower() for s in usage_list])

        if catalog_list:
            where_conditions.append("LOWER(inv.data->>'catalog') = ANY(%s)")
            query_params.append([s.lower() for s in catalog_list])

        if area_list:
            where_conditions.append("LOWER(inv.data->>'department') = ANY(%s)")
            query_params.append([s.lower() for s in area_list])

        if fleet_list:
            where_conditions.append("LOWER(inv.data->>'fleet') = ANY(%s)")
            query_params.append([s.lower() for s in fleet_list])

        if room_list:
            # Filter-options endpoint exposes "rooms" populated from
            # inv.data->>'location' so match the same field with 'room' as a
            # fallback for clients that send both keys.
            where_conditions.append("LOWER(COALESCE(inv.data->>'location', inv.data->>'room')) = ANY(%s)")
            query_params.append([s.lower() for s in room_list])

        if location_list:
            where_conditions.append("LOWER(inv.data->>'location') = ANY(%s)")
            query_params.append([s.lower() for s in location_list])

        if platform_list:
            def _expand_platform2(p: str) -> list[str]:
                p = p.strip().lower()
                if p in ('mac', 'macos', 'darwin'):
                    return ['%macos%', '%darwin%', '%os x%']
                if p in ('win', 'windows'):
                    return ['%windows%']
                return [f'%{p}%']
            patterns2: list[str] = []
            for p in platform_list:
                patterns2.extend(_expand_platform2(p))
            where_conditions.append("LOWER(COALESCE(sys.data->'operatingSystem'->>'name', d.platform, '')) ILIKE ANY(%s)")
            query_params.append(patterns2)

        where_clause = ' AND '.join(where_conditions)
        
        # Query to get all devices with applications data.
        # deviceLimit is validated by pydantic (1..5000) so safe to interpolate directly.
        query = f"""
        SELECT DISTINCT ON (d.serial_number)
            d.serial_number,
            d.device_id,
            d.last_seen,
            a.data as applications_data,
            a.collected_at,
            COALESCE(inv.data->>'device_name', inv.data->>'deviceName') as device_name,
            COALESCE(inv.data->>'computer_name', inv.data->>'computerName') as computer_name,
            inv.data->>'usage' as usage,
            inv.data->>'catalog' as catalog,
            inv.data->>'location' as location,
            COALESCE(inv.data->>'asset_tag', inv.data->>'assetTag') as asset_tag,
            COALESCE(sys.data->'operatingSystem'->>'name', d.platform) as platform,
            inv.data->>'department' as department,
            inv.data->>'fleet' as fleet,
            -- Filter-options endpoint exposes "rooms" populated from
            -- inv.data->>'location'; mirror that here so client-side room
            -- filtering on these rows matches the same set of devices.
            COALESCE(inv.data->>'location', inv.data->>'room') as room
        FROM devices d
        LEFT JOIN applications a ON d.id = a.device_id
        LEFT JOIN inventory inv ON d.id = inv.device_id
        LEFT JOIN system sys ON d.id = sys.device_id
        WHERE {where_clause}
            AND a.data IS NOT NULL
        ORDER BY d.serial_number, a.updated_at DESC
        LIMIT {int(deviceLimit)}
        """
        
        cursor.execute(query, tuple(query_params))
        rows = cursor.fetchall()
        conn.close()
        conn = None
        
        logger.info(f"Retrieved {len(rows)} devices with applications data")
        
        # Build per-device app lists first, then round-robin flatten. This matters
        # because the SQL orders by serial_number, and a single device with many apps
        # (e.g. a dev laptop with 1000+ entries) would otherwise consume the entire
        # default page and hide every other device's apps from the first response.
        per_device_apps: list[list[dict]] = []

        for row in rows:
            try:
                serial_number, device_uuid, last_seen, apps_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag, platform, department, fleet, room = row

                device_display_name = device_name or computer_name or serial_number

                if not apps_data:
                    continue

                installed_apps = []
                if isinstance(apps_data, dict):
                    installed_apps = apps_data.get('installedApplications') or apps_data.get('InstalledApplications') or apps_data.get('installed_applications') or []
                elif isinstance(apps_data, list):
                    installed_apps = apps_data

                last_seen_iso = last_seen.isoformat() if last_seen else None
                collected_at_iso = collected_at.isoformat() if collected_at else None

                device_bucket: list[dict] = []
                for idx, app in enumerate(installed_apps):
                    app_name = app.get('name') or app.get('displayName') or 'Unknown Application'
                    app_publisher = app.get('publisher') or app.get('signed_by') or app.get('vendor') or 'Unknown'
                    app_category = app.get('category', 'Other')
                    app_version = app.get('version') or app.get('bundle_version') or 'Unknown'
                    app_size = app.get('size') or app.get('estimatedSize')
                    app_install_date = app.get('installDate') or app.get('install_date') or app.get('last_modified')

                    if app_name_list and not any(name.lower() in app_name.lower() for name in app_name_list):
                        continue
                    if publisher_list and not any(pub.lower() in app_publisher.lower() for pub in publisher_list):
                        continue
                    if category_list and app_category not in category_list:
                        continue
                    if version_list and app_version not in version_list:
                        continue
                    if search and search.lower() not in app_name.lower():
                        continue
                    if sizeMin and app_size and app_size < sizeMin:
                        continue
                    if sizeMax and app_size and app_size > sizeMax:
                        continue

                    device_bucket.append({
                        'id': f"{device_uuid}_{idx}",
                        'deviceId': device_uuid,
                        'deviceName': device_display_name,
                        'serialNumber': serial_number,
                        'lastSeen': last_seen_iso,
                        'collectedAt': collected_at_iso,
                        'name': app_name,
                        'version': app_version,
                        'vendor': app_publisher,
                        'publisher': app_publisher,
                        'category': app_category,
                        'installDate': app_install_date,
                        'size': app_size,
                        'path': app.get('path') or app.get('install_location'),
                        'architecture': app.get('architecture', 'Unknown'),
                        'bundleId': app.get('bundleId') or app.get('bundle_id'),
                        'usage': usage,
                        'catalog': catalog,
                        'location': location,
                        'room': room,
                        'department': department,
                        'area': department,
                        'fleet': fleet,
                        'assetTag': asset_tag,
                        'platform': platform
                    })

                if device_bucket:
                    per_device_apps.append(device_bucket)

            except Exception as e:
                logger.warning(f"Error processing applications for device {row[0]}: {e}")
                continue

        # Round-robin flatten so the first `limit` items sample every device at
        # least once before returning a second app from the busiest device.
        all_applications: list[dict] = []
        if per_device_apps:
            max_len = max(len(bucket) for bucket in per_device_apps)
            for i in range(max_len):
                for bucket in per_device_apps:
                    if i < len(bucket):
                        all_applications.append(bucket[i])
        
        logger.info(f"Processed {len(all_applications)} applications from {len(rows)} devices")
        cache_set("applications", all_applications, _ckey)
        logger.info(f"[PERF] /api/devices/applications: {_time.monotonic()-_t0:.3f}s ({len(all_applications)} apps)")
        return paginate(all_applications, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk applications: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk applications: {str(e)}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

# Campus resolvers. A device that answers one of these on its last check-in was on
# the campus network at that moment.
CAMPUS_DNS_SERVERS = ('10.3.0.11', '172.16.20.10')

# Campus /16s. Used only as a fallback for devices whose client did not report DNS,
# so a missing DNS payload does not silently read as "off campus".
CAMPUS_IP_PREFIXES = tuple(f'10.{octet}.' for octet in range(14, 24)) + ('10.100.',)


def _has_campus_dns(dns_servers) -> bool:
    """Is the device resolving against campus DNS?

    True on the campus LAN, but equally true over VPN from anywhere in the world, so
    this answers "reachable on the campus network", not "physically on campus".
    """
    if not dns_servers:
        return False
    servers = dns_servers if isinstance(dns_servers, list) else [dns_servers]
    return any(str(s) in CAMPUS_DNS_SERVERS for s in servers)


def _is_on_campus(active_ip, dns_servers) -> bool:
    """Was this device physically on the campus network at its last check-in?

    Deliberately keyed on the campus address range alone. Campus DNS looks like the
    stronger signal and is not: a VPN client resolves campus DNS from a living room,
    so a DNS-based test reports home machines as on campus. Anything keyed on that
    would attach personally-owned peripherals to institutional inventory.

    dns_servers is still accepted so callers can tell the two states apart via
    _has_campus_dns - campus DNS with an off-campus address is the VPN case, worth
    surfacing rather than silently discarding.

    Point-in-time by necessity - module rows are upserted per device, so there is no
    history to ask "was it ever on campus".
    """
    return bool(active_ip) and str(active_ip).startswith(CAMPUS_IP_PREFIXES)


@router.get("/hardware", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_bulk_hardware(
    request: Request,
    response: Response,
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk hardware endpoint.
    
    Returns flattened list of hardware details across all devices.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers (serial number, device ID, name)
    - Hardware specs (manufacturer, model, CPU, memory, storage, GPU)
    - OS information (name, version, architecture)
    - Attached displays, normalized across both clients, keyed for asset inventory
    - Network position: active IP, DNS servers, a physically-on-campus flag,
      and a campus-DNS flag (the two differ over VPN)

    **Pagination:** limit and offset are both applied in Python, over the full
    result set. Pushing limit into the SQL instead -- which this endpoint used
    to do -- silently breaks offset: the query returns the first N rows and the
    slice then takes offset..offset+N *of those*, so any offset >= N answers an
    empty list. A caller paging with a fixed page size sees that empty second
    page, reads it as the end of the list, and stops with a partial result and
    no error. Measured against a live deployment: a page size of 500 returned
    500 records and every offset at or above 500 returned nothing.
    """
    try:
        # Keyed on the filter alone, not on limit: the cached value is the whole
        # result set and paginate() takes the caller's window out of it. Keying
        # on limit as well cached a *truncated* set under a key that said
        # nothing about the truncation.
        _ckey = (include_archived,)
        _cached = cache_get("hardware", _ckey)
        if _cached is not None:
            add_pagination_headers(response, request, total=len(_cached),
                                   limit=limit, offset=offset)
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info(f"Fetching bulk hardware data (includeArchived={include_archived})")

        conn = get_db_connection()
        cursor = conn.cursor()

        # Load SQL from external file - uses parameterized archive filter.
        # The query deliberately does not LIMIT: pagination is applied to the
        # full set by paginate(), which is the only place that also honours
        # offset.
        query = load_sql("devices/bulk_hardware")

        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with hardware data")
        
        # Process hardware data
        all_hardware = []
        
        for row in rows:
            try:
                (serial_number, device_uuid, last_seen, hardware_data, collected_at, system_data,
                 device_name, computer_name, usage, catalog, location, asset_tag, department, fleet,
                 active_ip, dns_servers) = row

                device_display_name = device_name or computer_name or serial_number
                
                # Extract OS info from system data
                os_info = {}
                if system_data:
                    if isinstance(system_data, list) and len(system_data) > 0:
                        os_info = system_data[0].get('operatingSystem', {})
                    elif isinstance(system_data, dict):
                        os_info = system_data.get('operatingSystem', {})
                
                # Extract hardware details
                hw_details = hardware_data if isinstance(hardware_data, dict) else {}
                
                # Pre-extract fields the frontend needs (eliminates raw blob)
                processor_data = hw_details.get('processor') or hw_details.get('cpu')
                memory_data = hw_details.get('memory') or hw_details.get('totalMemory') or hw_details.get('physicalMemory')
                graphics_data = hw_details.get('graphics') or hw_details.get('gpu') or hw_details.get('displayAdapter')
                storage_data = hw_details.get('storage') or hw_details.get('drives')
                
                # Slim storage to summary only (removes rootDirectories tree which is ~40KB per device)
                slim_storage = None
                if storage_data:
                    if isinstance(storage_data, list):
                        slim_storage = [{
                            'name': d.get('name'),
                            'type': d.get('type'),
                            'capacity': d.get('capacity') or d.get('size'),
                            'freeSpace': d.get('freeSpace') or d.get('free_space'),
                            'health': d.get('health'),
                            'interface': d.get('interface'),
                            'isInternal': d.get('isInternal'),
                        } for d in storage_data]
                    elif isinstance(storage_data, dict):
                        slim_storage = storage_data
                
                # Slim processor to summary fields only
                slim_processor = processor_data
                if isinstance(processor_data, dict):
                    slim_processor = {
                        'name': processor_data.get('name') or processor_data.get('model') or processor_data.get('brand'),
                        'cores': processor_data.get('cores') or processor_data.get('core_count') or processor_data.get('logicalCores'),
                        'speed': processor_data.get('speed') or processor_data.get('frequency') or processor_data.get('currentSpeed'),
                        'architecture': processor_data.get('architecture'),
                    }
                
                # Displays, normalized across the two clients. macOS writes snake_case keys
                # and Windows has written camelCase, so accept either and emit one shape -
                # asset inventory keys on serialNumber and cannot branch per platform.
                displays_data = hw_details.get('displays')
                slim_displays = None
                if isinstance(displays_data, list):
                    slim_displays = [{
                        'name': disp.get('name'),
                        'serialNumber': disp.get('serial_number') or disp.get('serialNumber'),
                        'manufacturer': disp.get('manufacturer'),
                        'model': disp.get('model'),
                        'type': disp.get('type'),
                        'resolution': disp.get('resolution'),
                        'vendorId': disp.get('vendor_id') or disp.get('vendorId'),
                        'productId': disp.get('product_id') or disp.get('productId'),
                        'manufactureYear': disp.get('manufacture_year') or disp.get('manufactureYear'),
                        # Week pairs with the year to make an actual EDID manufacture date.
                        # Year alone collapses every panel to 1 January, which is precise
                        # enough to look real and wrong enough to mislead an EOL date.
                        'manufactureWeek': disp.get('manufacture_week') or disp.get('manufactureWeek'),
                        'isMainDisplay': disp.get('is_main_display') or disp.get('isMainDisplay'),
                        'connectionType': disp.get('connection_type') or disp.get('connectionType'),
                        'online': disp.get('online'),
                    } for disp in displays_data if isinstance(disp, dict)]

                all_hardware.append({
                    'serialNumber': serial_number,
                    'deviceId': device_uuid,
                    'deviceName': device_display_name,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'manufacturer': hw_details.get('manufacturer') or hw_details.get('systemManufacturer'),
                    'model': hw_details.get('model') or hw_details.get('systemProductName'),
                    'processor': slim_processor,
                    'memory': memory_data,
                    'storage': slim_storage,
                    'graphics': graphics_data,
                    'osName': os_info.get('name'),
                    'osVersion': os_info.get('version') or os_info.get('displayVersion'),
                    'architecture': os_info.get('architecture'),
                    'inventory': {
                        **(hw_details.get('inventory') or {}),
                        'usage': usage,
                        'catalog': catalog,
                        'location': location,
                        'assetTag': asset_tag or (hw_details.get('inventory') or {}).get('assetTag') or (hw_details.get('inventory') or {}).get('asset_tag'),
                        'department': department,
                        'area': department,
                        'fleet': fleet,
                    },
                    'assetTag': asset_tag or (hw_details.get('inventory') or {}).get('assetTag') or (hw_details.get('inventory') or {}).get('asset_tag'),
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'department': department,
                    'area': department,
                    'fleet': fleet,
                    'displays': slim_displays,
                    'network': {
                        'ipAddress': active_ip,
                        'dnsServers': dns_servers,
                        'onCampus': _is_on_campus(active_ip, dns_servers),
                        'campusDns': _has_campus_dns(dns_servers),
                    },
                })
            
            except Exception as e:
                logger.warning(f"Error processing hardware for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(all_hardware)} hardware records")
        cache_set("hardware", all_hardware, _ckey)
        logger.info(f"[PERF] /api/devices/hardware: {_time.monotonic()-_t0:.3f}s ({len(all_hardware)} devices)")
        # X-Total-Count is how a paging client tells a short page from a truncated
        # one. Without it, a caller that reads fewer devices than exist has no way
        # to know.
        add_pagination_headers(response, request, total=len(all_hardware),
                               limit=limit, offset=offset)
        return paginate(all_hardware, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk hardware: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk hardware: {str(e)}")


@router.get("/installs/filters", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_installs_filters(
    include_archived: bool = Query(default=False, alias="includeArchived")
):
    """
    Lightweight endpoint for installs filter options.
    
    Returns unique managed install names, inventory filter values, config metadata,
    and a lightweight device list with pre-computed status counts.
    
    This replaces downloading the full /api/devices/installs/full (52MB+) just
    to extract filter options client-side.
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("installs_filters", _ckey)
        if _cached is not None:
            return _cached
        _t0 = _time.monotonic()
        logger.info(f"Fetching installs filter options (includeArchived={include_archived})")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = load_sql("devices/installs_filter_options")
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        managed_installs = set()
        stale_agents = []
        cimian_installs = set()
        munki_installs = set()
        usages = set()
        catalogs = set()
        rooms = set()
        areas = set()
        fleets = set()
        platforms = set()
        software_repos = set()
        manifests = set()
        devices = []

        for row in rows:
            serial, device_name, usage, catalog, location, asset_tag, department, fleet, platform, installs_data, last_seen = row

            if usage:
                usages.add(usage)
            if catalog:
                catalogs.add(catalog)
            if location:
                rooms.add(location)
            if department:
                areas.add(department)
            if fleet:
                fleets.add(fleet)
            if platform:
                normalized_platform = 'Macintosh' if platform == 'Darwin' else 'Windows' if platform == 'Windows NT' else platform
                platforms.add(normalized_platform)
            
            installs_obj = installs_data if isinstance(installs_data, dict) else {}
            cimian_data = installs_obj.get('cimian', {})
            munki_data = installs_obj.get('munki', {})
            
            # Extract unique item names
            for item in cimian_data.get('items', []):
                name = item.get('itemName') or item.get('displayName')
                if name and name not in ('managed_apps', 'managed_profiles'):
                    managed_installs.add(name.strip())
                    cimian_installs.add(name.strip())
            
            for item in munki_data.get('items', []):
                name = item.get('name') or item.get('displayName')
                if name:
                    managed_installs.add(name.strip())
                    munki_installs.add(name.strip())
            
            # Extract config metadata
            config = cimian_data.get('config', {})
            if config.get('SoftwareRepoURL'):
                software_repos.add(config['SoftwareRepoURL'])
            if config.get('softwareRepoUrl'):
                software_repos.add(config['softwareRepoUrl'])
            if config.get('ClientIdentifier'):
                manifests.add(config['ClientIdentifier'])
            if config.get('clientIdentifier'):
                manifests.add(config['clientIdentifier'])
            
            munki_repo = munki_data.get('softwareRepoURL')
            if munki_repo:
                software_repos.add(munki_repo)
            munki_client = munki_data.get('clientIdentifier')
            if munki_client:
                manifests.add(munki_client)
            
            # Pre-compute item status counts
            items = cimian_data.get('items', []) or munki_data.get('items', [])
            installed_count = 0
            pending_count = 0
            error_count = 0
            warning_count = 0
            removed_count = 0
            # Items that completed an install in the MOST RECENT run, as opposed
            # to the much larger set that is merely installed. Munki reports
            # these from InstallResults, Cimian from the session that ran them.
            success_count = 0

            for item in items:
                status = (item.get('currentStatus') or item.get('status') or '').lower()
                if status in ('install_succeeded', 'install-succeeded', 'completed'):
                    success_count += 1
                    installed_count += 1
                elif status in ('installed', 'install-of-', 'install_of', 'present'):
                    installed_count += 1
                elif status in ('will-be-installed', 'will_be_installed', 'pending', 'downloading', 'installing'):
                    pending_count += 1
                elif status in ('install-failed', 'install_failed', 'error', 'failed'):
                    error_count += 1
                elif status in ('warning', 'needs-update', 'needs_update'):
                    warning_count += 1
                elif status in ('removed', 'will-be-removed', 'will_be_removed', 'removal-of-'):
                    removed_count += 1
                else:
                    installed_count += 1  # Default to installed

            # For Munki: count run-level messages that aren't tied to items. Mac client keeps
            # the raw message in munki.errors/warnings even when it also attaches to an item,
            # so take max() instead of summing to avoid double-counting matched messages.
            # This catches preflight failures and other unattributable issues that would
            # otherwise show as "0 warnings" even when MunkiReport flags the device.
            if munki_data:
                munki_err_msgs = [m for m in (munki_data.get('errors') or '').split(';') if m.strip()]
                munki_warn_msgs = [m for m in (munki_data.get('warnings') or '').split(';') if m.strip()]
                munki_problem_items = [p for p in (munki_data.get('problemInstalls') or '').split(',') if p.strip()]
                items_with_last_warning = sum(1 for it in items if (it.get('lastWarning') or '').strip())
                error_count = max(error_count, len(munki_err_msgs))
                warning_count = max(
                    warning_count + items_with_last_warning,
                    len(munki_warn_msgs) + len(munki_problem_items),
                )
            
            # Determine config type
            is_cimian = bool(cimian_data)
            config_type = 'Cimian' if is_cimian else ('Munki' if munki_data else 'None')
            
            # Get most recent session
            sessions = cimian_data.get('sessions', []) or munki_data.get('sessions', [])
            latest_session = sessions[0] if sessions else None

            # How long this device has been reporting in with a silent agent.
            # Computed per agent: the two record their run times in different
            # shapes, so a single merged reading would be blank for one of them.
            cimian_run_at = agent_last_run(cimian_data)
            munki_run_at = agent_last_run(munki_data)
            cimian_stale_days = agent_stale_days(cimian_run_at, last_seen)
            munki_stale_days = agent_stale_days(munki_run_at, last_seen)
            cimian_run_iso = cimian_run_at.isoformat() if cimian_run_at else None
            munki_run_iso = munki_run_at.isoformat() if munki_run_at else None

            agent_run_at = cimian_run_at or munki_run_at
            stale_days = (
                cimian_stale_days if cimian_data else munki_stale_days
            )
            agent_last_run_iso = agent_run_at.isoformat() if agent_run_at else None
            
            # Build device record with slimmed items — keep only fields the
            # installs page actually reads: names for labels and pill matching,
            # statuses for categorization, and last error/warning strings for
            # the drill-down tables. Everything else (ids, versions, item
            # types, timestamps) came to ~10MB of a 28MB response across
            # ~113k items and had no reader; per-item version data lives in
            # the /installs report endpoint.
            ITEM_KEEP_FIELDS = ('itemName', 'displayName', 'name',
                                'currentStatus', 'status', 'lastError', 'lastWarning')

            # Errors and warnings carry their own message text; successes and
            # pending items do not, and a version plus a time is the only thing
            # that makes those drill-downs readable. Carried ONLY for items in a
            # notable state — plain 'installed' is ~99% of the ~113k items in
            # this payload and has no drill-down, so widening the field list for
            # every item would put back the megabytes the slimming removed.
            ITEM_DETAIL_FIELDS = ('installedVersion', 'version', 'latestVersion',
                                  'endTime', 'lastUpdate', 'lastAttemptTime', 'pendingReason')
            PLAIN_INSTALLED_STATUSES = {'installed', 'present', ''}

            def slim_item(item):
                slim = {k: item.get(k) for k in ITEM_KEEP_FIELDS
                        if item.get(k) is not None and item.get(k) != ''}
                status = (item.get('currentStatus') or item.get('status') or '').lower()
                if status not in PLAIN_INSTALLED_STATUSES:
                    slim.update({k: item.get(k) for k in ITEM_DETAIL_FIELDS
                                 if item.get(k) is not None and item.get(k) != ''})
                return slim

            cimian_slim = None
            if cimian_data:
                slim_items = [slim_item(item) for item in cimian_data.get('items', [])]
                cimian_slim = {
                    'config': config,
                    'version': cimian_data.get('version'),
                    'status': cimian_data.get('status'),
                    # status above is a static string the client emits; it says
                    # nothing about whether the agent still runs. These two do.
                    'lastRunTime': agent_last_run_iso,
                    'staleDays': stale_days,
                    # The page reads only sessions[0].status; five full
                    # session objects per device were ~6MB of the payload.
                    'sessions': (cimian_data.get('sessions') or [])[:1],
                    'items': slim_items,
                    'itemCounts': {
                        'total': len(cimian_data.get('items', [])),
                        'installed': installed_count,
                        'success': success_count,
                        'pending': pending_count,
                        'error': error_count,
                        'warning': warning_count,
                        'removed': removed_count,
                    }
                }
            
            munki_slim = None
            if munki_data:
                slim_munki_items = [slim_item(item) for item in munki_data.get('items', [])]
                munki_slim = {
                    'version': munki_data.get('version'),
                    'status': munki_data.get('status'),
                    'lastRunTime': munki_run_iso,
                    'staleDays': munki_stale_days,
                    'manifestName': munki_data.get('manifestName'),
                    'clientIdentifier': munki_data.get('clientIdentifier'),
                    'softwareRepoURL': munki_data.get('softwareRepoURL'),
                    'lastRunSuccess': munki_data.get('lastRunSuccess'),
                    'items': slim_munki_items,
                    'itemCounts': {
                        'total': len(munki_data.get('items', [])),
                        'installed': installed_count,
                        'success': success_count,
                        'pending': pending_count,
                        'error': error_count,
                        'warning': warning_count,
                        'removed': removed_count,
                    }
                }
            
            if stale_days is not None and stale_days >= STALE_AGENT_THRESHOLD_DAYS:
                stale_agents.append({
                    'serialNumber': serial,
                    'deviceName': device_name or serial,
                    'platform': platform,
                    'agent': config_type,
                    'agentVersion': (cimian_data or munki_data).get('version'),
                    'lastRunTime': agent_last_run_iso,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'staleDays': round(stale_days, 1),
                })

            devices.append({
                'serialNumber': serial,
                'deviceName': device_name or serial,
                'deviceId': None,
                'lastSeen': last_seen.isoformat() if last_seen else None,
                'platform': platform,
                'modules': {
                    'installs': {
                        'cimian': cimian_slim,
                        'munki': munki_slim,
                    },
                    'inventory': {
                        'deviceName': device_name,
                        'usage': usage,
                        'catalog': catalog,
                        'location': location,
                        'assetTag': asset_tag,
                        'department': department,
                        'area': department,
                        'fleet': fleet,
                    }
                }
            })

        logger.info(f"Installs filters: {len(managed_installs)} unique installs, {len(devices)} devices")
        
        _result = {
            'success': True,
            'managedInstalls': sorted(managed_installs),
            'cimianInstalls': sorted(cimian_installs),
            'munkiInstalls': sorted(munki_installs),
            'otherInstalls': [],
            'usages': sorted(usages),
            'catalogs': sorted(catalogs),
            'rooms': sorted(rooms),
            'areas': sorted(areas),
            'fleets': sorted(fleets),
            'platforms': sorted(platforms),
            'softwareRepos': sorted(software_repos),
            'manifests': sorted(manifests),
            'devicesWithData': len(devices),
            # Devices still reporting in whose management agent has stopped
            # running. They carry no errors or warnings -- their records froze
            # on the day the agent died -- so no per-item metric can surface
            # them. Newest silence first.
            'staleAgentCount': len(stale_agents),
            'staleAgentThresholdDays': STALE_AGENT_THRESHOLD_DAYS,
            'staleAgents': sorted(
                stale_agents, key=lambda d: d['staleDays'], reverse=True
            ),
            'devices': devices
        }
        cache_set("installs_filters", _result, _ckey)
        logger.info(f"[PERF] /api/devices/installs/filters: {_time.monotonic()-_t0:.3f}s")
        return _result
        
    except Exception as e:
        logger.error(f"Failed to get installs filters: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve installs filters: {str(e)}")


@router.get("/installs", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_bulk_installs(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk installs endpoint for Cimian managed packages.
    
    Returns flattened list of managed installs across all devices.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers and inventory data
    - Cimian package status (item name, version, update status)
    - Install dates and last check timestamps
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("installs", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk installs data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_installs")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with installs data")
        
        # Process installs data
        all_installs = []
        
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, installs_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag, fleet, platform = row
                
                device_display_name = device_name or computer_name or serial_number
                
                # Extract Cimian data (Windows)
                cimian_data = installs_data.get('cimian', {}) if isinstance(installs_data, dict) else {}
                cimian_items = cimian_data.get('items', [])
                
                # Extract Munki data (macOS)
                munki_data = installs_data.get('munki', {}) if isinstance(installs_data, dict) else {}
                munki_items = munki_data.get('items', [])
                
                # Flatten Cimian installs
                for idx, item in enumerate(cimian_items):
                    all_installs.append({
                        'id': f"{device_uuid}_cimian_{idx}",
                        'deviceId': device_uuid,
                        'deviceName': device_display_name,
                        'serialNumber': serial_number,
                        'lastSeen': last_seen.isoformat() if last_seen else None,
                        'collectedAt': collected_at.isoformat() if collected_at else None,
                        'itemName': item.get('itemName'),
                        'currentStatus': item.get('currentStatus'),
                        'latestVersion': item.get('latestVersion'),
                        'installedVersion': item.get('installedVersion'),
                        'installDate': item.get('installDate'),
                        'lastChecked': item.get('lastChecked'),
                        'updateAvailable': item.get('updateAvailable'),
                        'usage': usage,
                        'catalog': catalog,
                        'location': location,
                        'assetTag': asset_tag,
                        'fleet': fleet,
                        'platform': platform or 'Windows',
                        'source': 'cimian'
                    })
                
                # Flatten Munki installs (macOS)
                for idx, item in enumerate(munki_items):
                    all_installs.append({
                        'id': f"{device_uuid}_munki_{idx}",
                        'deviceId': device_uuid,
                        'deviceName': device_display_name,
                        'serialNumber': serial_number,
                        'lastSeen': last_seen.isoformat() if last_seen else None,
                        'collectedAt': collected_at.isoformat() if collected_at else None,
                        'itemName': item.get('name') or item.get('displayName'),
                        'currentStatus': item.get('status'),
                        'latestVersion': item.get('version'),
                        'installedVersion': item.get('installedVersion'),
                        'installDate': item.get('endTime'),
                        'lastChecked': None,
                        'updateAvailable': None,
                        'usage': usage,
                        'catalog': catalog,
                        'location': location,
                        'assetTag': asset_tag,
                        'fleet': fleet,
                        'platform': platform or 'macOS',
                        'source': 'munki'
                    })
            
            except Exception as e:
                logger.warning(f"Error processing installs for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(all_installs)} install records from {len(rows)} devices")
        cache_set("installs", all_installs, _ckey)
        logger.info(f"[PERF] /api/devices/installs: {_time.monotonic()-_t0:.3f}s ({len(all_installs)} records)")
        return paginate(all_installs, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk installs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk installs: {str(e)}")



@router.get("/installs/full", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_bulk_installs_full(
    include_archived: bool = Query(default=False, alias="includeArchived"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk installs endpoint returning FULL device records with nested structure.
    
    Unlike /api/devices/installs (flat items), this returns devices with complete
    modules.installs structure including config, version, sessions etc.
    Used by /devices/installs page for full UI rendering.
    
    By default, archived devices are excluded. Use includeArchived=true to include them.
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("installs_full", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk installs (full structure)")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # PERFORMANCE: Same query structure as working flat endpoint
        # Use d.id = i.device_id which is how installs are stored
        query = """
        SELECT DISTINCT ON (d.serial_number)
            d.serial_number,
            d.device_id,
            d.last_seen,
            i.updated_at as installs_updated_at,
            i.data as installs_data,
            COALESCE(inv.data->>'device_name', inv.data->>'deviceName') as device_name,
            inv.data->>'usage' as usage,
            inv.data->>'catalog' as catalog,
            inv.data->>'location' as location,
            COALESCE(inv.data->>'asset_tag', inv.data->>'assetTag') as asset_tag
        FROM devices d
        LEFT JOIN installs i ON d.id = i.device_id
        LEFT JOIN inventory inv ON d.id = inv.device_id
        WHERE d.serial_number IS NOT NULL
            AND d.serial_number NOT LIKE 'TEST-%'
            AND i.data IS NOT NULL
        """
        
        # Add archive filter
        if not include_archived:
            query += " AND d.archived = FALSE"
        
        query += " ORDER BY d.serial_number, i.updated_at DESC"
        
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with full installs data")
        
        # Build full device records with nested structure
        devices = []
        
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, installs_updated_at, installs_data, device_name, usage, catalog, location, asset_tag = row
                
                # Extract only what UI needs from installs_data
                installs_obj = installs_data if isinstance(installs_data, dict) else {}
                cimian_data = installs_obj.get('cimian', {})
                munki_data = installs_obj.get('munki', {})
                
                # Build lightweight installs structure (exclude runLog which is huge)
                lightweight_installs = {}

                # When this module was last ingested, which is NOT the same as the
                # device's last_seen. Several payloads go up per hour carrying
                # different module sets, and installs specifically is published by
                # Cimian's postflight - so it refreshes on an acting Cimian session,
                # not on every check-in. Without this a consumer cannot tell a live
                # failure from one the device already resolved hours ago, and the
                # only way to find out is to get onto the machine and read
                # reports\items.json.
                lightweight_installs['collectedAt'] = (
                    installs_updated_at.isoformat() if installs_updated_at else None
                )
                
                # Include Cimian data if present (Windows)
                if cimian_data:
                    lightweight_installs['cimian'] = {
                        'items': cimian_data.get('items', []),
                        'config': cimian_data.get('config', {}),
                        'version': cimian_data.get('version'),
                        'status': cimian_data.get('status'),
                        'sessions': cimian_data.get('sessions', [])[:5],  # Only last 5 sessions
                    }
                
                # Include Munki data if present (macOS)
                if munki_data:
                    lightweight_installs['munki'] = {
                        'items': munki_data.get('items', []),
                        'version': munki_data.get('version'),
                        'status': munki_data.get('status'),
                        'manifestName': munki_data.get('manifestName'),
                        'clientIdentifier': munki_data.get('clientIdentifier'),
                        'softwareRepoURL': munki_data.get('softwareRepoURL'),
                        'lastRunSuccess': munki_data.get('lastRunSuccess'),
                        'startTime': munki_data.get('startTime'),
                        'endTime': munki_data.get('endTime'),
                    }
                
                devices.append({
                    'serialNumber': serial_number,
                    'deviceId': device_uuid,
                    'deviceName': device_name or serial_number,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'platform': None,
                    'modules': {
                        'installs': lightweight_installs,
                        'inventory': {
                            'deviceName': device_name,
                            'usage': usage,
                            'catalog': catalog,
                            'location': location,
                            'assetTag': asset_tag
                        }
                    }
                })
            
            except Exception as e:
                logger.warning(f"Error processing full installs for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with full installs structure")
        cache_set("installs_full", devices, _ckey)
        logger.info(f"[PERF] /api/devices/installs/full: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk installs (full): {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk installs: {str(e)}")


@router.get("/network", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_bulk_network(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk network endpoint for fleet-wide network overview.
    
    Returns devices with network configuration data (interfaces, IPs, MACs, DNS, etc.).
    Used by /devices/network page for fleet-wide network visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers and inventory
    - Network interfaces, IP addresses, MAC addresses
    - DNS configuration, gateways, and network type
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("network", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk network data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_network")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with network data")
        
        # Process devices with network info
        devices = []
        
        for row in rows:
            try:
                (serial_number, device_uuid, last_seen, network_data, collected_at,
                 device_name, computer_name, usage, catalog, location, asset_tag,
                 department, fleet,
                 os_name, os_version, build_number, uptime, boot_time) = row

                device_obj = {
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'department': department,
                    'area': department,
                    'fleet': fleet,
                    'operatingSystem': os_name,
                    'osVersion': os_version,
                    'buildNumber': build_number,
                    'uptime': uptime,
                    'bootTime': boot_time,
                    'raw': network_data  # Raw network data for extractNetwork()
                }
                
                devices.append(device_obj)
            
            except Exception as e:
                logger.warning(f"Error processing network for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with network data")
        cache_set("network", devices, _ckey)
        logger.info(f"[PERF] /api/devices/network: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk network: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk network: {str(e)}")

@router.get("/security", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_bulk_security(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk security endpoint for fleet-wide security overview.
    
    Returns devices with security configuration (TPM, BitLocker, EDR, AV, etc.).
    Used by /devices/security page for fleet-wide security visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers and inventory
    - TPM status, BitLocker encryption state
    - EDR/AV status and configuration
    - Firewall and security baseline compliance
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("security", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk security data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_security")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with security data")
        
        devices = []
        for row in rows:
            try:
                (serial_number, device_uuid, last_seen, platform, collected_at,
                 device_name, computer_name, usage, catalog, location, asset_tag,
                 department, fleet,
                 firewall_enabled, encryption_enabled,
                 antivirus_name, antivirus_enabled, antivirus_up_to_date, antivirus_version, antivirus_last_scan,
                 detection_count, active_threat_count, has_active_threats,
                 detections_blocked_30d, detections_cleaned_30d, detections_total_30d,
                 last_threat_detected_at,
                 tpm_present, tpm_enabled, secure_boot_enabled, secure_boot_db_cert_count, secure_boot_kek_cert_count, sip_enabled, gatekeeper_enabled,
                 firmware_password_status,
                 memory_integrity_enabled, core_isolation_enabled, smart_app_control_state,
                 ssh_status_display, ssh_is_configured, ssh_is_service_running, rdp_enabled,
                 certificate_count, expired_cert_count, expiring_soon_cert_count,
                 user_expired_cert_count, os_root_expired_cert_count,
                 cve_count, critical_cve_count, actively_exploited_cve_count,
                 # Protection posture
                 lsa_protection_enabled, lsa_protection_mode, tamper_protected,
                 pending_reboot, asr_block_rule_count, asr_audit_rule_count,
                 defender_engine_version, defender_product_version, defender_exclusions_count,
                 # Compliance / inventory
                 applocker_configured, wdac_enabled,
                 smartscreen_state, edge_smartscreen_enabled,
                 audit_policy_count, edr_product_count) = row
                
                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'platform': platform,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'department': department,
                    'area': department,
                    'fleet': fleet,
                    # Firewall
                    'firewallEnabled': bool(firewall_enabled),
                    # Encryption
                    'encryptionEnabled': bool(encryption_enabled),
                    # Antivirus / Protection
                    'antivirusName': antivirus_name or '',
                    'antivirusEnabled': bool(antivirus_enabled),
                    'antivirusUpToDate': bool(antivirus_up_to_date),
                    'antivirusVersion': antivirus_version,
                    'antivirusLastScan': antivirus_last_scan,
                    # Detection (raw event count - includes ASR blocks)
                    'detectionCount': int(detection_count or 0),
                    # Active threats only (excludes ASR rule blocks which are protection working)
                    'activeThreatCount': int(active_threat_count or 0),
                    'hasActiveThreats': bool(has_active_threats),
                    'detectionsBlocked30d': int(detections_blocked_30d or 0),
                    'detectionsCleaned30d': int(detections_cleaned_30d or 0),
                    'detectionsTotal30d': int(detections_total_30d or 0),
                    'lastThreatDetectedAt': last_threat_detected_at,
                    # Tampering
                    'tpmPresent': bool(tpm_present),
                    'tpmEnabled': bool(tpm_enabled),
                    'secureBootEnabled': bool(secure_boot_enabled),
                    'secureBootDbCertCount': int(secure_boot_db_cert_count or 0),
                    'secureBootKekCertCount': int(secure_boot_kek_cert_count or 0),
                    'sipEnabled': sip_enabled,
                    'gatekeeperEnabled': bool(gatekeeper_enabled),
                    # Firmware Password
                    'firmwarePassword': {
                        'statusDisplay': firmware_password_status,
                        'isSet': firmware_password_status == 'Set',
                    } if firmware_password_status is not None else None,
                    # Protection (Windows)
                    'memoryIntegrityEnabled': bool(memory_integrity_enabled),
                    'coreIsolationEnabled': bool(core_isolation_enabled),
                    'smartAppControlState': smart_app_control_state,
                    # Remote Access
                    'secureShell': {
                        'statusDisplay': ssh_status_display,
                        'isConfigured': bool(ssh_is_configured),
                        'isServiceRunning': bool(ssh_is_service_running),
                    },
                    'rdpEnabled': bool(rdp_enabled),
                    # Certificates
                    'certificateCount': certificate_count or 0,
                    'expiredCertCount': expired_cert_count or 0,
                    'expiringSoonCertCount': expiring_soon_cert_count or 0,
                    'userExpiredCertCount': user_expired_cert_count or 0,
                    'osRootExpiredCertCount': os_root_expired_cert_count or 0,
                    # Vulnerabilities (unpatched only; total via securityCves array if needed)
                    'cveCount': cve_count or 0,
                    'criticalCveCount': critical_cve_count or 0,
                    'activelyExploitedCveCount': actively_exploited_cve_count or 0,
                    # Protection posture
                    'lsaProtectionEnabled': bool(lsa_protection_enabled),
                    'lsaProtectionMode': lsa_protection_mode,
                    'tamperProtected': tamper_protected,
                    'pendingReboot': bool(pending_reboot),
                    'asrBlockRuleCount': int(asr_block_rule_count or 0),
                    'asrAuditRuleCount': int(asr_audit_rule_count or 0),
                    'defenderEngineVersion': defender_engine_version,
                    'defenderProductVersion': defender_product_version,
                    'defenderExclusionsCount': int(defender_exclusions_count or 0),
                    # Compliance / inventory
                    'appLockerConfigured': bool(applocker_configured),
                    'wdacEnabled': bool(wdac_enabled),
                    'smartScreenState': smartscreen_state,
                    'edgeSmartScreenEnabled': edge_smartscreen_enabled,
                    'auditPolicyCount': int(audit_policy_count or 0),
                    'edrProductCount': int(edr_product_count or 0),
                    # Identity-domain signals (UAC, join state, local admins, LAPS,
                    # Windows Hello, TPM ownership, password policy, auto-login) are
                    # served by /api/devices/identity now (identity_data blob).
                })
            except Exception as e:
                logger.warning(f"Error processing security for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with security data")
        cache_set("security", devices, _ckey)
        logger.info(f"[PERF] /api/devices/security: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk security: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk security: {str(e)}")

CERT_SEARCH_HARD_LIMIT = 10000

@router.get("/security/certificates", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def search_fleet_certificates(
    search: str = Query(default="", description="Search term to match against certificate commonName, issuer, subject, or serialNumber"),
    status: str = Query(default="all", description="Filter by certificate status: all, valid, expired, expiring"),
    limit: int = Query(default=1000, ge=1, le=CERT_SEARCH_HARD_LIMIT, description=f"Maximum results to return (max {CERT_SEARCH_HARD_LIMIT})"),
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results")
):
    """
    Fleet-wide certificate search endpoint.

    Searches across all device certificates for matching commonName, issuer, subject, or serialNumber.
    Useful for verifying certificate deployment across the fleet or finding expired certificates.

    **Parameters:**
    - search: Text to search for (case-insensitive, partial match)
    - status: Filter by cert status (all, valid, expired, expiring)
    - limit: Maximum results to return (default 1000, hard cap 10000)
    - includeArchived: Include archived devices
    """
    try:
        _ckey = (search.strip(), status.strip().lower(), include_archived, limit)
        _cached = cache_get("security_certs", _ckey)
        if _cached is not None:
            return _cached
        _t0 = _time.monotonic()
        logger.info(f"Searching fleet certificates: search='{search}', status='{status}', limit={limit}")

        conn = get_db_connection()
        cursor = conn.cursor()

        query = load_sql("devices/security_certificates")

        cursor.execute(query, {
            "search": search.strip(),
            "status": status.strip().lower(),
            "include_archived": include_archived,
            "max_results": limit,
        })
        rows = cursor.fetchall()
        conn.close()

        logger.info(f"Certificate search returned {len(rows)} results (capped at {limit})")
        
        results = []
        for row in rows:
            try:
                (serial_number, platform, device_name,
                 common_name, issuer, subject, cert_status,
                 not_after, not_before, days_until_expiry,
                 is_expired, is_expiring_soon,
                 store_name, store_location, key_algorithm,
                 cert_serial_number, is_self_signed) = row
                
                results.append({
                    'serialNumber': serial_number,
                    'platform': platform,
                    'deviceName': device_name,
                    'commonName': common_name,
                    'issuer': issuer,
                    'subject': subject,
                    'status': cert_status,
                    'notAfter': not_after,
                    'notBefore': not_before,
                    'daysUntilExpiry': days_until_expiry,
                    'isExpired': bool(is_expired),
                    'isExpiringSoon': bool(is_expiring_soon),
                    'storeName': store_name,
                    'storeLocation': store_location,
                    'keyAlgorithm': key_algorithm,
                    'certSerialNumber': cert_serial_number,
                    'isSelfSigned': bool(is_self_signed),
                })
            except Exception as e:
                logger.warning(f"Error processing certificate row: {e}")
                continue
        
        cache_set("security_certs", results, _ckey)
        logger.info(f"[PERF] /api/devices/security/certificates: {_time.monotonic()-_t0:.3f}s ({len(results)} certs)")
        return results
        
    except Exception as e:
        logger.error(f"Failed to search fleet certificates: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to search certificates: {str(e)}")

def _management_reports_intune(management_data) -> bool:
    """True when the management module carries data only an Intune-managed
    device produces: the Intune policy, configuration and diagnostics
    structures the Windows client collects, or an ``mdm`` log root named
    Intune in the logs section (the Intune Management Extension logs on
    Windows, the Intune daemon logs on a Mac)."""
    if not isinstance(management_data, dict):
        return False
    intune_keys = ('intunePolicies', 'recentIntuneLogs',
                   'mdmConfigurations', 'mdmDiagnostics')
    if any(management_data.get(k) for k in intune_keys):
        return True
    logs = management_data.get('logs')
    roots = logs.get('roots') if isinstance(logs, dict) else None
    if not isinstance(roots, list):
        return False
    for root in roots:
        if not isinstance(root, dict):
            continue
        if str(root.get('tool') or '').lower() == 'mdm' and 'intune' in str(root.get('name') or '').lower():
            return True
    return False


def _detect_mdm_provider_from_url(url: str) -> str:
    """Detect the MDM provider from the active enrollment server/check-in URL.

    The enrollment URL reflects the MDM the device currently talks to. The MDM
    identity certificate is unreliable for this because it lingers in the
    System keychain after a device migrates between MDMs. Returns "" when the
    URL matches no known provider.
    """
    u = (url or '').lower()
    if not u.strip():
        return ''
    if 'manage.microsoft.com' in u or 'intune' in u:
        return 'Microsoft Intune'
    if 'jamfcloud' in u or 'jamf' in u:
        return 'Jamf Pro'
    if 'mosyle' in u:
        return 'Mosyle'
    if 'kandji' in u:
        return 'Kandji'
    if 'addigy' in u:
        return 'Addigy'
    if 'simplemdm' in u:
        return 'SimpleMDM'
    if 'micromdm' in u:
        return 'MicroMDM'
    if 'nanomdm' in u:
        return 'NanoMDM'
    return ''


@router.get("/management", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_bulk_management(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk management endpoint for fleet-wide MDM status.
    
    Returns devices with MDM enrollment status and management configuration.
    Used by /devices/management page for fleet-wide MDM visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers and inventory
    - MDM enrollment status (Enrolled/Not Enrolled)
    - Provider, enrollment type, Intune ID
    - Tenant information
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("management", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk management data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_management")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with management data")
        
        devices = []
        for row in rows:
            try:
                (serial_number, device_uuid, last_seen, management_data, collected_at,
                 device_name, computer_name, usage, catalog, location, asset_tag,
                 department, fleet, db_platform, db_os_name) = row
                
                # Extract key management fields from the raw data for easy frontend access
                # Support both Windows (camelCase) and Mac (snake_case) field names
                mdm_enrollment = management_data.get('mdmEnrollment', {}) or management_data.get('mdm_enrollment', {}) if management_data else {}
                device_details = management_data.get('deviceDetails', {}) or management_data.get('device_details', {}) if management_data else {}
                tenant_details = management_data.get('tenantDetails', {}) or management_data.get('tenant_details', {}) if management_data else {}
                mdm_certificate_raw = management_data.get('mdmCertificate', {}) or management_data.get('mdm_certificate', {}) if management_data else {}
                
                # Parse MDM certificate - Mac osquery returns JSON in 'output' field
                mdm_certificate = {}
                if mdm_certificate_raw:
                    if 'output' in mdm_certificate_raw and isinstance(mdm_certificate_raw['output'], str):
                        try:
                            import json
                            # Clean up osquery's escaped JSON format
                            clean_json = mdm_certificate_raw['output'].replace(';"', '"').strip()
                            mdm_certificate = json.loads(clean_json)
                        except:
                            mdm_certificate = mdm_certificate_raw
                    else:
                        mdm_certificate = mdm_certificate_raw
                
                # Determine enrollment status - support both isEnrolled (Windows) and enrolled (Mac)
                # Mac osquery returns string "true"/"false", Windows returns boolean
                is_enrolled_raw = mdm_enrollment.get('isEnrolled') or mdm_enrollment.get('is_enrolled') or mdm_enrollment.get('enrolled')
                is_enrolled = is_enrolled_raw in (True, 'true', '1', 'yes', 'True')
                enrollment_status = 'Enrolled' if is_enrolled else 'Not Enrolled'
                
                # Provider detection - the active MDM server/check-in URL is
                # authoritative; the MDM identity certificate is only a fallback
                # because it goes stale after a device migrates between MDMs.
                # Priority: explicit provider > enrollment URL > certificate > "Unmanaged"
                provider = mdm_enrollment.get('provider')
                if not provider:
                    server_url = mdm_enrollment.get('server_url') or mdm_enrollment.get('serverUrl') or ''
                    checkin_url = mdm_enrollment.get('checkin_url') or mdm_enrollment.get('checkinUrl') or ''
                    provider = _detect_mdm_provider_from_url(f"{server_url} {checkin_url}")
                if not provider:
                    # Fall back to certificate data (Mac) - may be stale after migration
                    cert_issuer = mdm_certificate.get('certificate_issuer') or mdm_certificate.get('certificateIssuer')
                    cert_provider = mdm_certificate.get('mdm_provider') or mdm_certificate.get('mdmProvider')
                    if cert_provider:
                        provider = cert_provider
                    elif cert_issuer:
                        issuer_lower = cert_issuer.lower()
                        if 'micromdm' in issuer_lower:
                            provider = 'MicroMDM'
                        elif 'nanomdm' in issuer_lower:
                            provider = 'NanoMDM'
                        elif 'jamf' in issuer_lower:
                            provider = 'Jamf Pro'
                        elif 'microsoft' in issuer_lower:
                            provider = 'Microsoft Intune'
                        else:
                            provider = cert_issuer  # Use issuer as provider
                if not provider:
                    # A device whose management module carries Intune-specific
                    # data is Intune-managed even when mdm_enrollment omits an
                    # explicit provider field. The Windows client collects these
                    # structures only under Intune, so their presence is a
                    # reliable signal.
                    has_intune_data = _management_reports_intune(management_data)
                    enrollment_type_raw = (mdm_enrollment.get('enrollmentType')
                                           or mdm_enrollment.get('enrollment_type') or '')
                    if has_intune_data or 'entra' in enrollment_type_raw.lower():
                        provider = 'Microsoft Intune'
                if not provider:
                    # Device reports an MDM enrollment but no provider could be
                    # identified from any source - surface it as Unmanaged.
                    provider = 'Unmanaged'
                
                # Enrollment type - support Mac and Windows patterns
                enrollment_type = mdm_enrollment.get('enrollmentType') or mdm_enrollment.get('enrollment_type')
                if not enrollment_type and is_enrolled:
                    # Mac-specific: Check for DEP/ADE enrollment
                    installed_from_dep = mdm_enrollment.get('installed_from_dep') or mdm_enrollment.get('installedFromDep')
                    user_approved = mdm_enrollment.get('user_approved') or mdm_enrollment.get('userApproved')
                    if installed_from_dep in (True, 'true', '1', 'True'):
                        enrollment_type = 'Automated Device Enrollment'
                    elif user_approved in (True, 'true', '1', 'True'):
                        enrollment_type = 'User Approved Enrollment'
                    else:
                        enrollment_type = 'MDM Enrolled'
                if not enrollment_type:
                    enrollment_type = 'N/A'
                
                # Platform comes from the devices table (the real OS), not the
                # MDM provider: Intune manages both Macs and Windows, so the
                # provider cannot distinguish them.
                device_platform = None
                if db_platform:
                    pl = str(db_platform).strip().lower()
                    if pl in ('macos', 'mac', 'darwin', 'macintosh'):
                        device_platform = 'macOS'
                    elif pl.startswith('win'):
                        device_platform = 'Windows'
                if not device_platform:
                    # Fall back to provider only for unambiguously macOS-only MDMs
                    provider_lower = (provider or '').lower()
                    if provider in ('MicroMDM', 'NanoMDM', 'Apple', 'Mosyle', 'Kandji') or 'jamf' in provider_lower:
                        device_platform = 'macOS'
                
                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'department': department,
                    'area': department,
                    'fleet': fleet,
                    # Extract flattened MDM fields for table display (using actual field names from data)
                    'provider': provider,
                    'enrollmentStatus': enrollment_status,
                    'enrollmentType': enrollment_type,
                    'platform': device_platform,
                    'intuneId': device_details.get('intuneDeviceId') or device_details.get('intune_device_id') or (management_data.get('device_identifiers', {}) or {}).get('uuid') or device_uuid or 'N/A',
                    'tenantName': tenant_details.get('tenantName') or tenant_details.get('tenant_name') or tenant_details.get('organization') or 'N/A',
                    'isEnrolled': is_enrolled,
                    # Pre-extracted fields (replaces raw blob)
                    'autopilotConfig': management_data.get('autopilot_config') or management_data.get('autopilotConfig') if management_data else None,
                    'osName': db_os_name  # real OS name from the devices table
                })

                # Fall back to embedded system data only when the devices table
                # has no os_name recorded.
                if not devices[-1]['osName'] and management_data:
                    sys_data = management_data.get('system', {})
                    if sys_data:
                        os_obj = sys_data.get('operatingSystem', {}) or sys_data.get('operating_system', {})
                        if os_obj:
                            devices[-1]['osName'] = os_obj.get('name')
            except Exception as e:
                logger.warning(f"Error processing management for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with management data")
        cache_set("management", devices, _ckey)
        logger.info(f"[PERF] /api/devices/management: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk management: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk management: {str(e)}")

@router.get("/inventory", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_bulk_inventory(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk inventory endpoint for fleet-wide device inventory.
    
    Returns devices with inventory metadata (names, asset tags, locations, usage, etc.).
    Used by /devices/inventory page for fleet-wide inventory management.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers (serial number, device ID)
    - Asset information (name, tag, location, department)
    - Usage classification and catalog assignment
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("inventory", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk inventory data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_inventory")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with inventory data")
        
        devices = []
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, inventory_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag, department, fleet = row

                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'department': department,
                    'fleet': fleet
                })
            except Exception as e:
                logger.warning(f"Error processing inventory for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with inventory data")
        cache_set("inventory", devices, _ckey)
        logger.info(f"[PERF] /api/devices/inventory: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk inventory: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk inventory: {str(e)}")

@router.get("/system", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_bulk_system(
    request: Request,
    response: Response,
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk system endpoint for fleet-wide OS and system information.
    
    Returns devices with OS details, uptime, updates, services, etc.
    Used by /devices/system page for fleet-wide system visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    limit/offset page the response, matching /management and /installs/full. Omitting
    limit returns every device; a fixed default would truncate the fleet silently once
    it grew past that number, which is the failure this endpoint already had.
    
    **Response includes:**
    - Device identifiers and inventory
    - Operating system name, version, build number
    - System uptime, boot time
    - Pending updates and service status (in raw field)
    """
    try:
        # Cache the whole result set and slice it per request, the way the other
        # bulk endpoints do. Keying the cache on limit and passing limit into the
        # query meant offset was applied to an already-truncated page, so a caller
        # paging at any size below the fleet total got one page and then empty
        # results - indistinguishable, to that caller, from having read everything.
        _ckey = (include_archived,)
        _cached = cache_get("system", _ckey)
        if _cached is not None:
            add_pagination_headers(response, request, total=len(_cached),
                                   limit=limit, offset=offset)
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk system data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses a parameterized archive filter
        query = load_sql("devices/bulk_system")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with system data")
        
        devices = []
        for row in rows:
            try:
                (serial_number, device_uuid, last_seen, system_data, collected_at,
                 device_name, computer_name, usage, catalog, location, asset_tag,
                 department, fleet) = row
                
                # Extract system data (handle array format)
                if isinstance(system_data, list) and len(system_data) > 0:
                    system_data = system_data[0]
                
                # Extract operating system info from raw data (handle both snake_case and camelCase)
                os_info = system_data.get('operating_system') or system_data.get('operatingSystem', {}) if system_data else {}
                uptime_raw = system_data.get('uptime') if system_data else None
                
                # Parse uptime - handle both integer (seconds) and string (format: "d.hh:mm:ss")
                uptime_seconds = None
                if uptime_raw:
                    try:
                        # If it's already an integer, use it directly
                        if isinstance(uptime_raw, (int, float)):
                            uptime_seconds = int(uptime_raw)
                        # If it's a string, parse it
                        elif isinstance(uptime_raw, str):
                            parts = uptime_raw.replace('.', ':').split(':')
                            if len(parts) >= 4:
                                days, hours, minutes, seconds = int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])
                                uptime_seconds = days * 86400 + hours * 3600 + minutes * 60 + seconds
                            elif len(parts) == 1:
                                # Single number as string
                                uptime_seconds = int(parts[0])
                    except (ValueError, IndexError, AttributeError) as e:
                        logger.debug(f"Could not parse uptime {uptime_raw} for device {serial_number}: {e}")
                        uptime_seconds = None
                
                # Build OS name string from components
                os_name = os_info.get('name', '')
                os_edition = os_info.get('edition', '')
                os_display_version = os_info.get('displayVersion', '')
                
                # Format: "Windows 11 Enterprise 24H2" or just the name if no edition
                operating_system = os_name
                if os_edition and os_edition not in os_name:
                    operating_system = f"{os_name} {os_edition}"
                if os_display_version:
                    operating_system = f"{operating_system} {os_display_version}"
                
                # Get counts for services, updates, scheduled_tasks (NOT the full arrays)
                services_count = 0
                updates_count = 0
                tasks_count = 0
                pending_updates_count = 0
                login_items_count = 0
                extensions_count = 0
                kernel_extensions_count = 0
                if system_data:
                    services = system_data.get('services', [])
                    updates = system_data.get('updates', [])
                    tasks = system_data.get('scheduled_tasks') or system_data.get('scheduledTasks', [])
                    services_count = len(services) if isinstance(services, list) else 0
                    updates_count = len(updates) if isinstance(updates, list) else 0
                    tasks_count = len(tasks) if isinstance(tasks, list) else 0
                    # Mac-specific counts
                    pending = system_data.get('pendingAppleUpdates') or system_data.get('pending_apple_updates', [])
                    pending_updates_count = len(pending) if isinstance(pending, list) else 0
                    deferred_updates_count = 0
                    if isinstance(pending, list):
                        deferred_updates_count = sum(1 for u in pending if isinstance(u, dict) and (u.get('deferred') or u.get('deferredUntil')))
                    # Windows pending updates from SystemModule collection
                    if pending_updates_count == 0:
                        win_count = system_data.get('pendingWindowsUpdatesCount', 0)
                        if isinstance(win_count, int) and win_count > 0:
                            pending_updates_count = win_count
                        else:
                            win_pending = system_data.get('pendingWindowsUpdates') or system_data.get('pending_windows_updates', [])
                            if isinstance(win_pending, list) and len(win_pending) > 0:
                                pending_updates_count = len(win_pending)
                    litems = system_data.get('loginItems') or system_data.get('login_items', [])
                    login_items_count = len(litems) if isinstance(litems, list) else 0
                    sext = system_data.get('systemExtensions') or system_data.get('system_extensions', [])
                    extensions_count = len(sext) if isinstance(sext, list) else 0
                    kext = system_data.get('kernelExtensions') or system_data.get('kernel_extensions', [])
                    kernel_extensions_count = len(kext) if isinstance(kext, list) else 0
                
                # Extract additional OS details already in the JSONB
                architecture = os_info.get('architecture') or os_info.get('arch', '')
                locale = os_info.get('locale', '')
                time_zone = os_info.get('timeZone') or os_info.get('time_zone', '')
                install_date = os_info.get('installDate') or os_info.get('install_date', '')
                feature_update = os_info.get('featureUpdate') or os_info.get('feature_update', '')
                # In-place upgrade markers (HKLM\SYSTEM\Setup\"Source OS (Updated on ...)").
                # installDate moves for a wipe and for a feature update alike; these say
                # which. None means the client has not reported the field yet, and is not
                # the same claim as 0, which means the OS has never been upgraded over.
                last_in_place_upgrade = (os_info.get('lastInPlaceUpgrade')
                                         or os_info.get('last_in_place_upgrade'))
                in_place_upgrade_count = os_info.get('inPlaceUpgradeCount')
                if in_place_upgrade_count is None:
                    in_place_upgrade_count = os_info.get('in_place_upgrade_count')
                uptime_string = system_data.get('uptimeString') or system_data.get('uptime_string', '') if system_data else ''
                
                # Check systemDetails for Mac locale/timezone/keyboard if not on os_info
                sys_details = system_data.get('systemDetails') or system_data.get('system_details', {}) if system_data else {}
                if not locale:
                    locale = sys_details.get('locale', '')
                if not time_zone:
                    time_zone = sys_details.get('timeZone') or sys_details.get('time_zone', '')
                
                keyboard_layouts = os_info.get('activeKeyboardLayout') or os_info.get('active_keyboard_layout', '')
                if not keyboard_layouts:
                    kb_list = os_info.get('keyboard_layouts') or os_info.get('keyboardLayouts') or sys_details.get('keyboardLayouts', [])
                    if isinstance(kb_list, list) and kb_list:
                        keyboard_layouts = ', '.join(str(k) for k in kb_list if k)
                
                # Activation details (Windows)
                activation = os_info.get('activation', {}) or {}
                activation_status = activation.get('isActivated', activation.get('is_activated'))
                license_type = activation.get('licenseType') or activation.get('license_type', '')
                license_source = activation.get('licenseSource') or activation.get('license_source', '')
                has_firmware_license = activation.get('hasFirmwareLicense', activation.get('has_firmware_license'))
                
                # Detect platform
                os_platform = os_info.get('platform', '')
                os_name_lower = (os_name or '').lower()
                if os_platform.lower() == 'darwin' or 'macos' in os_name_lower or 'mac os' in os_name_lower:
                    platform = 'macOS'
                elif 'windows' in os_name_lower:
                    platform = 'Windows'
                else:
                    platform = 'Unknown'
                
                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'department': department,
                    'area': department,
                    'fleet': fleet,
                    'operatingSystem': operating_system.strip() or None,
                    'osVersion': os_info.get('version'),
                    'buildNumber': os_info.get('build'),
                    'uptime': uptime_seconds,
                    'uptimeString': uptime_string or None,
                    'bootTime': system_data.get('bootTime') or system_data.get('last_boot_time') if system_data else None,
                    'servicesCount': services_count,
                    'updatesCount': updates_count,
                    'tasksCount': tasks_count,
                    # New enriched fields
                    'platform': platform,
                    'architecture': architecture or None,
                    'edition': os_edition or None,
                    'displayVersion': os_display_version or None,
                    'locale': locale or None,
                    'timeZone': time_zone or None,
                    'keyboardLayout': keyboard_layouts or None,
                    'installDate': install_date or None,
                    'featureUpdate': feature_update or None,
                    'lastInPlaceUpgrade': last_in_place_upgrade or None,
                    'inPlaceUpgradeCount': in_place_upgrade_count,
                    'activationStatus': activation_status,
                    'licenseType': license_type or None,
                    'licenseSource': license_source or None,
                    'hasFirmwareLicense': has_firmware_license,
                    # Mac-specific counts
                    'pendingUpdatesCount': pending_updates_count,
                    'deferredUpdatesCount': deferred_updates_count,
                    'loginItemsCount': login_items_count,
                    'extensionsCount': extensions_count,
                    'kernelExtensionsCount': kernel_extensions_count,
                })
            except Exception as e:
                logger.warning(f"Error processing system for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with system data")
        cache_set("system", devices, _ckey)
        logger.info(f"[PERF] /api/devices/system: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        # X-Total-Count is how a paging client tells a short page from a truncated
        # one. Without it, a caller that reads fewer devices than exist has no way
        # to know, which is how the fleet came to be reported at half its size.
        add_pagination_headers(response, request, total=len(devices),
                               limit=limit, offset=offset)
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk system: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk system: {str(e)}")

@router.get("/peripherals", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_bulk_peripherals(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk peripherals endpoint for fleet-wide peripheral devices.
    
    Returns devices with connected peripherals (USB, input devices, audio, Bluetooth, cameras, etc.).
    Used by /devices/peripherals page for fleet-wide peripheral visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers and inventory
    - USB devices (hubs, storage, peripherals)
    - Input devices (keyboards, mice, trackpads, graphics tablets)
    - Audio devices (speakers, microphones)
    - Bluetooth devices (paired and connected)
    - Cameras (built-in and external)
    - Thunderbolt devices (docks, displays, storage)
    - Printers (CUPS, network, direct-connect)
    - Scanners
    - External storage (USB drives, SD cards)
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("peripherals", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk peripherals data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_peripherals")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with peripherals data")
        
        devices = []
        for row in rows:
            try:
                (serial_number, device_uuid, last_seen, peripherals_data, collected_at,
                 device_name, computer_name, usage, catalog, location, asset_tag,
                 department, fleet, platform) = row
                
                # Clients emit peripherals data in two shapes:
                #   Windows: nested -- {"usb": {"usb_devices": [...]}, "bluetooth": {"bluetooth_devices": [...]}, ...}
                #   Mac:     flat   -- {"usbDevices": [...], "bluetoothDevices": [...], ...}
                # Extract from whichever is populated; fall back to [].
                pd = peripherals_data if isinstance(peripherals_data, dict) else {}
                def _pick(*paths):
                    for path in paths:
                        node = pd
                        for key in path:
                            if not isinstance(node, dict):
                                node = None
                                break
                            node = node.get(key)
                        if isinstance(node, list):
                            return node
                    return []

                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'department': department,
                    'area': department,
                    'fleet': fleet,
                    'platform': platform,
                    'usbDevices': _pick(('usbDevices',), ('usb', 'usb_devices')),
                    'bluetoothDevices': _pick(('bluetoothDevices',), ('bluetooth', 'bluetooth_devices')),
                    'printers': _pick(('printers',), ('printers', 'print_queues')),
                    'cameras': _pick(('cameras',), ('cameras', 'camera_devices')),
                    'audioDevices': _pick(('audioDevices',), ('audio', 'audio_devices')),
                    'displayDevices': _pick(('displayDevices',), ('displays', 'monitors')),
                    'inputDevices': _pick(('inputDevices',), ('input', 'input_devices')),
                    'storageDevices': _pick(('externalStorage',), ('storageDevices',), ('storage', 'storage_devices')),
                    'thunderboltDevices': _pick(('thunderboltDevices',), ('thunderbolt', 'thunderbolt_devices')),
                    'scanners': _pick(('scanners',), ('scanners', 'scanner_devices')),
                })
            except Exception as e:
                logger.warning(f"Error processing peripherals for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with peripherals data")
        cache_set("peripherals", devices, _ckey)
        logger.info(f"[PERF] /api/devices/peripherals: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk peripherals: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk peripherals: {str(e)}")

@router.get("/identity", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_bulk_identity(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk identity endpoint for fleet-wide user account and identity data.
    
    Returns devices with user accounts, groups, sessions, BTMDB health, and directory services.
    Used by /devices/identity page for fleet-wide identity visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers and inventory
    - User accounts (local, domain, Apple ID linked)
    - User groups and memberships
    - Login sessions and history
    - BTMDB health (macOS background task management database)
    - Directory services (AD, Open Directory, LDAP)
    - Secure Token users
    - Platform SSO registration status
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("identity", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk identity data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_identity")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with identity data")
        
        devices = []
        for row in rows:
            try:
                (serial_number, device_uuid, last_seen, platform, identity_data, collected_at,
                 device_name, computer_name, usage, catalog, location, asset_tag,
                 department, fleet, bootstrap_token) = row
                
                # Extract only the summary fields needed by the fleet page
                # Do NOT return the full raw identity blob (~50KB per device)
                summary = {}
                users_preview = []
                admin_usernames: list[str] = []
                logged_in_usernames = []
                btmdb = {}
                secure_token = {}
                platform_sso = {}
                directory_services = {}
                domain_trust = {}
                windows_hello = {}
                
                if identity_data and isinstance(identity_data, dict):
                    users = identity_data.get('users') or identity_data.get('userAccounts') or []
                    groups = identity_data.get('groups') or identity_data.get('userGroups') or []
                    logged_in_users = identity_data.get('loggedInUsers') or []
                    btmdb = identity_data.get('btmdbHealth') or identity_data.get('btmdb_health') or {}
                    directory_services = identity_data.get('directoryServices') or identity_data.get('directory_services') or {}
                    secure_token = identity_data.get('secureToken') or identity_data.get('secure_token') or identity_data.get('secureTokenUsers') or {}
                    platform_sso = identity_data.get('platformSSOUsers') or identity_data.get('platform_sso_users') or {}
                    domain_trust = identity_data.get('domainTrust') or {}
                    windows_hello = identity_data.get('windowsHello') or {}
                    session_summary = identity_data.get('sessionSummary') or {}
                    
                    admin_count = sum(1 for u in users if isinstance(u, dict) and u.get('isAdmin')) if isinstance(users, list) else 0
                    disabled_count = sum(1 for u in users if isinstance(u, dict) and u.get('disabled')) if isinstance(users, list) else 0
                    # Full list of admin usernames (preserves original case, dedup, order)
                    if isinstance(users, list):
                        _seen_admins: set[str] = set()
                        for u in users:
                            if not (isinstance(u, dict) and u.get('isAdmin')):
                                continue
                            name = u.get('username') or u.get('userName') or u.get('name')
                            if not name:
                                continue
                            key = str(name).lower()
                            if key in _seen_admins:
                                continue
                            _seen_admins.add(key)
                            admin_usernames.append(str(name))
                    
                    # Mac client emits raw osquery shape ({'user': ...}); Windows client
                    # emits the C# LoggedInUser model ({'username': ...}). Accept both.
                    unique_logged_in = list(dict.fromkeys(
                        (s.get('user') or s.get('username')) for s in logged_in_users
                        if isinstance(s, dict) and (s.get('user') or s.get('username'))
                    )) if isinstance(logged_in_users, list) else []
                    
                    summary = {
                        'totalUsers': len(users) if isinstance(users, list) else 0,
                        'adminUsers': admin_count,
                        'disabledUsers': disabled_count,
                        'groupCount': len(groups) if isinstance(groups, list) else 0,
                        'currentlyLoggedIn': len(unique_logged_in),
                    }
                    
                    # Top 5 users for preview
                    if isinstance(users, list):
                        users_preview = [
                            {
                                'username': u.get('username'),
                                'realName': u.get('realName'),
                                'isAdmin': u.get('isAdmin', False),
                                'lastLogon': u.get('lastLogon'),
                            }
                            for u in users[:5] if isinstance(u, dict)
                        ]
                    
                    logged_in_usernames = unique_logged_in[:3]
                
                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'platform': platform,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'department': department,
                    'area': department,
                    'fleet': fleet,
                    'summary': summary,
                    'users': users_preview,
                    'adminUsernames': admin_usernames,
                    'loggedInUsernames': logged_in_usernames,
                    # The full health record, not just size and status. The
                    # consumer of this field is a fleet alert that has to decide
                    # severity and say why: statusMessage is the client's own
                    # explanation, jetsamKills is the evidence the daemon is
                    # actually being killed rather than merely large, and
                    # localUserCount is what predicts growth. Projecting only two
                    # fields forced that alert to re-fetch every Mac device
                    # individually to recover the other three.
                    'btmdbHealth': {
                        'status': btmdb.get('status') or btmdb.get('health_status'),
                        'sizeMB': btmdb.get('sizeMB') or btmdb.get('size_mb'),
                        'statusMessage': (btmdb.get('statusMessage')
                                          or btmdb.get('status_message')),
                        'jetsamKillsLast7Days': (btmdb.get('jetsamKillsLast7Days')
                                                 or btmdb.get('jetsam_kills_last_7_days')),
                        'localUserCount': (btmdb.get('localUserCount')
                                           or btmdb.get('local_user_count')),
                    } if btmdb else None,
                    'secureTokenUsers': {
                        'tokenGrantedCount': (
                            secure_token.get('tokenGrantedCount')
                            if isinstance(secure_token.get('tokenGrantedCount'), int)
                            else len(secure_token.get('usersWithToken') or secure_token.get('users_with_token') or [])
                        ),
                        'tokenMissingCount': (
                            secure_token.get('tokenMissingCount')
                            if isinstance(secure_token.get('tokenMissingCount'), int)
                            else len(secure_token.get('usersWithoutToken') or secure_token.get('users_without_token') or [])
                        ),
                        'totalUsersChecked': (
                            secure_token.get('totalUsersChecked')
                            if isinstance(secure_token.get('totalUsersChecked'), int)
                            else len(secure_token.get('usersWithToken') or []) + len(secure_token.get('usersWithoutToken') or [])
                        ),
                        'usersWithToken': secure_token.get('usersWithToken') or secure_token.get('users_with_token') or [],
                        'usersWithoutToken': secure_token.get('usersWithoutToken') or secure_token.get('users_without_token') or [],
                    } if isinstance(secure_token, dict) and secure_token else None,
                    'platformSSOUsers': {
                        'deviceRegistered': platform_sso.get('deviceRegistered') or platform_sso.get('device_registered') or False,
                        'registeredUserCount': platform_sso.get('registeredUserCount', 0),
                    } if platform_sso else None,
                    'directoryServices': {
                        'activeDirectory': {
                            'bound': (directory_services.get('activeDirectory') or directory_services.get('active_directory') or {}).get('bound', False),
                            'domain': (directory_services.get('activeDirectory') or directory_services.get('active_directory') or {}).get('domain'),
                            'isDomainJoined': (directory_services.get('activeDirectory') or directory_services.get('active_directory') or {}).get('is_domain_joined') or (directory_services.get('activeDirectory') or directory_services.get('active_directory') or {}).get('isDomainJoined', False),
                        },
                        'azureAd': {
                            'joined': (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('joined') or (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('is_aad_joined') or (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('isAadJoined') or (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('is_entra_joined') or (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('isEntraJoined', False),
                            'tenantId': (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('tenant_id') or (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('tenantId'),
                            'tenantName': (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('tenant_name') or (directory_services.get('azureAd') or directory_services.get('azure_ad') or directory_services.get('entraId') or directory_services.get('entra_id') or {}).get('tenantName'),
                        },
                        'ldap': {
                            'bound': (directory_services.get('ldap') or {}).get('bound', False),
                        },
                        'workgroup': directory_services.get('workgroup'),
                    } if directory_services else None,
                    'domainTrust': {
                        'trustStatus': domain_trust.get('trustStatus'),
                    } if domain_trust else None,
                    'windowsHello': {
                        'statusDisplay': windows_hello.get('statusDisplay'),
                    } if windows_hello else None,
                    'sessionSummary': {
                        'totalSessions': session_summary.get('totalSessions') or session_summary.get('total_sessions', 0),
                        'uniqueUsers': session_summary.get('uniqueUsers') or session_summary.get('unique_users', 0),
                        'avgSessionMinutes': session_summary.get('avgSessionMinutes') or session_summary.get('avg_session_minutes', 0),
                        'medianSessionMinutes': session_summary.get('medianSessionMinutes') or session_summary.get('median_session_minutes', 0),
                    } if session_summary else None,
                    # macOS Bootstrap Token (from security module). Surface a flat
                    # status so the frontend can render it as a filter chip.
                    'bootstrapToken': ({
                        'status': (bootstrap_token or {}).get('status'),
                        'escrowed': (bootstrap_token or {}).get('escrowed'),
                        'supported': (bootstrap_token or {}).get('supported'),
                    }) if isinstance(bootstrap_token, dict) else None,
                })
            except Exception as e:
                logger.warning(f"Error processing identity for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with identity data")
        cache_set("identity", devices, _ckey)
        logger.info(f"[PERF] /api/devices/identity: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk identity: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk identity: {str(e)}")


@router.get("/profiles", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_bulk_profiles(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
):
    """
    Bulk profiles endpoint for fleet-wide MDM profile and configuration data.
    
    Returns devices with MDM profiles, configuration profiles, and management settings.
    Used by /devices/profiles page for fleet-wide profile visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    """
    try:
        _ckey = (include_archived,)
        _cached = cache_get("profiles", _ckey)
        if _cached is not None:
            return paginate(_cached, limit, offset)
        _t0 = _time.monotonic()
        logger.info("Fetching bulk profiles data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = load_sql("devices/bulk_profiles")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with profiles data")
        
        devices = []
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, profiles_data, profiles_collected_at, profiles_updated_at, device_name, computer_name, usage, catalog, location, asset_tag = row
                
                # Extract profile summary from JSONB data
                profile_list = []
                profile_count = 0
                if profiles_data and isinstance(profiles_data, dict):
                    profile_list = profiles_data.get('profiles', profiles_data.get('configurationProfiles', []))
                    if isinstance(profile_list, list):
                        profile_count = len(profile_list)
                    else:
                        profile_list = []
                
                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': profiles_collected_at.isoformat() if profiles_collected_at else None,
                    'updatedAt': profiles_updated_at.isoformat() if profiles_updated_at else None,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'profileCount': profile_count,
                    'profiles': profile_list[:50],  # Cap at 50 profiles per device for bulk response
                })
            except Exception as e:
                logger.warning(f"Error processing profiles for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with profiles data")
        cache_set("profiles", devices, _ckey)
        logger.info(f"[PERF] /api/devices/profiles: {_time.monotonic()-_t0:.3f}s ({len(devices)} devices)")
        return paginate(devices, limit, offset)
        
    except Exception as e:
        logger.error(f"Failed to get bulk profiles: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk profiles: {str(e)}")


# ---------------------------------------------------------------------------
# Fleet log sweep
# ---------------------------------------------------------------------------

def _shape_fleet_log_rows(rows, levels, needle, file_filter, platform_filter, max_lines, summarize):
    """Turn (serial, last_seen, device_name, platform, root_meta, file, lines)
    rows into per-device results and, when asked, fleet-wide message patterns.

    Pure so it can be tested without a database. Lines are classified here
    even when the query already narrowed them: the SQL pattern is a superset
    filter and this is where the requested levels are enforced.
    """
    wanted = set(levels)
    needle_l = (needle or "").strip().lower()
    file_l = (file_filter or "").strip().lower()
    platform_l = (platform_filter or "").strip().lower()

    by_device: Dict[str, Dict[str, Any]] = {}
    patterns: Dict[str, Dict[str, Any]] = {}
    level_totals = {level: 0 for level in ("error", "warning", "info", "debug")}
    scanned = set()
    truncated_devices = set()

    for serial, last_seen, device_name, platform, root_meta, file_name, lines in rows:
        scanned.add(serial)
        if platform_l:
            plat = (platform or "").lower()
            is_win = "win" in plat
            if (platform_l.startswith("win") and not is_win) or (platform_l.startswith("mac") and is_win):
                continue
        if file_l and (file_name or "").lower() != file_l:
            continue
        if isinstance(root_meta, str):
            try:
                root_meta = json.loads(root_meta)
            except Exception:
                root_meta = {}
        if isinstance(lines, str):
            try:
                lines = json.loads(lines)
            except Exception:
                lines = []
        if not isinstance(lines, list):
            continue

        for raw in lines:
            if not isinstance(raw, str):
                continue
            level = classify_line(raw)
            if level not in wanted:
                continue
            if needle_l and needle_l not in raw.lower():
                continue
            level_totals[level] += 1
            entry = by_device.get(serial)
            if entry is None:
                entry = by_device[serial] = {
                    "serialNumber": serial,
                    "deviceName": device_name or serial,
                    "platform": platform,
                    "lastSeen": last_seen.isoformat() if hasattr(last_seen, "isoformat") else last_seen,
                    "root": {
                        "name": (root_meta or {}).get("name"),
                        "path": (root_meta or {}).get("path"),
                        "newestModified": (root_meta or {}).get("newestModified"),
                        "errorCount": (root_meta or {}).get("errorCount"),
                        "warningCount": (root_meta or {}).get("warningCount"),
                    },
                    "counts": {"error": 0, "warning": 0, "info": 0, "debug": 0},
                    "lines": [],
                    "truncated": False,
                }
            entry["counts"][level] += 1
            if len(entry["lines"]) < max_lines:
                entry["lines"].append({"file": file_name, "level": level, "line": raw})
            else:
                entry["truncated"] = True
                truncated_devices.add(serial)
            if summarize:
                key = normalize_message(raw)
                pat = patterns.get(key)
                if pat is None:
                    pat = patterns[key] = {"message": key, "level": level, "lines": 0, "devices": set(), "sample": raw[:400]}
                pat["lines"] += 1
                pat["devices"].add(serial)

    results = sorted(by_device.values(), key=lambda d: (-(d["counts"]["error"]), -(d["counts"]["warning"]), d["serialNumber"]))
    shaped_patterns = None
    if summarize:
        shaped_patterns = sorted(
            (
                {"message": p["message"], "level": p["level"], "lines": p["lines"], "devices": len(p["devices"]), "sample": p["sample"]}
                for p in patterns.values()
            ),
            key=lambda p: (-p["devices"], -p["lines"], p["message"]),
        )[:200]
    return {
        "devicesScanned": len(scanned),
        "devicesMatched": len(results),
        "devicesTruncated": len(truncated_devices),
        "lineTotals": level_totals,
        "results": results,
        "patterns": shaped_patterns,
    }


@router.get("/management/logs/{tool}", dependencies=[Depends(verify_authentication)], tags=["fleet"])
def get_fleet_log_lines(
    tool: str,
    levels: Optional[str] = Query(default=None, description="Comma-separated levels to return: error, warning, info, debug (default error,warning)"),
    platform: Optional[str] = Query(default=None, description="windows or macos"),
    file: Optional[str] = Query(default=None, description="Only lines from this file within the root, e.g. run.log"),
    q: Optional[str] = Query(default=None, description="Case-insensitive substring the line must contain"),
    summary: bool = Query(default=False, description="Also return fleet-wide message patterns (same fault on many devices counted once)"),
    max_lines_per_device: int = Query(default=200, ge=1, le=5000, alias="maxLinesPerDevice"),
    include_archived: bool = Query(default=False, alias="includeArchived"),
    limit: Optional[int] = Query(default=None, ge=1, le=5000, description="Maximum devices to return"),
    offset: int = Query(default=0, ge=0),
):
    """
    Sweep one management tool's log tails across the whole fleet.

    ``tool`` is a log root key (installs, bootstrap, reports, state, encryption,
    users, utilities, notifications, mdm, installer). Every device's tails for
    that root are read straight from the management module in Postgres; when
    ``levels`` excludes info the narrowing happens in the query, so a sweep for
    errors and warnings ships only those lines. Each result carries the device,
    the root's facts and the matching lines with their file and level;
    ``summary=true`` adds the message patterns behind them, normalised so the
    same fault on many devices is one row with a device count.
    """
    try:
        wanted = parse_levels(levels)
    except ValueError as bad:
        raise HTTPException(status_code=400, detail=f"Unknown level '{bad}'. Use error, warning, info, debug.")

    pattern = sql_pattern_for_levels(wanted)
    try:
        _t0 = _time.monotonic()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            load_sql("devices/fleet_log_lines"),
            {"tool": tool, "pattern": pattern, "include_archived": include_archived},
        )
        rows = cursor.fetchall()
        conn.close()
        shaped = _shape_fleet_log_rows(rows, wanted, q, file, platform, max_lines_per_device, summary)
        logger.info(
            f"Fleet log sweep {tool} levels={','.join(wanted)}: {len(rows)} tails, "
            f"{shaped['devicesMatched']}/{shaped['devicesScanned']} devices in {_time.monotonic() - _t0:.1f}s"
        )
        results = paginate(shaped["results"], limit, offset)
        return {
            "tool": tool,
            "levels": wanted,
            "devicesScanned": shaped["devicesScanned"],
            "devicesMatched": shaped["devicesMatched"],
            "devicesTruncated": shaped["devicesTruncated"],
            "lineTotals": shaped["lineTotals"],
            "results": results,
            "patterns": shaped["patterns"],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Fleet log sweep failed for {tool}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to sweep logs: {str(e)}")

