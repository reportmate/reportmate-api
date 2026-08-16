"""Fleet analytics, dashboard data, and reporting endpoints."""

import asyncio
import json
import time as _time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from starlette.concurrency import run_in_threadpool

from dependencies import (
    cache_get, cache_set, get_db_connection, load_sql, logger,
    verify_authentication, infer_platform,
)

router = APIRouter(tags=["statistics"])

# Single-flight locks per dashboard cache key: when the cache is cold, only
# one request recomputes; concurrent requests await it and read the cache.
_dashboard_locks = defaultdict(asyncio.Lock)

@router.get("/dashboard", dependencies=[Depends(verify_authentication)], tags=["statistics"])
async def get_dashboard_data(
    events_limit: int = Query(default=200, ge=1, le=500, alias="eventsLimit"),
    include_archived: bool = Query(default=False, alias="includeArchived")
):
    """
    Consolidated dashboard endpoint - fetches all dashboard data in a single API call.
    
    Combines:
    - All devices with full OS data (eliminates need for individual device fetches)
    - Install statistics (devicesWithErrors, devicesWithWarnings, totalFailedInstalls)
    - Recent events (for dashboard event widget)
    
    This eliminates 10+ separate API calls from the dashboard, dramatically improving load time.
    
    Returns:
        {
            "devices": [...],           # Full device list with OS data
            "totalDevices": int,        # Total device count
            "installStats": {...},      # Install error/warning counts
            "events": [...],            # Recent events for widget
            "totalEvents": int,         # Total recent events count
            "lastUpdated": str          # ISO8601 timestamp
        }
    """
    _ckey = (include_archived, events_limit)
    _cached = cache_get("dashboard", _ckey)
    if _cached is not None:
        return _cached

    async with _dashboard_locks[_ckey]:
        # Re-check after waiting: the holder that just released the lock has
        # already stored a fresh result.
        _cached = cache_get("dashboard", _ckey)
        if _cached is not None:
            return _cached

        # The compute is synchronous DB work; run it off the event loop so a
        # multi-second recompute cannot stall ingest and health traffic.
        result = await run_in_threadpool(
            _compute_dashboard_data, events_limit, include_archived
        )
        cache_set("dashboard", result, _ckey)
        return result


def _compute_dashboard_data(events_limit: int, include_archived: bool):
    conn = None
    try:
        _t0 = _time.monotonic()

        conn = get_db_connection()
        cursor = conn.cursor()
        
        archive_filter = "" if include_archived else "WHERE archived = FALSE"

        # === STEP 1: Devices table only (no JOINs = fast) ===
        _t1 = _time.monotonic()
        cursor.execute(f"""
            SELECT id, device_id, serial_number, name, os, os_name, os_version,
                   last_seen, archived, created_at, platform
            FROM devices {archive_filter}
            ORDER BY last_seen DESC NULLS LAST
        """)
        device_rows = cursor.fetchall()
        _t2 = _time.monotonic()
        logger.info(f"[DASHBOARD PERF] devices query: {_t2-_t1:.3f}s ({len(device_rows)} devices)")

        # === STEP 2: Batch-fetch inventory data (single query, Python dict lookup) ===
        inv_lookup = {}
        try:
            cursor.execute("SELECT device_id, data FROM inventory")
            for inv_row in cursor.fetchall():
                inv_lookup[inv_row[0]] = inv_row[1]
        except Exception as inv_err:
            logger.warning(f"Failed to batch-fetch inventory: {inv_err}")
        _t3 = _time.monotonic()
        logger.info(f"[DASHBOARD PERF] inventory batch: {_t3-_t2:.3f}s ({len(inv_lookup)} rows)")

        # === STEP 3: Batch-fetch hardware data for name fallback (devices without inventory) ===
        hw_lookup = {}
        try:
            cursor.execute("SELECT device_id, data->'system'->>'computer_name', data->'system'->>'hostname' FROM hardware")
            for hw_row in cursor.fetchall():
                hw_name = hw_row[1] or hw_row[2]
                if hw_name and hw_name.strip():
                    hw_lookup[hw_row[0]] = hw_name.strip()
        except Exception as hw_err:
            logger.warning(f"Failed to batch-fetch hardware names: {hw_err}")
        _t4 = _time.monotonic()
        logger.info(f"[DASHBOARD PERF] hardware name batch: {_t4-_t3:.3f}s ({len(hw_lookup)} rows)")

        # === STEP 4: Build device list in Python (fast dict lookups) ===
        now_utc = datetime.now(timezone.utc)
        devices = []
        for row in device_rows:
            (db_id, device_id, serial_number, device_name, os_val, os_name_db,
             os_version_db, last_seen, archived, created_at, stored_platform) = row

            final_os_name = os_name_db or os_val or "Unknown"
            final_os_version = os_version_db or ""

            # Platform from stored column or inferred from OS name
            platform = stored_platform or (
                "Windows" if "windows" in (final_os_name or "").lower()
                else "macOS" if "mac" in (final_os_name or "").lower()
                else "Unknown"
            )

            # Status from last_seen
            status = "online"
            if last_seen:
                ls = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
                diff_s = (now_utc - ls).total_seconds()
                if diff_s > 86400:
                    status = "offline"
                elif diff_s > 3600:
                    status = "idle"

            # Inventory from batch lookup
            inv_device_name = device_name
            inv_catalog = inv_usage = inv_department = inv_location = None
            inv_raw = inv_lookup.get(serial_number)
            if inv_raw:
                try:
                    inventory = inv_raw if isinstance(inv_raw, dict) else json.loads(inv_raw)
                    inv_device_name = inventory.get("deviceName") or device_name
                    inv_catalog = inventory.get("catalog")
                    inv_usage = inventory.get("usage")
                    inv_department = inventory.get("department")
                    inv_location = inventory.get("location")
                except Exception:
                    pass

            # Fall back to hardware.system.computer_name if name is still Unknown/serial
            if not inv_device_name or inv_device_name == "Unknown" or inv_device_name == serial_number:
                hw_name = hw_lookup.get(serial_number)
                if hw_name:
                    inv_device_name = hw_name

            os_info = {
                "name": final_os_name,
                "version": final_os_version
            }

            modules_obj = {"system": {"operatingSystem": os_info}}
            resolved_name = inv_device_name if (inv_device_name and inv_device_name != "Unknown" and inv_device_name != serial_number) else None
            if any([resolved_name, inv_catalog, inv_usage, inv_department, inv_location]):
                modules_obj["inventory"] = {
                    "deviceName": resolved_name,
                    "catalog": inv_catalog, "usage": inv_usage,
                    "department": inv_department, "location": inv_location
                }

            devices.append({
                "id": db_id,
                "deviceId": device_id,
                "serialNumber": serial_number,
                "name": inv_device_name or serial_number,
                "platform": platform,
                "osName": final_os_name,
                "osVersion": final_os_version,
                "status": status,
                "archived": archived or False,
                "lastSeen": last_seen.isoformat() if last_seen else None,
                "createdAt": created_at.isoformat() if created_at else None,
                "modules": modules_obj
            })

        _t5 = _time.monotonic()
        logger.info(f"[DASHBOARD PERF] device transform: {_t5-_t4:.3f}s")

        # === INSTALL STATS - plain aggregate over precomputed counters ===
        # The per-device error/warning counts are maintained at ingest time
        # (and backfilled by migration 0003), so this is a cheap column scan
        # over ~1 row per device instead of expanding every install item's
        # JSONB per request. Item totals and device counts stay split by
        # platform, mirroring the /devices/installs page categorization.
        install_stats = {
            "devicesWithErrors": 0, "devicesWithWarnings": 0,
            "winDevicesWithErrors": 0, "winDevicesWithWarnings": 0,
            "macDevicesWithErrors": 0, "macDevicesWithWarnings": 0,
            "totalErrorItems": 0, "totalWarningItems": 0,
            "winErrorItems": 0, "winWarningItems": 0,
            "macErrorItems": 0, "macWarningItems": 0,
            "hasInstallData": False
        }
        try:
            cursor.execute("""
                WITH device_install AS (
                    SELECT
                        d.serial_number,
                        LOWER(COALESCE(d.platform, '')) AS plat,
                        i.cimian_errors,
                        i.cimian_warnings,
                        i.munki_errors,
                        i.munki_warnings
                    FROM installs i
                    INNER JOIN devices d ON d.serial_number = i.device_id
                    WHERE d.archived = FALSE
                )
                SELECT
                    -- Item totals (per platform)
                    COALESCE(SUM(CASE WHEN plat ~ 'windows' THEN cimian_errors   ELSE 0 END), 0) AS win_error_items,
                    COALESCE(SUM(CASE WHEN plat ~ 'windows' THEN cimian_warnings ELSE 0 END), 0) AS win_warning_items,
                    COALESCE(SUM(CASE WHEN plat ~ 'mac'     THEN munki_errors    ELSE 0 END), 0) AS mac_error_items,
                    COALESCE(SUM(CASE WHEN plat ~ 'mac'     THEN munki_warnings  ELSE 0 END), 0) AS mac_warning_items,
                    -- Device counts (per platform)
                    COUNT(DISTINCT CASE WHEN plat ~ 'windows' AND cimian_errors   > 0 THEN serial_number END) AS win_devices_errors,
                    COUNT(DISTINCT CASE WHEN plat ~ 'windows' AND cimian_warnings > 0 THEN serial_number END) AS win_devices_warnings,
                    COUNT(DISTINCT CASE WHEN plat ~ 'mac'     AND munki_errors    > 0 THEN serial_number END) AS mac_devices_errors,
                    COUNT(DISTINCT CASE WHEN plat ~ 'mac'     AND munki_warnings  > 0 THEN serial_number END) AS mac_devices_warnings,
                    -- Device counts (cross-platform)
                    COUNT(DISTINCT CASE
                        WHEN (plat ~ 'windows' AND cimian_errors > 0)
                          OR (plat ~ 'mac'     AND munki_errors  > 0)
                        THEN serial_number END) AS devices_errors,
                    COUNT(DISTINCT CASE
                        WHEN (plat ~ 'windows' AND cimian_warnings > 0)
                          OR (plat ~ 'mac'     AND munki_warnings  > 0)
                        THEN serial_number END) AS devices_warnings,
                    COUNT(*) > 0 AS has_data
                FROM device_install
            """)
            stats_row = cursor.fetchone()
            if stats_row:
                win_err_items   = int(stats_row[0] or 0)
                win_warn_items  = int(stats_row[1] or 0)
                mac_err_items   = int(stats_row[2] or 0)
                mac_warn_items  = int(stats_row[3] or 0)
                install_stats["winErrorItems"]        = win_err_items
                install_stats["winWarningItems"]      = win_warn_items
                install_stats["macErrorItems"]        = mac_err_items
                install_stats["macWarningItems"]      = mac_warn_items
                install_stats["totalErrorItems"]      = win_err_items + mac_err_items
                install_stats["totalWarningItems"]    = win_warn_items + mac_warn_items
                install_stats["winDevicesWithErrors"]   = int(stats_row[4] or 0)
                install_stats["winDevicesWithWarnings"] = int(stats_row[5] or 0)
                install_stats["macDevicesWithErrors"]   = int(stats_row[6] or 0)
                install_stats["macDevicesWithWarnings"] = int(stats_row[7] or 0)
                install_stats["devicesWithErrors"]      = int(stats_row[8] or 0)
                install_stats["devicesWithWarnings"]    = int(stats_row[9] or 0)
                install_stats["hasInstallData"]         = bool(stats_row[10])
        except Exception as stats_error:
            logger.warning(f"Failed to calculate install stats: {stats_error}")

        _t6 = _time.monotonic()
        logger.info(f"[DASHBOARD PERF] install stats: {_t6-_t5:.3f}s (devices_errors={install_stats['devicesWithErrors']}, devices_warnings={install_stats['devicesWithWarnings']})")

        # === EVENTS (per-type diverse fetch, bounded index scans) ===
        # A plain ORDER BY timestamp returns 100% info events because every
        # module collection creates one, so top-N is taken per type to keep
        # success/warning/error/system represented. Each branch is a bounded
        # scan of idx_events_type_timestamp_desc (migration 0003) -- the
        # previous window function sorted the entire events table (~1.4M
        # rows) on every call.
        events = []
        try:
            cursor.execute("""
                SELECT r.id, r.device_id, r.event_type, r.message, r.timestamp,
                       COALESCE(
                           NULLIF(NULLIF(i.data->>'deviceName',''),'Unknown'),
                           NULLIF(NULLIF(i.data->>'device_name',''),'Unknown')
                       ) AS device_name,
                       COALESCE(i.data->>'asset_tag', i.data->>'assetTag') AS asset_tag,
                       COALESCE(
                           s.data->'operating_system'->>'name',
                           s.data->'operatingSystem'->>'name',
                           i.data->>'platform'
                       ) AS platform
                FROM (
                    (SELECT id, device_id, event_type, message, timestamp
                     FROM events WHERE event_type = 'success'
                     ORDER BY timestamp DESC LIMIT %s)
                    UNION ALL
                    (SELECT id, device_id, event_type, message, timestamp
                     FROM events WHERE event_type = 'warning'
                     ORDER BY timestamp DESC LIMIT %s)
                    UNION ALL
                    (SELECT id, device_id, event_type, message, timestamp
                     FROM events WHERE event_type = 'error'
                     ORDER BY timestamp DESC LIMIT %s)
                    UNION ALL
                    (SELECT id, device_id, event_type, message, timestamp
                     FROM events WHERE event_type = 'system'
                     ORDER BY timestamp DESC LIMIT %s)
                    UNION ALL
                    (SELECT id, device_id, event_type, message, timestamp
                     FROM events WHERE event_type = 'info'
                     ORDER BY timestamp DESC LIMIT %s)
                ) r
                LEFT JOIN inventory i ON r.device_id = i.device_id
                LEFT JOIN system s ON r.device_id = s.device_id
                ORDER BY r.timestamp DESC
            """, (events_limit,) * 5)

            for row in cursor.fetchall():
                event_id, device_id, event_type, message, timestamp, device_name, asset_tag, platform = row
                ev_name = device_name or device_id
                if not ev_name or ev_name == device_id:
                    inv = inv_lookup.get(device_id)
                    if inv:
                        try:
                            inv_d = inv if isinstance(inv, dict) else json.loads(inv)
                            ev_name = inv_d.get("deviceName") or device_id
                        except Exception:
                            pass
                events.append({
                    "id": event_id, "device": device_id,
                    "deviceName": ev_name, "kind": event_type,
                    "message": message,
                    "ts": timestamp.isoformat() if timestamp else None,
                    "serialNumber": device_id, "eventType": event_type,
                    "timestamp": timestamp.isoformat() if timestamp else None,
                    "assetTag": asset_tag,
                    "platform": platform,
                })
        except Exception as events_error:
            logger.warning(f"Failed to get events for dashboard: {events_error}")

        _t7 = _time.monotonic()
        logger.info(f"[DASHBOARD PERF] events: {_t7-_t6:.3f}s ({len(events)} events)")
        logger.info(f"[DASHBOARD PERF] TOTAL: {_t7-_t0:.3f}s ({len(devices)} devices)")

        conn.close()

        result = {
            "devices": devices,
            "totalDevices": len(devices),
            "installStats": install_stats,
            "events": events,
            "totalEvents": len(events),
            "lastUpdated": datetime.now(timezone.utc).isoformat()
        }

        # Caching happens in the async endpoint wrapper (under the
        # single-flight lock), not here.
        return result
        
    except Exception as e:
        logger.error(f"Failed to get dashboard data: {e}")
        if conn:
            conn.close()
        raise HTTPException(status_code=500, detail=f"Failed to retrieve dashboard data: {str(e)}")

@router.get("/stats/installs", dependencies=[Depends(verify_authentication)], tags=["statistics"])
def get_install_stats():
    """
    Get aggregated install statistics for dashboard widgets.
    
    Returns pre-computed counts from Cimian installs data without transferring
    full installs module data for all devices. Optimized for dashboard performance.
    
    Returns:
        {
            "devicesWithErrors": int,      // Devices with failed/needs_reinstall
            "devicesWithWarnings": int,    // Devices with pending/updates (no errors)
            "totalFailedInstalls": int,    // Total count of failed installs
            "totalWarnings": int,          // Total count of warnings
            "lastUpdated": str            // ISO8601 timestamp
        }
    """
    try:
        _cached = cache_get("stats_installs")
        if _cached is not None:
            return _cached

        _t0 = _time.monotonic()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Single-pass aggregate: counts errors, warnings, and device-level stats.
        # Covers both Cimian (Windows) item statuses and Munki (macOS) run-level
        # messages. For Munki, the Mac client keeps unattributable messages in
        # munki.errors/warnings strings — if we only read item statuses, Macs with
        # preflight failures or other run-level issues contribute nothing to the
        # dashboard (they were silently invisible before this query was extended).
        cursor.execute("""
            SELECT
                COUNT(DISTINCT CASE WHEN device_errors > 0 THEN i.device_id END) AS devices_with_errors,
                COUNT(DISTINCT CASE WHEN device_warnings > 0 THEN i.device_id END) AS devices_with_warnings,
                COALESCE(SUM(device_errors), 0) AS total_errors,
                COALESCE(SUM(device_warnings), 0) AS total_warnings
            FROM installs i
            INNER JOIN devices d ON d.serial_number = i.device_id AND d.archived = FALSE
            CROSS JOIN LATERAL (
                SELECT
                    GREATEST(
                        (SELECT COUNT(*) FROM jsonb_array_elements(COALESCE(i.data->'cimian'->'items','[]'::jsonb)) item
                         WHERE LOWER(item->>'currentStatus') IN ('failed','error','needs_reinstall')
                            OR LOWER(item->>'mappedStatus') IN ('failed','error')
                        ),
                        (SELECT COUNT(*) FROM jsonb_array_elements(COALESCE(i.data->'munki'->'items','[]'::jsonb)) item
                         WHERE LOWER(COALESCE(item->>'status', item->>'currentStatus','')) IN ('install_failed','install-failed','failed','error')
                        ),
                        (SELECT COUNT(*) FROM regexp_split_to_table(COALESCE(i.data->'munki'->>'errors',''), ';') s
                         WHERE btrim(s) <> ''
                        )
                    ) AS device_errors,
                    (
                        (SELECT COUNT(*) FROM jsonb_array_elements(COALESCE(i.data->'cimian'->'items','[]'::jsonb)) item
                         WHERE LOWER(item->>'currentStatus') LIKE '%%pending%%'
                            OR LOWER(item->>'currentStatus') LIKE '%%update%%'
                            OR LOWER(item->>'currentStatus') = 'warning'
                        )
                        +
                        GREATEST(
                            (SELECT COUNT(*) FROM jsonb_array_elements(COALESCE(i.data->'munki'->'items','[]'::jsonb)) item
                             WHERE LENGTH(COALESCE(item->>'lastWarning','')) > 0
                            ),
                            (SELECT COUNT(*) FROM regexp_split_to_table(COALESCE(i.data->'munki'->>'warnings',''), ';') s
                             WHERE btrim(s) <> ''
                            )
                            +
                            (SELECT COUNT(*) FROM regexp_split_to_table(COALESCE(i.data->'munki'->>'problemInstalls',''), ',') s
                             WHERE btrim(s) <> ''
                            )
                        )
                    ) AS device_warnings
            ) counts
        """)
        row = cursor.fetchone()
        conn.close()
        
        result = {
            "devicesWithErrors": int(row[0] or 0),
            "devicesWithWarnings": int(row[1] or 0),
            "totalFailedInstalls": int(row[2] or 0),
            "totalWarnings": int(row[3] or 0),
            "lastUpdated": datetime.now(timezone.utc).isoformat()
        }
        
        _t1 = _time.monotonic()
        logger.info(f"[STATS/INSTALLS PERF] {_t1-_t0:.3f}s ({result['devicesWithErrors']} errors, {result['devicesWithWarnings']} warnings)")
        cache_set("stats_installs", result)
        return result
        
    except Exception as e:
        logger.error(f"Failed to get install stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve install statistics: {str(e)}")
