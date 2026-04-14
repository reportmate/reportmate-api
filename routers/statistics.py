"""Fleet analytics, dashboard data, and reporting endpoints."""

import json
import time as _time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from dependencies import (
    cache_get, cache_set, get_db_connection, load_sql, logger,
    verify_authentication, infer_platform,
)

router = APIRouter(tags=["statistics"])

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
    conn = None
    try:
        _t0 = _time.monotonic()

        # Check in-memory cache before hitting the database
        _ckey = (include_archived, events_limit)
        _cached = cache_get("dashboard", _ckey)
        if _cached is not None:
            return _cached

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

        # === INSTALL STATS - single-pass correlated subqueries (one scan of installs) ===
        install_stats = {
            "devicesWithErrors": 0, "devicesWithWarnings": 0,
            "totalErrorItems": 0, "totalWarningItems": 0,
            "winErrorItems": 0, "winWarningItems": 0,
            "macErrorItems": 0, "macWarningItems": 0,
            "hasInstallData": False
        }
        try:
            cursor.execute("""
                SELECT
                    -- Windows (Cimian) errors
                    COALESCE(SUM(CASE WHEN LOWER(COALESCE(d.platform,'')) LIKE '%%windows%%'
                        THEN (SELECT COUNT(*) FROM jsonb_array_elements(COALESCE(i.data->'cimian'->'items','[]'::jsonb)) item
                              WHERE LOWER(item->>'currentStatus') ~ '(error|failed|problem|install-error)')
                        ELSE 0 END), 0) AS win_errors,
                    -- Windows (Cimian) warnings
                    COALESCE(SUM(CASE WHEN LOWER(COALESCE(d.platform,'')) LIKE '%%windows%%'
                        THEN (SELECT COUNT(*) FROM jsonb_array_elements(COALESCE(i.data->'cimian'->'items','[]'::jsonb)) item
                              WHERE LOWER(item->>'currentStatus') ~ '(warning|needs-attention)')
                        ELSE 0 END), 0) AS win_warnings,
                    -- macOS (Munki) errors
                    COALESCE(SUM(CASE WHEN LOWER(COALESCE(d.platform,'')) LIKE '%%mac%%'
                        THEN (SELECT COUNT(*) FROM jsonb_array_elements(COALESCE(i.data->'munki'->'items','[]'::jsonb)) item
                              WHERE LOWER(item->>'status') ~ '(error|failed)')
                        ELSE 0 END), 0) AS mac_errors,
                    -- macOS (Munki) warnings
                    COALESCE(SUM(CASE WHEN LOWER(COALESCE(d.platform,'')) LIKE '%%mac%%'
                        THEN (SELECT COUNT(*) FROM jsonb_array_elements(COALESCE(i.data->'munki'->'items','[]'::jsonb)) item
                              WHERE LOWER(item->>'status') LIKE '%%warning%%')
                        ELSE 0 END), 0) AS mac_warnings,
                    COUNT(*) > 0 AS has_data
                FROM installs i
                INNER JOIN devices d ON d.serial_number = i.device_id
                WHERE d.archived = FALSE
                  AND (
                      jsonb_typeof(i.data->'cimian'->'items') = 'array'
                      OR jsonb_typeof(i.data->'munki'->'items') = 'array'
                  )
            """)
            stats_row = cursor.fetchone()
            if stats_row:
                win_errors   = int(stats_row[0] or 0)
                win_warnings = int(stats_row[1] or 0)
                mac_errors   = int(stats_row[2] or 0)
                mac_warnings = int(stats_row[3] or 0)
                install_stats["winErrorItems"]    = win_errors
                install_stats["winWarningItems"]  = win_warnings
                install_stats["macErrorItems"]    = mac_errors
                install_stats["macWarningItems"]  = mac_warnings
                install_stats["totalErrorItems"]  = win_errors + mac_errors
                install_stats["totalWarningItems"] = win_warnings + mac_warnings
                install_stats["hasInstallData"]   = bool(stats_row[4])
        except Exception as stats_error:
            logger.warning(f"Failed to calculate install stats: {stats_error}")

        _t6 = _time.monotonic()
        logger.info(f"[DASHBOARD PERF] install stats: {_t6-_t5:.3f}s (errors={install_stats['totalErrorItems']}, warnings={install_stats['totalWarningItems']})")

        # === EVENTS (per-type diverse fetch via window function) ===
        # A plain ORDER BY timestamp returns 100% info events because every
        # module collection creates one.  Window function picks top-N per type
        # so success/warning/error/system are always represented.
        events = []
        try:
            cursor.execute("""
                WITH ranked AS (
                    SELECT e.id, e.device_id, e.event_type, e.message, e.timestamp,
                           ROW_NUMBER() OVER (
                               PARTITION BY e.event_type
                               ORDER BY e.timestamp DESC
                           ) AS rn
                    FROM events e
                    WHERE e.event_type IN ('success','warning','error','system','info')
                )
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
                FROM ranked r
                LEFT JOIN inventory i ON r.device_id = i.device_id
                LEFT JOIN system s ON r.device_id = s.device_id
                WHERE r.rn <= %s
                ORDER BY r.timestamp DESC
            """, (events_limit,))

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

        # Store in cache
        cache_set("dashboard", result, _ckey)

        return result
        
    except Exception as e:
        logger.error(f"Failed to get dashboard data: {e}")
        if conn:
            conn.close()
        raise HTTPException(status_code=500, detail=f"Failed to retrieve dashboard data: {str(e)}")

@router.get("/stats/installs", dependencies=[Depends(verify_authentication)], tags=["statistics"])
async def get_install_stats():
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
        
        # Single-pass aggregate: counts errors, warnings, and device-level stats
        cursor.execute("""
            SELECT
                COUNT(DISTINCT CASE WHEN device_errors > 0 THEN i.device_id END) AS devices_with_errors,
                COUNT(DISTINCT CASE WHEN device_warnings > 0 AND device_errors = 0 THEN i.device_id END) AS devices_with_warnings,
                COALESCE(SUM(device_errors), 0) AS total_errors,
                COALESCE(SUM(device_warnings), 0) AS total_warnings
            FROM installs i
            INNER JOIN devices d ON d.serial_number = i.device_id AND d.archived = FALSE
            CROSS JOIN LATERAL (
                SELECT
                    (SELECT COUNT(*) FROM jsonb_array_elements(COALESCE(i.data->'cimian'->'items','[]'::jsonb)) item
                     WHERE LOWER(item->>'currentStatus') IN ('failed','error','needs_reinstall')
                        OR LOWER(item->>'mappedStatus') IN ('failed','error')
                    ) AS device_errors,
                    (SELECT COUNT(*) FROM jsonb_array_elements(COALESCE(i.data->'cimian'->'items','[]'::jsonb)) item
                     WHERE LOWER(item->>'currentStatus') LIKE '%%pending%%'
                        OR LOWER(item->>'currentStatus') LIKE '%%update%%'
                        OR LOWER(item->>'currentStatus') = 'warning'
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
