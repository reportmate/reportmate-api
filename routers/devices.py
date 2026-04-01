"""
ReportMate API - Device endpoints router.

Handles all device-related operations:
- List all devices
- Individual device detail
- Device installs run log
- Device events
- Fast info tab data
- Progressive module loading
- Device application usage history
"""

import json
import time as _time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from dependencies import (
    logger,
    get_db_connection,
    verify_authentication,
    cache_get,
    cache_set,
    load_sql,
    paginate,
    infer_platform,
    build_os_summary,
    DevicesResponse,
    VALID_MODULE_NAMES,
    DeviceInfo,
    ErrorResponse,
)

router = APIRouter()


@router.get("/devices", response_model=DevicesResponse, dependencies=[Depends(verify_authentication)], tags=["devices"])
async def get_all_devices(
    limit: Optional[int] = Query(default=None, ge=1, le=1000, description="Maximum devices to return"),
    offset: int = Query(default=0, ge=0, description="Number of devices to skip for pagination"),
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices")
):
    """
    List all devices with standardized identification and lightweight module payloads.
    
    By default, archived devices are excluded from results.
    Use includeArchived=true to show archived devices.
    
    **Query Parameters:**
    - limit: Maximum devices to return (1-1000, default all)
    - offset: Pagination offset
    - includeArchived: Include archived devices (default false)
    
    **Response:**
    - devices: Array of device objects
    - total: Total device count
    - offset: Current pagination offset
    """
    conn = None
    try:
        _t0 = _time.monotonic()
        _ckey = (include_archived, limit, offset)
        _cached = cache_get("devices", _ckey)
        if _cached is not None:
            return _cached

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build archive filter before count query
        archive_filter = "" if include_archived else "WHERE archived = FALSE"

        total_devices = 0
        try:
            cursor.execute(f"SELECT COUNT(*) FROM devices {archive_filter}")
            total_result = cursor.fetchone()
            if total_result and total_result[0] is not None:
                total_devices = int(total_result[0])
        except Exception as count_error:
            logger.warning(f"Failed to get total device count: {count_error}")

        # Build archive filter for main query
        archive_filter_where = "" if include_archived else "WHERE d.archived = FALSE"
        
        query = f"""
        SELECT 
            d.id,
            d.device_id,
            d.name,
            d.serial_number, 
            d.last_seen,
            d.created_at,
            d.status,
            d.model,
            d.manufacturer,
            d.os,
            d.os_name,
            d.os_version,
            d.archived,
            d.archived_at,
            d.platform,
            i.data as inventory_data,
            n.data as network_data,
            s.data->'operatingSystem'->>'name' as system_os_name
        FROM devices d
        LEFT JOIN inventory i ON i.device_id = d.serial_number
        LEFT JOIN network n ON n.device_id = d.serial_number
        LEFT JOIN system s ON s.device_id = d.serial_number
        {archive_filter_where}
        ORDER BY COALESCE(d.serial_number, d.device_id) ASC
        """

        params: List[Any] = []
        if limit is not None:
            query += " LIMIT %s"
            params.append(limit)
        if offset and offset > 0:
            query += " OFFSET %s"
            params.append(offset)

        if params:
            cursor.execute(query, tuple(params))
        else:
            cursor.execute(query)

        rows = cursor.fetchall()

        devices: List[Dict[str, Any]] = []

        for row in rows:
            (
                device_id,
                device_uuid,
                device_name,
                serial_number,
                last_seen,
                created_at,
                status,
                _model,
                _manufacturer,
                os,
                os_name,
                os_version,
                archived,
                archived_at,
                platform,
                inventory_data_raw,
                network_data_raw,
                system_os_name,
            ) = row

            serial = serial_number or str(device_id)

            os_summary = build_os_summary(os_name or os, os_version)
            # Priority: system.operatingSystem.name (kernel) > stored platform > inferred
            device_platform = system_os_name or platform or infer_platform(os_name or os)

            inventory_summary: Optional[Dict[str, Any]] = None
            device_display_name = device_name

            # Process inventory data from JOIN
            if inventory_data_raw:
                try:
                    raw_inventory = inventory_data_raw
                    if isinstance(raw_inventory, str):
                        raw_inventory = json.loads(raw_inventory)
                    if isinstance(raw_inventory, list) and raw_inventory:
                        raw_inventory = raw_inventory[0]
                    if isinstance(raw_inventory, dict):
                        # Map snake_case to camelCase (Windows client uses snake_case)
                        normalized = {
                            "deviceName": raw_inventory.get("device_name") or raw_inventory.get("deviceName"),
                            "assetTag": raw_inventory.get("asset_tag") or raw_inventory.get("assetTag"),
                            "serialNumber": raw_inventory.get("serial_number") or raw_inventory.get("serialNumber"),
                            "location": raw_inventory.get("location"),
                            "department": raw_inventory.get("department"),
                            "usage": raw_inventory.get("usage"),
                            "catalog": raw_inventory.get("catalog"),
                            "owner": raw_inventory.get("owner"),
                        }
                        # Filter out None/"" values
                        summary = {k: v for k, v in normalized.items() if v not in (None, "")}
                        if summary:
                            inventory_summary = summary
                            device_display_name = summary.get("deviceName", device_display_name)
                except Exception as inventory_error:
                    logger.warning(f"Failed to parse inventory data for {serial}: {inventory_error}")

            # Process network data to extract hostname
            hostname: Optional[str] = None
            network_summary: Optional[Dict[str, Any]] = None
            if network_data_raw:
                logger.info(f"Found network data for device {serial}")
                try:
                    raw_network = network_data_raw
                    if isinstance(raw_network, str):
                        raw_network = json.loads(raw_network)
                    if isinstance(raw_network, list) and raw_network:
                        raw_network = raw_network[0]
                    if isinstance(raw_network, dict):
                        hostname = raw_network.get("hostname")
                        logger.info(f"Extracted hostname for {serial}: {hostname}")
                        # Build network summary with key fields
                        network_summary = {
                            "hostname": hostname,
                        }
                except Exception as network_error:
                    logger.warning(f"Failed to parse network data for {serial}: {network_error}")
            else:
                logger.debug(f"No network data found for device {serial}")

            if not device_display_name:
                device_display_name = serial

            device_info: Dict[str, Any] = {
                "serialNumber": serial,
                "deviceId": device_uuid or str(device_id),
                "deviceName": device_display_name,
                "name": device_display_name,
                "hostname": hostname,  # Include hostname at top level for search
                "lastSeen": last_seen.isoformat() if last_seen else None,
                "createdAt": created_at.isoformat() if created_at else None,
                "registrationDate": created_at.isoformat() if created_at else None,
                "status": status,
                "archived": archived,
                "archivedAt": archived_at.isoformat() if archived_at else None,
                "platform": device_platform,
                "osName": os_name or os,
                "osVersion": os_version,
                "lastEventTime": last_seen.isoformat() if last_seen else None,
                "totalEvents": 0,
            }
            
            # DEBUG: Log what we're actually adding to device_info
            logger.info(f"🔍 [HOSTNAME_TEST_v2] Device {serial}: hostname_var={hostname}, network_summary_exists={bool(network_summary)}")

            if inventory_summary:
                device_info["inventory"] = inventory_summary
                device_info["assetTag"] = inventory_summary.get("assetTag")
                device_info["usage"] = inventory_summary.get("usage")
                device_info["catalog"] = inventory_summary.get("catalog")
                device_info["department"] = inventory_summary.get("department")
                device_info["location"] = inventory_summary.get("location")
                device_info["owner"] = inventory_summary.get("owner")

            modules_payload: Dict[str, Any] = {}
            if inventory_summary:
                modules_payload["inventory"] = inventory_summary
            if os_summary:
                modules_payload["system"] = {"operatingSystem": os_summary}
            if network_summary:
                modules_payload["network"] = network_summary
            if modules_payload:
                device_info["modules"] = modules_payload

            devices.append(device_info)

        # DEBUG: Check first device in response
        if devices:
            first_dev = devices[0]
            logger.info(f"🔍 [FINAL_RESPONSE_CHECK] First device: serial={first_dev.get('serialNumber')}, hostname={first_dev.get('hostname')}, has_modules_network={'network' in first_dev.get('modules', {})}")

        page_size = limit or len(devices) or total_devices or 1
        page = (offset // page_size) + 1 if page_size else 1
        has_more = bool(limit is not None and (offset + len(devices)) < total_devices)

        response = {
            "devices": devices,
            "total": total_devices or len(devices),
            "message": f"Successfully retrieved {len(devices)} devices",
            "page": page,
            "pageSize": page_size,
            "hasMore": has_more,
        }

        _t1 = _time.monotonic()
        logger.info(f"[DEVICES PERF] {_t1-_t0:.3f}s ({len(devices)} devices)")
        cache_set("devices", response, _ckey)
        return response

    except Exception as e:
        print(f"[ERROR] get_all_devices failed: {e}")
        logger.error(f"Failed to retrieve devices: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve devices: {str(e)}")
    finally:
        if conn:
            conn.close()

@router.get("/device/{serial_number}", dependencies=[Depends(verify_authentication)], tags=["devices"])
async def get_device_by_serial(serial_number: str):
    """
    Get individual device details with all modules.
    
    Uses serialNumber consistently as primary identifier.
    Returns complete device data including all collected module data.
    
    **Path Parameters:**
    - serial_number: Device serial number (e.g., "ABC123XYZ")
    
    **Response includes:**
    - Device metadata (serial, UUID, last seen, client version)
    - All module data (inventory, hardware, network, security, etc.)
    - Archive status
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Query uses correct schema columns - include archived status, client_version, and platform
        cursor.execute("""
            SELECT id, device_id, name, serial_number, last_seen, status, 
                   model, manufacturer, os, os_name, os_version, platform, created_at,
                   archived, archived_at, client_version
            FROM devices 
            WHERE serial_number = %s OR id = %s
        """, (serial_number, serial_number))
        
        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            raise HTTPException(status_code=404, detail="Device not found")
        
        device_id, device_uuid, device_name, serial_num, last_seen, status, model, manufacturer, os, os_name, os_version, platform, created_at, archived, archived_at, client_version = device_row
        
        # Get all module data for this device using device ID
        modules = {}
        
        # System module - use serial number as device_id 
        cursor.execute("SELECT data FROM system WHERE device_id = %s", (serial_num,))
        system_row = cursor.fetchone()
        if system_row:
            system_data = json.loads(system_row[0]) if isinstance(system_row[0], str) else system_row[0]
            if isinstance(system_data, list) and len(system_data) > 0:
                modules["system"] = system_data[0]
            else:
                modules["system"] = system_data
        
        # CRITICAL FIX: Use serial number for module queries (module tables use serial as device_id)
        module_tables = ["applications", "hardware", "installs", "network", "security", "inventory", "management", "peripherals", "identity"]
        for table in module_tables:
            try:
                # Use serial_number as device_id since module tables store serial numbers
                if table == "installs":
                    # Exclude runLog from main payload to keep response light
                    # Note: This requires Postgres JSONB column type
                    cursor.execute(f"SELECT data - 'runLog' FROM {table} WHERE device_id = %s", (serial_num,))
                else:
                    cursor.execute(f"SELECT data FROM {table} WHERE device_id = %s", (serial_num,))
                
                module_row = cursor.fetchone()
                if module_row:
                    module_data = json.loads(module_row[0]) if isinstance(module_row[0], str) else module_row[0]
                    modules[table] = module_data
            except Exception as e:
                logger.warning(f"Failed to get {table} data for {serial_num}: {e}")
        
        conn.close()
        
        # Resolve best device name: inventory.deviceName > network.hostname > stored name > serial
        display_name = device_name
        if modules.get("inventory"):
            inv = modules["inventory"]
            if isinstance(inv, list) and inv:
                inv = inv[0]
            if isinstance(inv, dict):
                display_name = inv.get("deviceName") or inv.get("device_name") or display_name
        if (not display_name or display_name == "Unknown" or display_name == serial_num) and modules.get("network"):
            net = modules["network"]
            if isinstance(net, list) and net:
                net = net[0]
            if isinstance(net, dict):
                display_name = net.get("hostname") or display_name
        if not display_name or display_name == "Unknown":
            display_name = serial_num or device_id
        
        # Build response with clean schema (no top-level inventory duplication)
        response = {
            "success": True,
            "device": {
                "serialNumber": serial_num or device_id,
                "deviceId": device_uuid or device_id,
                "name": display_name,
                "platform": platform,
                "clientVersion": client_version,
                "lastSeen": last_seen.isoformat() if last_seen else None,
                "createdAt": created_at.isoformat() if created_at else None,
                "registrationDate": created_at.isoformat() if created_at else None,
                "archived": archived or False,
                "archivedAt": archived_at.isoformat() if archived_at else None,
                "modules": modules
            }
        }
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get device {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve device: {str(e)}")


@router.get("/device/{serial_number}/installs/log", dependencies=[Depends(verify_authentication)], tags=["devices"])
async def get_device_installs_log(serial_number: str):
    """
    Get the full run log for the installs module.
    
    This data is lazy-loaded because it can be very large (MBs of text).
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Query uses correct schema columns
        cursor.execute("""
            SELECT data->>'runLog' as run_log
            FROM installs 
            WHERE device_id = %s
        """, (serial_number,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            # Return empty log if no record found, not 404 to avoid frontend errors
            return {"runLog": None}
        
        return {"runLog": row[0]}
        
    except Exception as e:
        logger.error(f"Failed to get installs log for {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve installs log: {str(e)}")

@router.get("/device/{serial_number}/events", dependencies=[Depends(verify_authentication)], tags=["devices"])
async def get_device_events(
    serial_number: str,
    limit: int = 100,
    type: str = Query(default=None, description="Filter by event type (success, warning, error, info, system)")
):
    """
    Get events for a specific device.
    
    Returns event history for device activity logging and monitoring.
    Used by EventsTab for displaying device events.
    
    **Query Parameters:**
    - limit: Maximum events to return (default 100)
    - type: Filter by event type - success, warning, error, info, system (optional)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify device exists
        cursor.execute("""
            SELECT serial_number FROM devices 
            WHERE serial_number = %s
        """, (serial_number,))
        
        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Validate event type filter
        VALID_EVENT_TYPES = ['success', 'warning', 'error', 'info', 'system']
        event_type = None
        if type and type.lower() in VALID_EVENT_TYPES:
            event_type = type.lower()
        
        # Get events for this device
        # NOTE: events.device_id contains the serial_number string
        if event_type:
            cursor.execute("""
                SELECT id, event_type, message, details, timestamp, created_at
                FROM events
                WHERE device_id = %s AND event_type = %s
                ORDER BY timestamp DESC
                LIMIT %s
            """, (serial_number, event_type, limit))
        else:
            cursor.execute("""
                SELECT id, event_type, message, details, timestamp, created_at
                FROM events
                WHERE device_id = %s
                ORDER BY timestamp DESC
                LIMIT %s
            """, (serial_number, limit))
        
        events = []
        for row in cursor.fetchall():
            event_id, event_type, message, details, timestamp, created_at = row
            events.append({
                "id": str(event_id),
                "kind": event_type,
                "message": message,
                "raw": json.loads(details) if isinstance(details, str) else details,
                "ts": timestamp.isoformat() if timestamp else created_at.isoformat()
            })
        
        conn.close()
        
        logger.info(f"Retrieved {len(events)} events for device {serial_number}")
        
        return {
            "success": True,
            "events": events,
            "count": len(events)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get events for device {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve events: {str(e)}")


@router.get("/device/{serial_number}/info", dependencies=[Depends(verify_authentication)], tags=["devices"])
async def get_device_info_fast(serial_number: str):
    """
    Fast endpoint returning only InfoTab data for progressive loading.
    
    Returns minimal data needed for immediate display:
    - inventory (device name, serial, etc.)
    - system basics (OS, uptime)
    - hardware summary (model, processor)
    - management status
    - security features
    - network hostname
    
    This is ~10-20KB vs 100-200KB for full device data
    Response time: <500ms vs 3-5s for full load
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get device record (include all metadata fields needed by frontend)
        cursor.execute("""
            SELECT id, device_id, serial_number, last_seen, created_at,
                   archived, archived_at, client_version, platform, status
            FROM devices 
            WHERE serial_number = %s OR id = %s
        """, (serial_number, serial_number))
        
        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            raise HTTPException(status_code=404, detail="Device not found")
        
        _, device_uuid, serial_num, last_seen, created_at, archived, archived_at, client_version, platform, status = device_row
        
        # Get only the modules needed for InfoTab (6 widgets)
        info_modules = {}
        
        # Inventory - Device info widget
        cursor.execute("SELECT data FROM inventory WHERE device_id = %s", (serial_num,))
        if row := cursor.fetchone():
            info_modules["inventory"] = json.loads(row[0]) if isinstance(row[0], str) else row[0]
        
        # System - System widget (OS, uptime)
        cursor.execute("SELECT data FROM system WHERE device_id = %s", (serial_num,))
        if row := cursor.fetchone():
            system_data = json.loads(row[0]) if isinstance(row[0], str) else row[0]
            info_modules["system"] = system_data[0] if isinstance(system_data, list) and len(system_data) > 0 else system_data
        
        # Hardware - Hardware widget (model, processor summary)
        cursor.execute("SELECT data FROM hardware WHERE device_id = %s", (serial_num,))
        if row := cursor.fetchone():
            info_modules["hardware"] = json.loads(row[0]) if isinstance(row[0], str) else row[0]
        
        # Management - Management widget (MDM status)
        cursor.execute("SELECT data FROM management WHERE device_id = %s", (serial_num,))
        if row := cursor.fetchone():
            info_modules["management"] = json.loads(row[0]) if isinstance(row[0], str) else row[0]
        
        # Security - Security widget (TPM, encryption)
        cursor.execute("SELECT data FROM security WHERE device_id = %s", (serial_num,))
        if row := cursor.fetchone():
            info_modules["security"] = json.loads(row[0]) if isinstance(row[0], str) else row[0]
        
        # Network - Network widget (hostname, IP)
        cursor.execute("SELECT data FROM network WHERE device_id = %s", (serial_num,))
        if row := cursor.fetchone():
            info_modules["network"] = json.loads(row[0]) if isinstance(row[0], str) else row[0]
        
        conn.close()
        
        response = {
            "success": True,
            "device": {
                "serialNumber": serial_num,
                "deviceId": device_uuid,
                "lastSeen": last_seen.isoformat() if last_seen else None,
                "createdAt": created_at.isoformat() if created_at else None,
                "registrationDate": created_at.isoformat() if created_at else None,
                "status": status,
                "archived": archived or False,
                "archivedAt": archived_at.isoformat() if archived_at else None,
                "clientVersion": client_version,
                "platform": platform,
                "modules": info_modules
            }
        }
        
        logger.info(f"Fast info fetch for {serial_number}: {len(json.dumps(response))} bytes")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get fast info for {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve device info: {str(e)}")


@router.get("/device/{serial_number}/modules/{module_name}", dependencies=[Depends(verify_authentication)], tags=["devices"])
async def get_device_module(serial_number: str, module_name: str):
    """
    Get individual module data for progressive/on-demand loading.
    
    Supports all module types:
    - applications, hardware, installs, network, security
    - inventory, management, system
    
    Used for:
    1. Background progressive loading (after fast info load)
    2. On-demand loading when user clicks tabs
    """
    try:
        # Validate module name
        valid_modules = [
            "applications", "hardware", "installs", "network", "security",
            "inventory", "management", "system", "peripherals", "identity"
        ]
        
        if module_name not in valid_modules:
            raise HTTPException(status_code=400, detail=f"Invalid module: {module_name}")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get device serial number
        cursor.execute("""
            SELECT serial_number FROM devices 
            WHERE serial_number = %s OR id = %s
        """, (serial_number, serial_number))
        
        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            raise HTTPException(status_code=404, detail="Device not found")
        
        serial_num = device_row[0]
        
        # Get module data
        cursor.execute(f"SELECT data FROM {module_name} WHERE device_id = %s", (serial_num,))
        module_row = cursor.fetchone()
        
        conn.close()
        
        if not module_row:
            return {
                "success": True,
                "module": module_name,
                "data": None
            }
        
        module_data = json.loads(module_row[0]) if isinstance(module_row[0], str) else module_row[0]
        
        # Handle system module array format
        if module_name == "system" and isinstance(module_data, list) and len(module_data) > 0:
            module_data = module_data[0]
        
        response = {
            "success": True,
            "module": module_name,
            "data": module_data
        }
        
        logger.info(f"Module fetch {module_name} for {serial_number}: {len(json.dumps(response))} bytes")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get module {module_name} for {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve module: {str(e)}")


@router.get("/device/{serial_number}/applications/usage/history", dependencies=[Depends(verify_authentication)], tags=["devices"])
async def get_device_usage_history(
    serial_number: str,
    days: int = Query(default=90, ge=1, le=548, description="Number of days to look back"),
    app_name: Optional[str] = Query(default=None, alias="appName", description="Filter by application name")
):
    """
    Per-device daily application usage time-series.
    Returns day-by-day usage for a single device, suitable for device detail page charts.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        if app_name:
            cursor.execute("""
                SELECT date::text, app_name, launches, total_seconds, users
                FROM usage_history
                WHERE device_id = %s AND date >= %s AND app_name = %s
                ORDER BY date DESC
            """, (serial_number, cutoff.date(), app_name))
        else:
            cursor.execute("""
                SELECT date::text, app_name, launches, total_seconds, users
                FROM usage_history
                WHERE device_id = %s AND date >= %s
                ORDER BY date DESC, total_seconds DESC
            """, (serial_number, cutoff.date()))

        rows = cursor.fetchall()
        conn.close()

        results = []
        for date_str, name, launches, total_secs, users_json in rows:
            results.append({
                "date": date_str,
                "appName": name,
                "launches": launches or 0,
                "totalSeconds": float(total_secs or 0),
                "totalHours": round(float(total_secs or 0) / 3600, 2),
                "users": users_json if isinstance(users_json, list) else []
            })

        return {
            "serialNumber": serial_number,
            "days": days,
            "filters": {"appName": app_name},
            "data": results,
            "count": len(results)
        }

    except Exception as e:
        logger.error(f"Failed to get device usage history for {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
