"""Event logging, retrieval, and real-time event ingestion."""

import json
import logging
import re
import time as _time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from dependencies import (
    broadcast_event, cache_get, cache_set, get_db_connection,
    invalidate_caches, limiter, load_sql, logger, paginate,
    verify_authentication, VALID_MODULE_NAMES,
    infer_platform, build_os_summary,
)

router = APIRouter(tags=["events"])

@router.get("/events", dependencies=[Depends(verify_authentication)], tags=["events"])
async def get_events(
    limit: int = Query(default=100, ge=1, le=1000, description="Maximum number of events to return"),
    offset: int = Query(default=0, ge=0, description="Number of events to skip (for pagination)"),
    startDate: str = Query(default=None, description="Filter events after this ISO8601 date"),
    endDate: str = Query(default=None, description="Filter events before this ISO8601 date"),
    type: str = Query(default=None, description="Filter by event type (success, warning, error, info, system)")
):
    """
    Get recent events with device names (optimized for dashboard).
    
    Returns lightweight event list with device context for fast dashboard rendering.
    **Note:** Full event payload is NOT included - use `/api/events/{id}/payload` for details.
    
    **Query Parameters:**
    - limit: Maximum events to return (1-1000, default 100)
    - offset: Number of events to skip (for pagination, default 0)
    - startDate: Filter events after this ISO8601 date (optional)
    - endDate: Filter events before this ISO8601 date (optional)
    - type: Filter by event type(s). Single value (e.g. `error`) or comma-separated (e.g. `success,warning,error,system`)
    
    **Response includes:**
    - Event ID, type, message, timestamp
    - Device serial number and name
    - Total count for pagination
    """
    try:
        _ckey = (limit, offset, startDate or '', endDate or '', type or '')
        _cached = cache_get("events", _ckey)
        if _cached is not None:
            return _cached
        _t0 = _time.monotonic()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Parse date parameters
        start_date = None
        end_date = None
        if startDate:
            try:
                start_date = datetime.fromisoformat(startDate.replace('Z', '+00:00'))
            except ValueError as e:
                logger.warning(f"Invalid startDate format: {startDate}, error: {e}")
        if endDate:
            try:
                end_date = datetime.fromisoformat(endDate.replace('Z', '+00:00'))
            except ValueError as e:
                logger.warning(f"Invalid endDate format: {endDate}, error: {e}")
        
        # Validate event type filter — supports single value or comma-separated list
        VALID_EVENT_TYPES = ['success', 'warning', 'error', 'info', 'system']
        event_types = None  # None means no filter (all types)
        if type:
            parts = [t.strip().lower() for t in type.split(',') if t.strip()]
            valid = [t for t in parts if t in VALID_EVENT_TYPES]
            if valid:
                event_types = valid
            elif parts:
                logger.warning(f"Invalid event type filter: {type}")
        
        # Get total count first for pagination info
        count_query = load_sql("events/count_events")
        cursor.execute(count_query, {"start_date": start_date, "end_date": end_date, "event_types": event_types})
        total_count = cursor.fetchone()[0]
        
        # JOIN with inventory to get device names and assetTag in single query
        query = load_sql("events/list_events")
        cursor.execute(query, {
            "limit": limit, 
            "offset": offset,
            "start_date": start_date,
            "end_date": end_date,
            "event_types": event_types
        })
        
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            event_id, device_id, device_name, asset_tag, event_type, message, timestamp, platform = row
            events.append({
                # Essential fields for events page
                "id": event_id,
                "device": device_id,  # Serial number (used for links)
                "deviceName": device_name if (device_name and device_name.lower() != "unknown") else device_id,  # Friendly name from inventory
                "assetTag": asset_tag,  # Asset tag for display
                "kind": event_type,  # Event type (success/warning/error/info)
                "message": message,  # User-friendly message
                "ts": timestamp.isoformat() if timestamp else None,  # Timestamp
                "platform": platform,  # Platform from system.operatingSystem.name
                # Legacy compatibility fields (minimal)
                "serialNumber": device_id,
                "eventType": event_type,
                "timestamp": timestamp.isoformat() if timestamp else None
            })
        
        _result = {
            "success": True,
            "events": events, 
            "total": total_count,
            "totalEvents": total_count,
            "count": len(events),
            "limit": limit,
            "offset": offset
        }
        cache_set("events", _result, _ckey)
        logger.info(f"[PERF] /api/events: {_time.monotonic()-_t0:.3f}s ({len(events)} events)")
        return _result
        
    except Exception as e:
        logger.error(f"Failed to get events: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve events: {str(e)}")

@router.get("/events/{event_id}/payload", dependencies=[Depends(verify_authentication)], tags=["events"])
async def get_event_payload(event_id: int):
    """
    Get the FULL payload for a specific event including related module data.
    
    This endpoint is called when user clicks to expand an event in the dashboard.
    It fetches the event details AND the actual module data from the module tables.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # First get the event details and device_id
        cursor.execute("""
            SELECT details, device_id, timestamp
            FROM events 
            WHERE id = %s
        """, (event_id,))
        
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
        
        details, device_id, event_timestamp = row
        
        # If details is a string, try to parse as JSON
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except json.JSONDecodeError:
                details = {"raw": details}
        
        # Build full payload with actual module data
        full_payload = details.copy() if isinstance(details, dict) else {"metadata": details}
        
        # Get the modules list from the event details
        modules_list = []
        if isinstance(details, dict):
            modules_list = details.get('modules', [])
            if isinstance(modules_list, str):
                modules_list = [modules_list]
        
        # Fetch actual data from each module table mentioned in this event
        module_data = {}
        for module_name in modules_list:
            try:
                table_name = module_name.lower()
                # Validate table name to prevent SQL injection
                valid_tables = ['applications', 'hardware', 'installs', 'inventory', 
                               'management', 'network', 'peripherals', 'security', 'system', 'identity']
                if table_name not in valid_tables:
                    continue
                
                # Fetch the module data for this device around the event timestamp
                # Use a time window to find the closest module data to the event
                cursor.execute(f"""
                    SELECT data, collected_at
                    FROM {table_name}
                    WHERE device_id = %s
                    ORDER BY ABS(EXTRACT(EPOCH FROM (collected_at - %s::timestamp)))
                    LIMIT 1
                """, (device_id, event_timestamp))
                
                module_row = cursor.fetchone()
                if module_row:
                    module_content = module_row[0]
                    if isinstance(module_content, str):
                        try:
                            module_content = json.loads(module_content)
                        except json.JSONDecodeError:
                            pass
                    module_data[module_name] = module_content
                    
            except Exception as module_error:
                logger.warning(f"Failed to fetch {module_name} data for event {event_id}: {module_error}")
                continue
        
        conn.close()
        
        # Include the actual module data in the payload
        if module_data:
            full_payload['moduleData'] = module_data
        
        return {"payload": full_payload}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get event payload: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve event payload: {str(e)}")

@router.post("/events", dependencies=[Depends(verify_authentication)], tags=["events"])
@limiter.limit("30/minute")
async def submit_events(request: Request):
    """
    Submit device events and unified module data.
    
    This endpoint handles:
    - Device registration/update
    - Module data storage (system, hardware, installs, network, etc.)
    - Event creation for tracking
    
    Expected payload structure:
    {
        "metadata": {
            "deviceId": "UUID",
            "serialNumber": "SERIAL",
            "collectedAt": "ISO8601",
            "clientVersion": "version",
            "platform": "Windows|macOS",
            "collectionType": "Full|Single",
            "enabledModules": ["system", "hardware", ...]
        },
        "events": [...],  # Optional event messages
        "system": {...},   # Module data (top-level keys)
        "hardware": {...},
        "installs": {...},
        ...
    }
    """
    try:
        payload = await request.json()
        
        # Validate top-level structure via Pydantic
        try:
            submission = EventSubmission.model_validate(payload)
        except Exception as validation_err:
            raise HTTPException(status_code=422, detail=f"Invalid payload: {validation_err}")
        
        # Extract metadata - support both snake_case and camelCase for Windows client compatibility
        meta = submission.metadata
        device_uuid = meta.device_id or meta.deviceId
        serial_number = meta.serial_number or meta.serialNumber
        collected_at = meta.collected_at or meta.collectedAt or datetime.now(timezone.utc).isoformat()
        client_version = meta.client_version or meta.clientVersion or 'unknown'
        platform = meta.platform or 'Unknown'
        collection_type = meta.collection_type or meta.collectionType or 'Full'
        enabled_modules = meta.enabled_modules or meta.enabledModules or []
        
        # VALIDATION: Reject serial numbers that look like hostnames
        # This prevents database pollution from client bugs where hostname is sent as serial
        hostname_patterns = [
            r'^[A-Z]+-[A-Z]+$',  # All caps with hyphens (e.g., TOLUWANI-AGBI, AWI-JUMP)
            r'^[A-Z]+\-[A-Z0-9]+\-[A-Z0-9]+$',  # Pattern like DESKTOP-ABC123
            r'^WIN-[A-Z0-9]+$',  # Windows default hostnames
            r'^[A-Z]+-[A-Z]+-[A-Z]+-[0-9]+$',
            r'^[A-Z]{4,}-[0-9]{4}$',
            r'^[A-Z]{2,}\d{2,}$',
        ]
        
        for pattern in hostname_patterns:
            if re.match(pattern, serial_number, re.IGNORECASE):
                logger.error(f"Rejected device registration: serial_number '{serial_number}' matches hostname pattern '{pattern}'")
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid serial number: '{serial_number}' appears to be a hostname. Device must provide hardware serial number (BIOS/chassis serial)."
                )
        
        # Additional validation: Serial numbers should not contain only letters and hyphens
        # Real serials usually have numbers
        if serial_number.replace('-', '').isalpha():
            logger.error(f"Rejected device registration: serial_number '{serial_number}' contains only letters (likely a hostname)")
            raise HTTPException(
                status_code=400,
                detail=f"Invalid serial number: '{serial_number}' contains only letters and appears to be a hostname. Device must provide hardware serial number."
            )
        
        logger.info(f"Processing unified payload for device {serial_number} (UUID: {device_uuid})")
        logger.info(f"Collection type: {collection_type}, Enabled modules: {enabled_modules}")
        
        # Connect to database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. UPSERT device record
        try:
            # Check if device exists
            cursor.execute(
                "SELECT id FROM devices WHERE serial_number = %s",
                (serial_number,)
            )
            device_exists = cursor.fetchone()
            
            if device_exists:
                # Update existing device - include client_version and platform
                cursor.execute("""
                    UPDATE devices 
                    SET device_id = %s, last_seen = %s, updated_at = %s, client_version = %s, platform = %s
                    WHERE serial_number = %s
                """, (device_uuid, collected_at, datetime.now(timezone.utc), client_version, platform, serial_number))
                logger.info(f"Updated existing device: {serial_number} (client v{client_version}, platform: {platform})")
            else:
                # Insert new device
                # NOTE: devices.id is VARCHAR and equals serial_number (per schema design)
                # Set name to 'Unknown' as placeholder (will be populated from system module data)
                cursor.execute("""
                    INSERT INTO devices (id, device_id, serial_number, name, status, last_seen, created_at, updated_at, client_version, platform)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (serial_number, device_uuid, serial_number, 'Unknown', 'online', collected_at, datetime.now(timezone.utc), datetime.now(timezone.utc), client_version, platform))
                logger.info(f"Created new device: {serial_number} (client v{client_version}, platform: {platform})")
            
            conn.commit()
        except Exception as device_error:
            logger.error(f"Device upsert failed: {device_error}")
            conn.rollback()
            raise
        
        # 2. Process and store module data
        modules_processed = []
        module_tables = {
            'system': 'system',
            'hardware': 'hardware',
            'network': 'network',
            'installs': 'installs',
            'security': 'security',
            'applications': 'applications',
            'inventory': 'inventory',
            'management': 'management',
            'peripherals': 'peripherals',
            'identity': 'identity'
        }
        
        # Get modules from payload (could be at top level or nested under 'modules' key)
        modules_data = payload.get('modules', payload)
        
        # Debug: Log available modules in payload
        available_modules = [k for k in modules_data.keys() if k in module_tables]
        logger.info(f"Available modules in payload for {serial_number}: {available_modules}")
        
        for module_name, table_name in module_tables.items():
            if module_name in modules_data and modules_data[module_name]:
                try:
                    module_data = modules_data[module_name]
                    
                    # STANDARD HANDLING: All modules store in their table with data JSONB
                    # Check if module record exists (device_id in module tables = serial_number per schema)
                    cursor.execute(
                        f"SELECT id FROM {table_name} WHERE device_id = %s",
                        (serial_number,)
                    )
                    module_exists = cursor.fetchone()
                    
                    # Store as JSONB
                    module_json = json.dumps(module_data)
                    
                    if module_exists:
                        # Update existing module
                        cursor.execute(f"""
                            UPDATE {table_name}
                            SET data = %s::jsonb, collected_at = %s, updated_at = %s
                            WHERE device_id = %s
                        """, (module_json, collected_at, datetime.now(timezone.utc), serial_number))
                    else:
                        # Insert new module record
                        # NOTE: device_id column references devices.id which equals serial_number
                        cursor.execute(f"""
                            INSERT INTO {table_name} (device_id, data, collected_at, created_at, updated_at)
                            VALUES (%s, %s::jsonb, %s, %s, %s)
                        """, (serial_number, module_json, collected_at, datetime.now(timezone.utc), datetime.now(timezone.utc)))
                    
                    conn.commit()
                    modules_processed.append(module_name)
                    logger.info(f"Stored {module_name} module for device {serial_number}")
                    
                    # Extract daily usage history from applications module and UPSERT
                    if module_name == 'applications' and isinstance(module_data, dict):
                        daily_history = module_data.get('dailyUsageHistory', [])
                        if daily_history:
                            try:
                                for entry in daily_history:
                                    date_val = entry.get('date')
                                    app_name = entry.get('appName')
                                    if not date_val or not app_name:
                                        continue
                                    cursor.execute("""
                                        INSERT INTO usage_history (device_id, date, app_name, publisher, launches, total_seconds, users, updated_at)
                                        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, NOW())
                                        ON CONFLICT (device_id, date, app_name) DO UPDATE SET
                                            publisher = EXCLUDED.publisher,
                                            launches = EXCLUDED.launches,
                                            total_seconds = EXCLUDED.total_seconds,
                                            users = EXCLUDED.users,
                                            updated_at = NOW()
                                    """, (
                                        serial_number,
                                        date_val,
                                        app_name,
                                        entry.get('publisher', ''),
                                        entry.get('launches', 0),
                                        entry.get('totalSeconds', 0),
                                        json.dumps(entry.get('users', []))
                                    ))
                                conn.commit()
                                logger.info(f"Stored {len(daily_history)} daily usage entries for device {serial_number}")
                            except Exception as usage_err:
                                logger.error(f"Failed to store daily usage history for {serial_number}: {usage_err}")
                                conn.rollback()
                    
                    # Update devices table with OS info if system module
                    if module_name == 'system':
                        try:
                            # Handle list format
                            sys_data = module_data[0] if isinstance(module_data, list) and len(module_data) > 0 else module_data
                            if isinstance(sys_data, dict):
                                os_info = sys_data.get('operatingSystem', {})
                                os_name = os_info.get('name')
                                os_version = os_info.get('version') or os_info.get('displayVersion')
                                
                                if os_name:
                                    cursor.execute("""
                                        UPDATE devices 
                                        SET os_name = %s, os_version = %s, os = %s
                                        WHERE serial_number = %s
                                    """, (os_name, os_version, os_name, serial_number))
                                    conn.commit()
                                    logger.info(f"Updated OS info for device {serial_number}: {os_name} {os_version}")
                        except Exception as os_update_error:
                            logger.error(f"Failed to update OS info for device {serial_number}: {os_update_error}")
                    
                except Exception as module_error:
                    logger.error(f"Failed to store {module_name} module: {module_error}")
                    conn.rollback()
                    continue
        
        # 3. Store events from payload with validation
        events_stored = 0
        payload_events = payload.get('events', [])
        
        # Check if installs module is present in payload
        has_installs_module = 'installs' in modules_data and modules_data['installs']
        
        for event in payload_events:
            try:
                event_type = event.get('eventType', 'info').lower()  # Normalize to lowercase
                message = event.get('message', 'Event from device')
                details = event.get('details', {})
                module_id = event.get('moduleId', None)  # For upsert: os_update events are one per device
                
                # VALIDATION: Events containing installs module MUST be success/warning/error
                if has_installs_module or (isinstance(details, dict) and details.get('module_status') in ['success', 'warning', 'error']):
                    allowed_types = {'success', 'warning', 'error'}
                    if event_type not in allowed_types:
                        logger.warning(f"Invalid event type '{event_type}' for installs module event, defaulting to 'info'")
                        # For installs events with invalid type, use 'info' but log the issue
                        # This ensures backward compatibility while flagging the problem
                        if event_type not in {'info', 'system'}:
                            event_type = 'warning'  # Default to warning for installs-related events
                
                # Store only the event's own details — full module data lives in the module tables.
                enhanced_details = details.copy() if isinstance(details, dict) else {}
                
                # Store enhanced details as JSON
                details_json = json.dumps(enhanced_details)
                
                # Upsert for module-scoped events (e.g., os_update) — latest only per device
                if module_id and module_id == 'os_update':
                    cursor.execute("""
                        INSERT INTO events (device_id, event_type, module_id, message, details, timestamp, created_at)
                        VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s)
                        ON CONFLICT (device_id, module_id) WHERE module_id IS NOT NULL
                        DO UPDATE SET event_type = EXCLUDED.event_type,
                                      message = EXCLUDED.message,
                                      details = EXCLUDED.details,
                                      timestamp = EXCLUDED.timestamp,
                                      created_at = EXCLUDED.created_at
                        RETURNING id
                    """, (serial_number, event_type, module_id, message, details_json, collected_at, datetime.now(timezone.utc)))
                    logger.info(f"Upserted os_update event for device {serial_number}: {message}")
                else:
                    # NOTE: events.device_id references devices.id which equals serial_number
                    cursor.execute("""
                        INSERT INTO events (device_id, event_type, message, details, timestamp, created_at)
                        VALUES (%s, %s, %s, %s::jsonb, %s, %s)
                        RETURNING id
                    """, (serial_number, event_type, message, details_json, collected_at, datetime.now(timezone.utc)))
                
                event_row = cursor.fetchone()
                event_id = event_row[0] if event_row else None
                
                events_stored += 1
                logger.debug(f"Stored {event_type} event for device {serial_number}: {message}")
                
                # Broadcast event to connected WebSocket clients
                # Include the message field so frontend shows proper description immediately
                try:
                    await broadcast_event({
                        "id": str(event_id) if event_id else str(datetime.now(timezone.utc).timestamp()),
                        "device": serial_number,
                        "kind": event_type,
                        "ts": collected_at.isoformat() if hasattr(collected_at, 'isoformat') else str(collected_at),
                        "message": message,  # Include the formatted message for immediate display
                        "payload": enhanced_details
                    })
                except Exception as broadcast_error:
                    logger.warning(f"Failed to broadcast event: {broadcast_error}")
                
            except Exception as event_error:
                logger.error(f"Failed to store event: {event_error}")
                continue
        
        # 4. ONLY create a system event if NO events were sent in payload
        # This prevents generic "Data collection" messages when client sends better events
        # SPECIAL CASE: Never create fallback 'info' events when installs module is present
        if events_stored == 0 and not has_installs_module:
            try:
                collection_message = f"Data collection: {collection_type} ({len(modules_processed)} modules)"
                
                # Store only summary fields — full module data already lives in the module tables.
                collection_details = json.dumps({
                    'platform': platform,
                    'client_version': client_version,
                    'collection_type': collection_type,
                    'modules_processed': modules_processed,
                    'collected_at': collected_at
                })
                
                # NOTE: events.device_id references devices.id which equals serial_number
                cursor.execute("""
                    INSERT INTO events (device_id, event_type, message, details, timestamp, created_at)
                    VALUES (%s, 'info', %s, %s::jsonb, %s, %s)
                    RETURNING id
                """, (serial_number, collection_message, collection_details, collected_at, datetime.now(timezone.utc)))
                
                event_row = cursor.fetchone()
                event_id = event_row[0] if event_row else None
                
                events_stored += 1
                logger.info(f"Created fallback system event for device {serial_number}")
                
                # Broadcast fallback event to connected WebSocket clients
                # Include message field for proper display
                try:
                    await broadcast_event({
                        "id": str(event_id) if event_id else str(datetime.now(timezone.utc).timestamp()),
                        "device": serial_number,
                        "kind": "info",
                        "ts": collected_at.isoformat() if hasattr(collected_at, 'isoformat') else str(collected_at),
                        "message": collection_message,  # Include the formatted message
                        "payload": {"message": collection_message, "modules": modules_processed}
                    })
                except Exception as broadcast_error:
                    logger.warning(f"Failed to broadcast fallback event: {broadcast_error}")
            except Exception as system_event_error:
                logger.error(f"Failed to create system event: {system_event_error}")
        elif has_installs_module and events_stored == 0:
            logger.warning(f"[WARN] INSTALLS MODULE PRESENT but NO events sent - this should not happen! Device: {serial_number}")
        else:
            logger.info(f"Skipped system event creation - {events_stored} events already in payload")
        
        conn.commit()

        # Periodic retention: purge events older than 30 days (runs ~1% of requests to avoid overhead)
        import random
        if random.random() < 0.01:
            try:
                cursor.execute(
                    "DELETE FROM events WHERE timestamp < NOW() - INTERVAL '30 days'"
                )
                deleted = cursor.rowcount
                conn.commit()
                if deleted:
                    logger.info(f"Retention purge: deleted {deleted} events older than 30 days")
            except Exception as purge_error:
                logger.warning(f"Retention purge failed (non-fatal): {purge_error}")
                conn.rollback()

        conn.close()
        invalidate_caches()
        
        logger.info(f"[SUCCESS] Successfully processed device {serial_number}: {len(modules_processed)} modules, {events_stored} events")
        
        return {
            "success": True,
            "message": f"Complete data storage: {len(modules_processed)} modules, {events_stored} events",
            "device_id": serial_number,
            "serial_number": serial_number,
            "modules_processed": modules_processed,
            "events_stored": events_stored,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "internal_uuid": device_uuid
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to submit events: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to process events: {str(e)}")

