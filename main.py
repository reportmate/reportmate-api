#!/usr/bin/env python3
"""
ReportMate FastAPI Application
- Bulk devices endpoint with complete OS data (/api/devices)
- Individual device details (/api/device/{serial_number})
- Health monitoring (/api/health)
- Event ingestion (/api/events)
- SignalR integration (/api/negotiate)
- Database diagnostics (/api/debug/database)
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Union

import pg8000
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app initialization
app = FastAPI(
    title="ReportMate API",
    version="1.0.0",
    description="Device management and telemetry API"
)

# Database connection configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://reportmate:password@localhost:5432/reportmate')

def get_db_connection():
    """Get database connection using pg8000 driver."""
    try:
        # Parse DATABASE_URL with proper SSL parameter handling
        if DATABASE_URL.startswith('postgresql://'):
            url = DATABASE_URL[13:]  # Remove postgresql://
            
            # Handle SSL parameters in URL
            if '?' in url:
                url, params = url.split('?', 1)
            
            auth_part, host_part = url.split('@')
            username, password = auth_part.split(':')
            
            # Handle database name with potential parameters
            if '/' in host_part:
                host_and_port, database_part = host_part.split('/', 1)
                # Remove any parameters from database name
                database = database_part.split('?')[0]
            else:
                host_and_port = host_part
                database = 'reportmate'
            
            if ':' in host_and_port:
                host, port = host_and_port.split(':')
                port = int(port)
            else:
                host = host_and_port
                port = 5432

            logger.info(f"Connecting to database: {host}:{port}/{database}")
            conn = pg8000.connect(
                host=host,
                port=port,
                database=database,
                user=username,
                password=password,
                ssl_context=True
            )
            return conn
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")

# Pydantic models
class DeviceOS(BaseModel):
    """Operating System information model."""
    name: Optional[str] = None
    build: Optional[str] = None
    major: Optional[int] = None
    minor: Optional[int] = None
    patch: Optional[int] = None
    edition: Optional[str] = None
    version: Optional[str] = None
    featureUpdate: Optional[str] = None
    displayVersion: Optional[str] = None
    architecture: Optional[str] = None
    locale: Optional[str] = None
    timeZone: Optional[str] = None
    installDate: Optional[str] = None

class SystemModule(BaseModel):
    """System module data model."""
    operatingSystem: Optional[DeviceOS] = None

class DeviceModules(BaseModel):
    """Device modules container for bulk endpoint - only system and inventory."""
    system: Optional[SystemModule] = None
    inventory: Optional[dict] = None  # Inventory data for bulk response

class DeviceInfo(BaseModel):
    """
    Device information with database schema mapping.
    All inventory and system details are in nested modules.
    Frontend calculates status from lastSeen.
    """
    serialNumber: str  # PRIMARY KEY - Always use this
    deviceId: str      # UUID from device_id column
    deviceName: Optional[str] = None
    lastSeen: Optional[str] = None
    createdAt: Optional[str] = None
    registrationDate: Optional[str] = None
    modules: Optional[DeviceModules] = None

class DevicesResponse(BaseModel):
    """Response model for bulk devices endpoint."""
    devices: List[DeviceInfo]
    total: int
    message: str

@app.get("/")
async def root():
    """API root endpoint with service information."""
    return {
        "name": "ReportMate API",
        "version": "1.0.0",
        "status": "running",
        "platform": "FastAPI on Azure Container Apps",
        "deviceIdStandard": "serialNumber",
        "endpoints": {
            "health": "/api/health",
            "device": "/api/device/{serial_number}",
            "devices": "/api/devices",
            "events": "/api/events",
            "events_submit": "/api/events (POST)",
            "signalr": "/api/negotiate",
            "debug_database": "/api/debug/database"
        }
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        conn.close()
        
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": "connected",
            "version": "1.0.0",
            "deviceIdStandard": "serialNumber"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "unhealthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": str(e)
            }
        )

@app.get("/api/devices", response_model=DevicesResponse)
async def get_all_devices():
    """
    Bulk devices endpoint with standardized device identification
    """
    try:
        print(f"[DEBUG] Starting get_all_devices endpoint")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # CRITICAL FIX: Use same query approach as individual endpoint (which works)
        query = """
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
            d.os_version
        FROM devices d
        ORDER BY COALESCE(d.serial_number, d.device_id) ASC
        """
        
        print(f"[DEBUG] Executing devices query")
        cursor.execute(query)
        rows = cursor.fetchall()
        print(f"[DEBUG] Query returned {len(rows)} rows")
        # Keep connection open for module queries
        
        devices = []
        
        for i, row in enumerate(rows):
            print(f"[DEBUG] Processing row {i+1}/{len(rows)}")
            try:
                device_id, device_uuid, device_name, serial_number, last_seen, created_at, status, model, manufacturer, os, os_name, os_version = row
                
                print(f"[DEBUG] Row {i+1}: serial={serial_number}, uuid={device_uuid}, name={device_name}")
                
                # Build basic device info (no inventory duplication)
                device_info = {
                    "serialNumber": serial_number or str(device_id),
                    "deviceId": device_uuid or str(device_id),
                    "lastSeen": last_seen.isoformat() if last_seen else None,
                    "createdAt": created_at.isoformat() if created_at else None,
                    "registrationDate": created_at.isoformat() if created_at else None,
                }
                
                print(f"[DEBUG] Row {i+1}: Basic device info created")
                
                # Initialize modules structure
                device_info["modules"] = {}
                
                # CRITICAL FIX: Handle system module first (like individual endpoint)
                try:
                    cursor.execute("SELECT data FROM system WHERE device_id = %s", (serial_number,))
                    system_row = cursor.fetchone()
                    if system_row:
                        system_data = json.loads(system_row[0]) if isinstance(system_row[0], str) else system_row[0]
                        if isinstance(system_data, list) and len(system_data) > 0:
                            device_info["modules"]["system"] = system_data[0]
                        else:
                            device_info["modules"]["system"] = system_data
                        print(f"[DEBUG] Row {i+1}: Added system module")
                except Exception as e:
                    print(f"[ERROR] Row {i+1}: Failed to get system data for {serial_number}: {e}")
                
                # BULK ENDPOINT OPTIMIZATION: Only fetch inventory module (not all 8 modules)
                try:
                    cursor.execute("SELECT data FROM inventory WHERE device_id = %s", (serial_number,))
                    inventory_row = cursor.fetchone()
                    
                    if inventory_row:
                        inventory_data = json.loads(inventory_row[0]) if isinstance(inventory_row[0], str) else inventory_row[0]
                        device_info["modules"]["inventory"] = inventory_data
                        print(f"[DEBUG] Row {i+1}: Added inventory module")
                    else:
                        print(f"[DEBUG] Row {i+1}: No inventory data found")
                except Exception as e:
                    print(f"[ERROR] Row {i+1}: Failed to get inventory data for {serial_number}: {e}")
                
                # All module processing is now done above using individual endpoint approach
                devices.append(device_info)
                print(f"[DEBUG] Row {i+1}: Device added successfully")
                
            except Exception as e:
                print(f"[ERROR] Row {i+1}: Failed to process device row: {e}")
                continue
        
        print(f"[DEBUG] Successfully processed {len(devices)} devices")
        
        conn.close()  # Close connection after all processing
        
        return {
            "devices": devices,
            "total": len(devices),
            "message": f"Successfully retrieved {len(devices)} devices"
        }
        
    except Exception as e:
        print(f"[ERROR] get_all_devices failed: {e}")
        logger.error(f"Failed to retrieve devices: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve devices: {str(e)}")

@app.get("/api/device/{serial_number}")
async def get_device_by_serial(serial_number: str):
    """
    Get individual device details with all modules.
    
    Uses serialNumber consistently as primary identifier
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Query uses correct schema columns
        cursor.execute("""
            SELECT id, device_id, name, serial_number, last_seen, status, 
                   model, manufacturer, os, os_name, os_version, created_at
            FROM devices 
            WHERE serial_number = %s OR id = %s
        """, (serial_number, serial_number))
        
        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            raise HTTPException(status_code=404, detail="Device not found")
        
        device_id, device_uuid, device_name, serial_num, last_seen, status, model, manufacturer, os, os_name, os_version, created_at = device_row
        
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
        module_tables = ["applications", "hardware", "installs", "network", "security", "inventory", "management", "profiles"]
        for table in module_tables:
            try:
                # Use serial_number as device_id since module tables store serial numbers
                cursor.execute(f"SELECT data FROM {table} WHERE device_id = %s", (serial_num,))
                module_row = cursor.fetchone()
                if module_row:
                    module_data = json.loads(module_row[0]) if isinstance(module_row[0], str) else module_row[0]
                    modules[table] = module_data
            except Exception as e:
                logger.warning(f"Failed to get {table} data for {serial_num}: {e}")
        
        conn.close()
        
        # Build response with clean schema (no top-level inventory duplication)
        response = {
            "success": True,
            "device": {
                "serialNumber": serial_num or device_id,
                "deviceId": device_uuid or device_id,
                "lastSeen": last_seen.isoformat() if last_seen else None,
                "createdAt": created_at.isoformat() if created_at else None,
                "registrationDate": created_at.isoformat() if created_at else None,
                "modules": modules
            }
        }
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get device {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve device: {str(e)}")

@app.get("/api/devices/applications")
async def get_bulk_applications(
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
    loadAll: bool = False
):
    """
    Bulk applications endpoint with filtering support.
    
    Returns flattened list of applications across all devices with filtering.
    Frontend is responsible for search/filtering logic - this is just data retrieval.
    """
    try:
        logger.info(f"Fetching bulk applications (loadAll={loadAll}, filters={dict(request.query_params)})")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Parse comma-separated filter values
        device_name_list = deviceNames.split(',') if deviceNames else []
        app_name_list = applicationNames.split(',') if applicationNames else []
        publisher_list = publishers.split(',') if publishers else []
        category_list = categories.split(',') if categories else []
        version_list = versions.split(',') if versions else []
        
        # Build WHERE clause for device filtering
        where_conditions = ["d.serial_number IS NOT NULL", "d.serial_number NOT LIKE 'TEST-%'", "d.serial_number != 'localhost'"]
        query_params = []
        param_index = 1
        
        if device_name_list:
            placeholders = ', '.join([f'${i}' for i in range(param_index, param_index + len(device_name_list) * 3)])
            where_conditions.append(f"(inv.data->>'deviceName' IN ({placeholders}) OR inv.data->>'computerName' IN ({placeholders}) OR d.serial_number IN ({placeholders}))")
            query_params.extend(device_name_list * 3)
            param_index += len(device_name_list) * 3
        
        where_clause = ' AND '.join(where_conditions)
        
        # Query to get all devices with applications data
        query = f"""
        SELECT DISTINCT ON (d.serial_number)
            d.serial_number,
            d.device_id,
            d.last_seen,
            a.data as applications_data,
            a.collected_at,
            inv.data->>'deviceName' as device_name,
            inv.data->>'computerName' as computer_name,
            inv.data->>'usage' as usage,
            inv.data->>'catalog' as catalog,
            inv.data->>'location' as location,
            inv.data->>'assetTag' as asset_tag
        FROM devices d
        LEFT JOIN applications a ON d.id = a.device_id
        LEFT JOIN inventory inv ON d.id = inv.device_id
        WHERE {where_clause}
            AND a.data IS NOT NULL
        ORDER BY d.serial_number, a.updated_at DESC
        """
        
        cursor.execute(query, tuple(query_params))
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with applications data")
        
        # Process and flatten applications
        all_applications = []
        
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, apps_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag = row
                
                device_display_name = device_name or computer_name or serial_number
                
                if not apps_data:
                    continue
                
                # Handle different data structures
                installed_apps = []
                if isinstance(apps_data, dict):
                    installed_apps = apps_data.get('installedApplications') or apps_data.get('InstalledApplications') or apps_data.get('installed_applications') or []
                elif isinstance(apps_data, list):
                    installed_apps = apps_data
                
                # Flatten each application
                for idx, app in enumerate(installed_apps):
                    app_name = app.get('name') or app.get('displayName') or 'Unknown Application'
                    app_publisher = app.get('publisher') or app.get('signed_by') or app.get('vendor') or 'Unknown'
                    app_category = app.get('category', 'Other')
                    app_version = app.get('version') or app.get('bundle_version') or 'Unknown'
                    app_size = app.get('size') or app.get('estimatedSize')
                    app_install_date = app.get('installDate') or app.get('install_date') or app.get('last_modified')
                    
                    # Apply application-level filters (if provided)
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
                    
                    all_applications.append({
                        'id': f"{device_uuid}_{idx}",
                        'deviceId': device_uuid,
                        'deviceName': device_display_name,
                        'serialNumber': serial_number,
                        'lastSeen': last_seen.isoformat() if last_seen else None,
                        'collectedAt': collected_at.isoformat() if collected_at else None,
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
                        'assetTag': asset_tag,
                        'raw': app
                    })
            
            except Exception as e:
                logger.warning(f"Error processing applications for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(all_applications)} applications from {len(rows)} devices")
        
        return all_applications
        
    except Exception as e:
        logger.error(f"Failed to get bulk applications: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk applications: {str(e)}")

@app.get("/api/devices/hardware")
async def get_bulk_hardware():
    """
    Bulk hardware endpoint.
    
    Returns flattened list of hardware details across all devices.
    """
    try:
        logger.info("Fetching bulk hardware data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
        SELECT DISTINCT ON (d.serial_number)
            d.serial_number,
            d.device_id,
            d.last_seen,
            h.data as hardware_data,
            h.collected_at,
            s.data as system_data,
            inv.data->>'deviceName' as device_name,
            inv.data->>'computerName' as computer_name
        FROM devices d
        LEFT JOIN hardware h ON d.id = h.device_id
        LEFT JOIN system s ON d.id = s.device_id
        LEFT JOIN inventory inv ON d.id = inv.device_id
        WHERE d.serial_number IS NOT NULL
            AND d.serial_number NOT LIKE 'TEST-%'
            AND h.data IS NOT NULL
        ORDER BY d.serial_number, h.updated_at DESC
        """
        
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with hardware data")
        
        # Process hardware data
        all_hardware = []
        
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, hardware_data, collected_at, system_data, device_name, computer_name = row
                
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
                
                all_hardware.append({
                    'serialNumber': serial_number,
                    'deviceId': device_uuid,
                    'deviceName': device_display_name,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
                    'manufacturer': hw_details.get('manufacturer') or hw_details.get('systemManufacturer'),
                    'model': hw_details.get('model') or hw_details.get('systemProductName'),
                    'cpu': hw_details.get('processor') or hw_details.get('cpu'),
                    'memory': hw_details.get('totalMemory') or hw_details.get('physicalMemory'),
                    'storage': hw_details.get('storage') or hw_details.get('drives'),
                    'gpu': hw_details.get('gpu') or hw_details.get('displayAdapter'),
                    'osName': os_info.get('name'),
                    'osVersion': os_info.get('version') or os_info.get('displayVersion'),
                    'architecture': os_info.get('architecture'),
                    'raw': hardware_data
                })
            
            except Exception as e:
                logger.warning(f"Error processing hardware for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(all_hardware)} hardware records")
        
        return all_hardware
        
    except Exception as e:
        logger.error(f"Failed to get bulk hardware: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk hardware: {str(e)}")

@app.get("/api/devices/installs")
async def get_bulk_installs():
    """
    Bulk installs endpoint for Cimian managed packages.
    
    Returns flattened list of managed installs across all devices.
    """
    try:
        logger.info("Fetching bulk installs data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
        SELECT DISTINCT ON (d.serial_number)
            d.serial_number,
            d.device_id,
            d.last_seen,
            i.data as installs_data,
            i.collected_at,
            inv.data->>'deviceName' as device_name,
            inv.data->>'computerName' as computer_name,
            inv.data->>'usage' as usage,
            inv.data->>'catalog' as catalog,
            inv.data->>'location' as location
        FROM devices d
        LEFT JOIN installs i ON d.id = i.device_id
        LEFT JOIN inventory inv ON d.id = inv.device_id
        WHERE d.serial_number IS NOT NULL
            AND d.serial_number NOT LIKE 'TEST-%'
            AND i.data IS NOT NULL
        ORDER BY d.serial_number, i.updated_at DESC
        """
        
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with installs data")
        
        # Process installs data
        all_installs = []
        
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, installs_data, collected_at, device_name, computer_name, usage, catalog, location = row
                
                device_display_name = device_name or computer_name or serial_number
                
                # Extract Cimian data
                cimian_data = installs_data.get('cimian', {}) if isinstance(installs_data, dict) else {}
                managed_items = cimian_data.get('items', [])
                
                # Flatten each managed install
                for idx, item in enumerate(managed_items):
                    all_installs.append({
                        'id': f"{device_uuid}_{idx}",
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
                        'raw': item
                    })
            
            except Exception as e:
                logger.warning(f"Error processing installs for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(all_installs)} install records from {len(rows)} devices")
        
        return all_installs
        
    except Exception as e:
        logger.error(f"Failed to get bulk installs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk installs: {str(e)}")

@app.get("/api/events")
async def get_events(limit: int = 100):
    """
    Get recent events with device names (optimized for dashboard).
    
    Returns only 4 essential fields per event: type, device, message, time
    Uses JOIN to get device names in single query for maximum performance.
    NOTE: Details/payload is NOT included here - use /api/events/{id}/payload to lazy-load.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # JOIN with inventory to get device names in single query
        # Return only 4 fields needed for dashboard Recent Events widget
        # Note: device_id in both tables IS the serial number
        # deviceName is stored in inventory.data JSONB column
        cursor.execute("""
            SELECT 
                e.id,
                e.device_id,
                i.data->>'deviceName' as device_name,
                e.event_type,
                e.message,
                e.timestamp
            FROM events e
            LEFT JOIN inventory i ON e.device_id = i.device_id
            ORDER BY e.created_at DESC 
            LIMIT %s
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            event_id, device_id, device_name, event_type, message, timestamp = row
            events.append({
                # 4 essential fields for dashboard
                "id": event_id,
                "device": device_id,  # Serial number (used for links)
                "deviceName": device_name or device_id,  # Friendly name from inventory
                "kind": event_type,  # Event type (success/warning/error/info)
                "message": message,  # User-friendly message
                "ts": timestamp.isoformat() if timestamp else None,  # Timestamp
                # Legacy compatibility fields (minimal)
                "serialNumber": device_id,
                "eventType": event_type,
                "timestamp": timestamp.isoformat() if timestamp else None
            })
        
        return {"events": events, "total": len(events)}
        
    except Exception as e:
        logger.error(f"Failed to get events: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve events: {str(e)}")

@app.get("/api/events/{event_id}/payload")
async def get_event_payload(event_id: int):
    """
    Get the details/payload for a specific event (lazy-loaded).
    
    This endpoint is called when user clicks to expand an event in the dashboard.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT details
            FROM events 
            WHERE id = %s
        """, (event_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
        
        details = row[0]
        
        # If details is a string, try to parse as JSON
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except json.JSONDecodeError:
                details = {"raw": details}
        
        return {"payload": details or {}}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get event payload: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve event payload: {str(e)}")

@app.get("/api/stats/installs")
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
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Count devices with install errors from Cimian event logs
        logger.debug("Counting devices with install errors...")
        cursor.execute("""
            SELECT COUNT(DISTINCT i.device_id)
            FROM installs i
            CROSS JOIN LATERAL jsonb_array_elements(i.data->'cimian'->'events') as event
            WHERE event->>'status' IN ('Error', 'Failed')
               OR event->>'level' = 'ERROR'
        """)
        devices_with_errors = cursor.fetchone()[0] or 0
        logger.debug(f"Devices with errors: {devices_with_errors}")
        
        # Count devices with warnings but NO errors from Cimian event logs
        logger.debug("Counting devices with warnings (excluding devices with errors)...")
        cursor.execute("""
            SELECT COUNT(DISTINCT i.device_id)
            FROM installs i
            CROSS JOIN LATERAL jsonb_array_elements(i.data->'cimian'->'events') as event
            WHERE (event->>'status' = 'Warning' OR event->>'level' = 'WARN')
            AND i.device_id NOT IN (
                -- Exclude devices that have any errors
                SELECT DISTINCT device_id
                FROM installs
                CROSS JOIN LATERAL jsonb_array_elements(data->'cimian'->'events') as err_event
                WHERE err_event->>'status' IN ('Error', 'Failed')
                   OR err_event->>'level' = 'ERROR'
            )
        """)
        devices_with_warnings = cursor.fetchone()[0] or 0
        logger.debug(f"Devices with warnings: {devices_with_warnings}")
        
        # Count total failed install events across all devices
        logger.debug("Counting total failed installs...")
        cursor.execute("""
            SELECT COUNT(*)
            FROM installs i
            CROSS JOIN LATERAL jsonb_array_elements(i.data->'cimian'->'events') as event
            WHERE event->>'status' IN ('Error', 'Failed')
               OR event->>'level' = 'ERROR'
        """)
        total_failed = cursor.fetchone()[0] or 0
        
        # Count total warning events across all devices
        logger.debug("Counting total warnings...")
        cursor.execute("""
            SELECT COUNT(*)
            FROM installs i
            CROSS JOIN LATERAL jsonb_array_elements(i.data->'cimian'->'events') as event
            WHERE event->>'status' = 'Warning'
               OR event->>'level' = 'WARN'
        """)
        total_warnings = cursor.fetchone()[0] or 0
        
        conn.close()
        
        result = {
            "devicesWithErrors": devices_with_errors,
            "devicesWithWarnings": devices_with_warnings,
            "totalFailedInstalls": total_failed,
            "totalWarnings": total_warnings,
            "lastUpdated": datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"Install stats: {devices_with_errors} errors, {devices_with_warnings} warnings")
        return result
        
    except Exception as e:
        logger.error(f"Failed to get install stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve install statistics: {str(e)}")

@app.post("/api/events")
async def submit_events(request: Request):
    """
    Submit device events and unified module data.
    
    This endpoint handles:
    - Device registration/update
    - Module data storage (system, hardware, installs, network, etc.)
    - Event creation for tracking
    
    CRITICAL EVENT TYPE VALIDATION:
    - Events containing 'installs' module MUST use event types: 'success', 'warning', or 'error'
    - Other event types ('info', 'system') are NOT allowed for installs-related events
    - This ensures dashboard displays accurate install status information
    
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
        
        # Extract metadata
        metadata = payload.get('metadata', {})
        device_uuid = metadata.get('deviceId', 'unknown-device')
        serial_number = metadata.get('serialNumber', 'unknown-serial')
        collected_at = metadata.get('collectedAt', datetime.now(timezone.utc).isoformat())
        client_version = metadata.get('clientVersion', 'unknown')
        platform = metadata.get('platform', 'Unknown')
        collection_type = metadata.get('collectionType', 'Full')
        enabled_modules = metadata.get('enabledModules', [])
        
        # Validate required fields
        if device_uuid == 'unknown-device' or serial_number == 'unknown-serial':
            raise HTTPException(
                status_code=400,
                detail="Both deviceId (UUID) and serialNumber are required in metadata"
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
                # Update existing device
                cursor.execute("""
                    UPDATE devices 
                    SET device_id = %s, last_seen = %s, updated_at = %s
                    WHERE serial_number = %s
                """, (device_uuid, collected_at, datetime.now(timezone.utc), serial_number))
                logger.info(f"Updated existing device: {serial_number}")
            else:
                # Insert new device
                # NOTE: devices.id is VARCHAR and equals serial_number (per schema design)
                # Set name to 'Unknown' as placeholder (will be populated from system module data)
                cursor.execute("""
                    INSERT INTO devices (id, device_id, serial_number, name, status, last_seen, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (serial_number, device_uuid, serial_number, 'Unknown', 'online', collected_at, datetime.now(timezone.utc), datetime.now(timezone.utc)))
                logger.info(f"Created new device: {serial_number}")
            
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
            'profiles': 'profiles',
            'displays': 'displays',
            'printers': 'printers'
        }
        
        # Get modules from payload (could be at top level or nested under 'modules' key)
        modules_data = payload.get('modules', payload)
        
        for module_name, table_name in module_tables.items():
            if module_name in modules_data and modules_data[module_name]:
                try:
                    module_data = modules_data[module_name]
                    
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
                
                # VALIDATION: Events containing installs module MUST be success/warning/error
                if has_installs_module or (isinstance(details, dict) and details.get('module_status') in ['success', 'warning', 'error']):
                    allowed_types = {'success', 'warning', 'error'}
                    if event_type not in allowed_types:
                        logger.warning(f"Invalid event type '{event_type}' for installs module event, defaulting to 'info'")
                        # For installs events with invalid type, use 'info' but log the issue
                        # This ensures backward compatibility while flagging the problem
                        if event_type not in {'info', 'system'}:
                            event_type = 'warning'  # Default to warning for installs-related events
                
                # Store details as JSON
                details_json = json.dumps(details)
                
                # NOTE: events.device_id references devices.id which equals serial_number
                cursor.execute("""
                    INSERT INTO events (device_id, event_type, message, details, timestamp, created_at)
                    VALUES (%s, %s, %s, %s::jsonb, %s, %s)
                """, (serial_number, event_type, message, details_json, collected_at, datetime.now(timezone.utc)))
                
                events_stored += 1
                logger.debug(f"Stored {event_type} event for device {serial_number}: {message}")
                
            except Exception as event_error:
                logger.error(f"Failed to store event: {event_error}")
                continue
        
        # 4. ONLY create a system event if NO events were sent in payload
        # This prevents generic "Data collection" messages when client sends better events
        # SPECIAL CASE: Never create fallback 'info' events when installs module is present
        if events_stored == 0 and not has_installs_module:
            try:
                collection_message = f"Data collection: {collection_type} ({len(modules_processed)} modules)"
                
                # Sanitize metadata to remove passphrase before storing
                sanitized_metadata = metadata.copy()
                if 'additional' in sanitized_metadata and isinstance(sanitized_metadata['additional'], dict):
                    sanitized_additional = sanitized_metadata['additional'].copy()
                    # Remove passphrase completely - should NEVER be stored or visible
                    sanitized_additional.pop('passphrase', None)
                    sanitized_metadata['additional'] = sanitized_additional
                
                # Sanitize full payload to remove passphrase
                sanitized_payload = payload.copy()
                if 'metadata' in sanitized_payload and isinstance(sanitized_payload['metadata'], dict):
                    sanitized_payload_metadata = sanitized_payload['metadata'].copy()
                    if 'additional' in sanitized_payload_metadata and isinstance(sanitized_payload_metadata['additional'], dict):
                        sanitized_payload_additional = sanitized_payload_metadata['additional'].copy()
                        sanitized_payload_additional.pop('passphrase', None)
                        sanitized_payload_metadata['additional'] = sanitized_payload_additional
                    sanitized_payload['metadata'] = sanitized_payload_metadata
                
                # CRITICAL: Store COMPLETE original payload in details column for full payload retrieval
                # Include all metadata, modules, and original request data (with passphrase removed)
                collection_details = json.dumps({
                    # Summary fields (for display in list view)
                    'platform': platform,
                    'client_version': client_version,
                    'collection_type': collection_type,
                    'modules_processed': modules_processed,
                    # FULL PAYLOAD: Store complete original payload for detailed view (SANITIZED)
                    'full_payload': sanitized_payload,  # Complete request (passphrase removed)
                    'metadata': sanitized_metadata,      # All metadata from request (passphrase removed)
                    'collected_at': collected_at
                })
                
                # NOTE: events.device_id references devices.id which equals serial_number
                cursor.execute("""
                    INSERT INTO events (device_id, event_type, message, details, timestamp, created_at)
                    VALUES (%s, 'info', %s, %s::jsonb, %s, %s)
                """, (serial_number, collection_message, collection_details, collected_at, datetime.now(timezone.utc)))
                
                events_stored += 1
                logger.info(f"Created fallback system event with full payload (no events in payload)")
            except Exception as system_event_error:
                logger.error(f"Failed to create system event: {system_event_error}")
        elif has_installs_module and events_stored == 0:
            logger.warning(f"⚠️ INSTALLS MODULE PRESENT but NO events sent - this should not happen! Device: {serial_number}")
        else:
            logger.info(f"Skipped system event creation - {events_stored} events already in payload")
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Successfully processed device {serial_number}: {len(modules_processed)} modules, {events_stored} events")
        
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

@app.get("/api/negotiate")
async def signalr_negotiate():
    """SignalR negotiate endpoint."""
    return {
        "url": "wss://reportmate-signalr.service.signalr.net/client/?hub=events",
        "accessToken": "mock-token-for-development"
    }

@app.get("/api/debug/database")
async def debug_database():
    """
    Database diagnostic endpoint.
    
    Shows device identification standard
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        diagnostics = {}
        
        # Check tables and record counts
        tables = ["devices", "events", "system", "applications", "hardware", "installs", "network"]
        for table in tables:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                diagnostics[table] = {"records": count, "status": "ok"}
            except Exception as e:
                diagnostics[table] = {"records": 0, "status": f"error: {str(e)}"}
        
        conn.close()
        
        return {
            "database": "connected",
            "deviceIdStandard": "serialNumber",
            "diagnostics": diagnostics,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Database diagnostic failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database diagnostic failed: {str(e)}")

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=404,
        content={"error": "Not found", "detail": exc.detail}
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)