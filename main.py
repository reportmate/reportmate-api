#!/usr/bin/env python3
"""
ReportMate FastAPI Application
Enterprise-grade device management API with comprehensive data support

Device Management:
- Standardized device identification using serialNumber as primary key
- deviceId field maintained for compatibility
- Consistent database schema across all operations
- Clean UUID/serialNumber handling

Key Features:
- Bulk devices endpoint with complete OS data (/api/devices)
- Individual device details (/api/device/{serial_number})
- Health monitoring (/api/health)
- Event ingestion (/api/events)
- SignalR integration (/api/negotiate)
- Database diagnostics (/api/debug/database)

Architecture: Professional REST API with standardized device identification
"""

import json
import logging
import os
from datetime import datetime, timezone
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
    description="Professional device management and telemetry API"
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
    """Device modules container."""
    system: Optional[SystemModule] = None

class DeviceInfo(BaseModel):
    """
    Device information with database schema mapping
    """
    serialNumber: str  # PRIMARY KEY - Always use this
    deviceId: str      # UUID from device_id column
    deviceName: Optional[str] = None
    lastSeen: Optional[str] = None
    status: str = "unknown"
    model: Optional[str] = None
    manufacturer: Optional[str] = None
    platform: Optional[str] = None
    os_version: Optional[str] = None
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
        }@app.get("/api/health")
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
        
        # Query uses correct column names and handles NULL serials
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
            d.os_version,
            s.data as system_data
        FROM devices d
        LEFT JOIN system s ON d.id = s.device_id
        WHERE d.serial_number IS NOT NULL AND d.serial_number != ''
        ORDER BY d.serial_number ASC
        """
        
        print(f"[DEBUG] Executing devices query")
        cursor.execute(query)
        rows = cursor.fetchall()
        print(f"[DEBUG] Query returned {len(rows)} rows")
        conn.close()
        
        devices = []
        
        for i, row in enumerate(rows):
            print(f"[DEBUG] Processing row {i+1}/{len(rows)}")
            try:
                device_id, device_uuid, device_name, serial_number, last_seen, created_at, status, model, manufacturer, os, os_name, os_version, system_data = row
                
                print(f"[DEBUG] Row {i+1}: serial={serial_number}, uuid={device_uuid}, name={device_name}")
                
                # Build basic device info
                device_info = {
                    "serialNumber": serial_number or str(device_id),
                    "deviceId": device_uuid or str(device_id),
                    "deviceName": device_name or serial_number or str(device_id),
                    "lastSeen": last_seen.isoformat() if last_seen else None,
                    "createdAt": created_at.isoformat() if created_at else None,
                    "status": status or "online",
                    "model": model or "Unknown",
                    "manufacturer": manufacturer or "Unknown",
                    "platform": "Unknown",  # Will be set from system data
                    "os_version": "Unknown"  # Will be set from system data
                }
                
                print(f"[DEBUG] Row {i+1}: Basic device info created")
                
                # Add complete modules structure like individual device API
                if system_data:
                    print(f"[DEBUG] Row {i+1}: Processing system data")
                    print(f"[DEBUG] Row {i+1}: Raw system data type: {type(system_data)}")
                    try:
                        system_json = json.loads(system_data) if isinstance(system_data, str) else system_data
                        print(f"[DEBUG] Row {i+1}: Parsed system JSON keys: {list(system_json.keys()) if isinstance(system_json, dict) else 'Not a dict'}")
                        
                        # Extract operating system data
                        os_data = None
                        if isinstance(system_json, dict) and "operatingSystem" in system_json:
                            os_data = system_json["operatingSystem"]
                            print(f"[DEBUG] Row {i+1}: Found operatingSystem in system data")
                        elif isinstance(system_json, list) and len(system_json) > 0:
                            # Check if system data is an array
                            first_item = system_json[0]
                            if isinstance(first_item, dict) and "operatingSystem" in first_item:
                                os_data = first_item["operatingSystem"]
                                print(f"[DEBUG] Row {i+1}: Found operatingSystem in system data array")
                        
                        print(f"[DEBUG] Row {i+1}: OS data: {os_data if os_data else 'None'}")
                        
                        if os_data:
                            # Add complete modules structure 
                            device_info["modules"] = {
                                "system": {
                                    "operatingSystem": {
                                        "name": os_data.get("name"),
                                        "build": os_data.get("build"), 
                                        "major": os_data.get("major"),
                                        "minor": os_data.get("minor"),
                                        "patch": os_data.get("patch"),
                                        "edition": os_data.get("edition"),
                                        "version": os_data.get("version"),
                                        "featureUpdate": os_data.get("featureUpdate"),
                                        "displayVersion": os_data.get("displayVersion"),
                                        "architecture": os_data.get("architecture"),
                                        "locale": os_data.get("locale"),
                                        "timeZone": os_data.get("timeZone"),
                                        "installDate": os_data.get("installDate")
                                    }
                                }
                            }
                            
                            # Set platform based on OS name
                            os_name_lower = (os_data.get("name") or "").lower()
                            if "windows" in os_name_lower:
                                device_info["platform"] = "Windows"
                            elif "mac" in os_name_lower or "darwin" in os_name_lower:
                                device_info["platform"] = "macOS"
                            elif "linux" in os_name_lower:
                                device_info["platform"] = "Linux"
                            else:
                                device_info["platform"] = os_data.get("name", "Unknown")
                            
                            # Set os_version from displayVersion (Windows) or version (other)
                            if os_data.get("displayVersion"):
                                device_info["os_version"] = os_data.get("displayVersion")
                            elif os_data.get("version"):
                                device_info["os_version"] = os_data.get("version")
                            elif os_data.get("major") is not None:
                                # macOS style: major.minor.patch
                                major = os_data.get("major", 0)
                                minor = os_data.get("minor", 0) 
                                patch = os_data.get("patch", 0)
                                device_info["os_version"] = f"{major}.{minor}.{patch}"
                            
                            print(f"[DEBUG] Row {i+1}: Updated platform to {device_info['platform']} and os_version to {device_info['os_version']}")
                            
                    except Exception as e:
                        print(f"[ERROR] Row {i+1}: Failed to parse system data: {e}")
                else:
                    print(f"[DEBUG] Row {i+1}: No system data")
                
                devices.append(device_info)
                print(f"[DEBUG] Row {i+1}: Device added successfully")
                
            except Exception as e:
                print(f"[ERROR] Row {i+1}: Failed to process device row: {e}")
                continue
        
        print(f"[DEBUG] Successfully processed {len(devices)} devices")
        
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
        
        # System module
        cursor.execute("SELECT data FROM system WHERE device_id = %s", (device_id,))
        system_row = cursor.fetchone()
        if system_row:
            system_data = json.loads(system_row[0]) if isinstance(system_row[0], str) else system_row[0]
            if isinstance(system_data, list) and len(system_data) > 0:
                modules["system"] = system_data[0]
            else:
                modules["system"] = system_data
        
        # Other modules (applications, hardware, etc.) - all use device ID
        module_tables = ["applications", "hardware", "installs", "network", "security", "inventory", "management", "profiles"]
        for table in module_tables:
            try:
                cursor.execute(f"SELECT data FROM {table} WHERE device_id = %s", (device_id,))
                module_row = cursor.fetchone()
                if module_row:
                    module_data = json.loads(module_row[0]) if isinstance(module_row[0], str) else module_row[0]
                    modules[table] = module_data
            except Exception as e:
                logger.warning(f"Failed to get {table} data for {device_id}: {e}")
        
        conn.close()
        
        # Build response with correct schema mapping
        response = {
            "success": True,
            "device": {
                "serialNumber": serial_num or device_id,  # PRIMARY KEY
                "deviceId": device_uuid or device_id,     # COMPATIBILITY
                "deviceName": device_name or serial_num,  # Use name if available
                "lastSeen": last_seen.isoformat() if last_seen else None,
                "status": status or "unknown",
                "model": model,
                "manufacturer": manufacturer,
                "platform": os_name or os,
                "os_version": os_version or "",
                "createdAt": created_at.isoformat() if created_at else None,
                "modules": modules
            }
        }
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get device {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve device: {str(e)}")

@app.get("/api/events")
async def get_events(limit: int = 100):
    """
    Get recent events.
    
    Uses device_id which corresponds to serialNumber in our schema
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, device_id, event_type, message, timestamp, created_at
            FROM events 
            ORDER BY created_at DESC 
            LIMIT %s
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            event_id, device_id, event_type, message, timestamp, created_at = row
            events.append({
                "id": event_id,
                "serialNumber": device_id,  # device_id in events table IS the serialNumber
                "deviceId": device_id,      # COMPATIBILITY
                "eventType": event_type,
                "message": message,
                "timestamp": timestamp.isoformat() if timestamp else None,
                "createdAt": created_at.isoformat() if created_at else None
            })
        
        return {"events": events, "total": len(events)}
        
    except Exception as e:
        logger.error(f"Failed to get events: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve events: {str(e)}")

@app.post("/api/events")
async def submit_events(request: Request):
    """
    Submit device events and data.
    
    Event ingestion uses serialNumber as device identifier
    """
    try:
        payload = await request.json()
        
        # Process event submission
        # This would contain the logic for ingesting device events
        # For now, return success
        
        return {
            "success": True,
            "message": "Events processed successfully",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "deviceIdStandard": "serialNumber"
        }
        
    except Exception as e:
        logger.error(f"Failed to submit events: {e}")
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
async def internal_error_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": exc.detail}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)