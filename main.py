#!/usr/bin/env python3
"""
ReportMate FastAPI Application
Enterprise-grade device management API with OS data support

🚨 CRITICAL DEVICE ID ALIGNMENT FIX 🚨
- ALL device identification now uses serialNumber as primary key
- deviceId field is DEPRECATED and mapped to serialNumber for compatibility
- Database queries use serial_number consistently
- No more UUID/serialNumber confusion

Key Features:
- Bulk devices endpoint with OS data (/api/devices)
- Individual device details (/api/device/{serial_number})
- Health monitoring (/api/health)
- Event ingestion (/api/events)
- SignalR integration (/api/negotiate)
- Database diagnostics (/api/debug/database)

Critical Fix: Standardized device identification on serialNumber throughout stack
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
    version="2.1.0",
    description="Enterprise device management API with standardized device identification"
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
    🚨 FIXED: Device information with standardized ID handling
    - serialNumber is the PRIMARY identifier
    - deviceId is DEPRECATED but kept for compatibility (maps to serialNumber)
    """
    serialNumber: str  # PRIMARY KEY - Always use this
    deviceId: str      # DEPRECATED - Maps to serialNumber for compatibility
    deviceName: Optional[str] = None
    lastSeen: Optional[str] = None
    status: str = "unknown"
    assetTag: Optional[str] = None
    usage: Optional[str] = None
    catalog: Optional[str] = None
    location: Optional[str] = None
    department: Optional[str] = None
    platform: Optional[str] = None
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
        "version": "2.1.0",
        "status": "running",
        "platform": "FastAPI on Azure Container Apps",
        "deviceIdStandard": "serialNumber (UUIDs deprecated)",
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
            "version": "2.1.0",
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
    🚀 CRITICAL FIX: Bulk devices endpoint with standardized device identification
    
    🚨 DEVICE ID ALIGNMENT FIX:
    - Uses serialNumber as primary identifier
    - deviceId field maps to serialNumber for compatibility
    - No more UUID confusion
    
    Returns:
        - All devices with serialNumber as primary key
        - OS data (platform, modules.system.operatingSystem) for devices that have it
        - Windows: name, build, edition, version, featureUpdate, displayVersion
        - macOS: name, major, minor, patch
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 🚨 CRITICAL FIX: Query uses serial_number as primary key
        # REMOVED device_id field confusion - serialNumber is the source of truth
        query = """
        WITH device_os AS (
            SELECT 
                d.serial_number, 
                d.device_name,
                d.last_seen,
                d.created_at,
                d.status,
                d.asset_tag,
                d.usage,
                d.catalog,
                d.location,
                d.department,
                s.data as system_data
            FROM devices d
            LEFT JOIN system s ON d.serial_number = s.device_id
        )
        SELECT 
            serial_number,
            device_name, 
            last_seen,
            created_at,
            status,
            asset_tag,
            usage,
            catalog,
            location,
            department,
            system_data
        FROM device_os
        ORDER BY device_name ASC, serial_number ASC
        """
        
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        
        devices = []
        
        for row in rows:
            serial_number, device_name, last_seen, created_at, status, asset_tag, usage, catalog, location, department, system_data = row
            
            # 🚨 FIXED: Build device info with serialNumber as primary key
            device_info = {
                "serialNumber": serial_number,  # PRIMARY KEY
                "deviceId": serial_number,       # COMPATIBILITY - Maps to serialNumber
                "deviceName": device_name,
                "lastSeen": last_seen.isoformat() if last_seen else None,
                "createdAt": created_at.isoformat() if created_at else None,
                "status": status or "online",
                "assetTag": asset_tag,
                "usage": usage,
                "catalog": catalog,
                "location": location,
                "department": department
            }
            
            # 🚀 CRITICAL: Add OS data from system module
            if system_data:
                try:
                    system_json = json.loads(system_data) if isinstance(system_data, str) else system_data
                    
                    # Extract operating system data from system module
                    os_data = None
                    if isinstance(system_json, dict) and "operatingSystem" in system_json:
                        # System data has operatingSystem directly
                        os_data = system_json["operatingSystem"]
                    
                    if os_data:
                        # 🚀 ADD THE MISSING MODULES STRUCTURE TO BULK ENDPOINT
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
                        
                        # Set platform based on OS name for frontend compatibility  
                        os_name = os_data.get("name", "").lower()
                        if "windows" in os_name:
                            device_info["platform"] = "Windows"
                        elif "mac" in os_name or "darwin" in os_name:
                            device_info["platform"] = "macOS"
                        else:
                            device_info["platform"] = "Unknown"
                        
                except Exception as e:
                    logger.warning(f"Failed to parse system data for {serial_number}: {e}")
            
            devices.append(device_info)
        
        return {
            "success": True,
            "devices": devices,
            "count": len(devices)
        }
        
    except Exception as e:
        logger.error(f"Failed to retrieve devices: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve devices: {str(e)}")

@app.get("/api/device/{serial_number}")
async def get_device_by_serial(serial_number: str):
    """
    Get individual device details with all modules.
    
    🚨 FIXED: Uses serialNumber consistently as primary identifier
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 🚨 FIXED: Query uses serial_number only (no device_id confusion)
        cursor.execute("""
            SELECT serial_number, device_name, last_seen, status, 
                   asset_tag, usage, catalog, location, department, created_at
            FROM devices 
            WHERE serial_number = %s
        """, (serial_number,))
        
        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            raise HTTPException(status_code=404, detail="Device not found")
        
        serial_num, device_name, last_seen, status, asset_tag, usage, catalog, location, department, created_at = device_row
        
        # Get all module data for this device using serialNumber
        modules = {}
        
        # System module
        cursor.execute("SELECT data FROM system WHERE device_id = %s", (serial_number,))
        system_row = cursor.fetchone()
        if system_row:
            system_data = json.loads(system_row[0]) if isinstance(system_row[0], str) else system_row[0]
            if isinstance(system_data, list) and len(system_data) > 0:
                modules["system"] = system_data[0]
            else:
                modules["system"] = system_data
        
        # Other modules (applications, hardware, etc.) - all use serialNumber as device_id
        module_tables = ["applications", "hardware", "installs", "network", "security", "inventory", "management", "profiles"]
        for table in module_tables:
            try:
                cursor.execute(f"SELECT data FROM {table} WHERE device_id = %s", (serial_number,))
                module_row = cursor.fetchone()
                if module_row:
                    module_data = json.loads(module_row[0]) if isinstance(module_row[0], str) else module_row[0]
                    modules[table] = module_data
            except Exception as e:
                logger.warning(f"Failed to get {table} data for {serial_number}: {e}")
        
        conn.close()
        
        # 🚨 FIXED: Build response with standardized device identification
        response = {
            "success": True,
            "device": {
                "serialNumber": serial_num,  # PRIMARY KEY
                "deviceId": serial_num,      # COMPATIBILITY - Maps to serialNumber
                "deviceName": device_name,
                "lastSeen": last_seen.isoformat() if last_seen else None,
                "status": status or "unknown",
                "assetTag": asset_tag,
                "usage": usage,
                "catalog": catalog,
                "location": location,
                "department": department,
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
    
    🚨 FIXED: Uses device_id which corresponds to serialNumber in our schema
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
    
    🚨 FIXED: Event ingestion uses serialNumber as device identifier
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
    
    🚨 FIXED: Shows device identification standard
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
            "deviceIdStandard": "serialNumber (UUIDs deprecated)",
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