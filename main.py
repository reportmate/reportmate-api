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
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pg8000
# Use pyformat paramstyle for named parameters like %(name)s
pg8000.paramstyle = 'pyformat'
from fastapi import FastAPI, HTTPException, Query, Request, Header, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Azure Web PubSub for real-time events
try:
    from azure.messaging.webpubsubservice import WebPubSubServiceClient
    WEBPUBSUB_AVAILABLE = True
except ImportError:
    WEBPUBSUB_AVAILABLE = False
    WebPubSubServiceClient = None

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# SQL Query Loader - Load queries from external .sql files at startup
# -----------------------------------------------------------------------------
SQL_DIR = Path(__file__).parent / "sql"
SQL_QUERIES: Dict[str, str] = {}

def load_sql(name: str) -> str:
    """
    Load a SQL query from an external .sql file.
    
    Args:
        name: Path relative to sql/ directory (e.g., 'devices/bulk_hardware')
    
    Returns:
        SQL query string with %(name)s style parameter placeholders
    
    Raises:
        FileNotFoundError: If SQL file doesn't exist
        ValueError: If name contains path traversal attempts
        OSError: If file cannot be read
    """
    if name in SQL_QUERIES:
        return SQL_QUERIES[name]
    
    # Security: Prevent path traversal attacks
    if ".." in name or name.startswith("/") or name.startswith("\\"):
        raise ValueError(f"Invalid SQL query name (path traversal detected): {name}")
    
    sql_path = SQL_DIR / f"{name}.sql"
    
    # Additional safety: ensure resolved path is within SQL_DIR
    try:
        resolved = sql_path.resolve()
        if not str(resolved).startswith(str(SQL_DIR.resolve())):
            raise ValueError(f"Invalid SQL query path: {name}")
    except OSError as e:
        raise ValueError(f"Cannot resolve SQL path: {name}") from e
    
    if not sql_path.exists():
        raise FileNotFoundError(f"SQL file not found: {sql_path}")
    
    try:
        query = sql_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        logger.error(f"Failed to read SQL file {name}: {e}")
        raise OSError(f"Cannot read SQL file: {sql_path}") from e
    
    SQL_QUERIES[name] = query
    logger.info(f"Loaded SQL query: {name}")
    return query

def preload_sql_queries():
    """
    Preload all SQL queries at startup for faster execution.
    Called during application initialization.
    """
    sql_files = [
        # Bulk fleet endpoints
        "devices/bulk_hardware",
        "devices/bulk_installs",
        "devices/bulk_network",
        "devices/bulk_security",
        "devices/bulk_profiles",
        "devices/bulk_management",
        "devices/bulk_inventory",
        "devices/bulk_system",
        "devices/bulk_peripherals",
        # Dashboard endpoints
        "devices/dashboard_devices",
        "devices/dashboard_events",
        # Device list and count
        "devices/list_devices",
        "devices/count_devices",
        # Single device operations
        "devices/get_device",
        "devices/get_device_module",
        "devices/get_device_profiles",
        "devices/get_policies_by_hash",
        "devices/get_installs_log",
        "devices/get_device_id",
        "devices/get_serial_number",
        # Events
        "events/list_events",
        "events/get_device_events",
        "events/get_event_payload",
        # Admin operations
        "admin/archive_device",
        "admin/unarchive_device",
        "admin/get_device_for_delete",
        "admin/check_device_archived",
        "admin/check_duplicates",
        "admin/check_orphaned",
        "admin/events_stats",
        "admin/table_sizes",
    ]
    
    loaded = 0
    failed = []
    for name in sql_files:
        try:
            load_sql(name)
            loaded += 1
        except (FileNotFoundError, ValueError, OSError) as e:
            logger.error(f"Failed to preload SQL query '{name}': {e}")
            failed.append(name)
    
    if failed:
        logger.error(f"SQL preload incomplete: {len(failed)} queries failed to load: {failed}")
    logger.info(f"Preloaded {loaded}/{len(sql_files)} SQL queries")

# Preload SQL queries at module import time
preload_sql_queries()

# FastAPI app initialization with OpenAPI documentation
app = FastAPI(
    title="ReportMate API",
    version="1.0.0",
    description="""
## ReportMate Device Management and Telemetry API

ReportMate provides a comprehensive REST API for managing device fleets and collecting telemetry data.

### Features
- **Device Management**: Query, archive, and delete devices
- **Fleet Analytics**: Bulk endpoints for hardware, software, network, and security data
- **Event Logging**: Real-time event ingestion and retrieval
- **Module Data**: Access individual module data (system, hardware, network, etc.)

### Authentication
All endpoints require authentication via one of:
- `X-Client-Passphrase` header (Windows/macOS clients)
- `X-Internal-Secret` header (container-to-container)
- Azure Managed Identity (when Easy Auth is configured)

### Rate Limiting
API requests are subject to rate limiting. Contact support for increased limits.
    """,
    contact={
        "name": "ReportMate Support",
        "url": "https://reportmate.ecuad.ca",
        "email": "support@ecuad.ca"
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html"
    },
    openapi_tags=[
        {
            "name": "devices",
            "description": "Device management operations - list, get, archive, delete devices"
        },
        {
            "name": "fleet",
            "description": "Fleet-wide bulk data endpoints for analytics dashboards"
        },
        {
            "name": "events",
            "description": "Event logging, retrieval, and real-time notifications"
        },
        {
            "name": "statistics",
            "description": "Fleet analytics, usage statistics, and reporting"
        },
        {
            "name": "admin",
            "description": "Administrative operations and diagnostics"
        },
        {
            "name": "health",
            "description": "Health checks and status endpoints"
        }
    ]
)

# Database connection configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://reportmate:password@localhost:5432/reportmate')

# Security: Authentication configuration
REPORTMATE_PASSPHRASE = os.getenv('REPORTMATE_PASSPHRASE')  # For Windows/Mac clients
API_INTERNAL_SECRET = os.getenv('API_INTERNAL_SECRET')  # For internal container-to-container auth (frontend to API)
AZURE_MANAGED_IDENTITY_HEADER = "X-MS-CLIENT-PRINCIPAL-ID"  # Azure Container Apps managed identity
DISABLE_AUTH = os.getenv('DISABLE_AUTH', 'false').lower() in ('true', '1', 'yes')

async def verify_authentication(
    request: Request,
    x_api_passphrase: str = Header(None, alias="X-API-PASSPHRASE"),
    x_client_passphrase: str = Header(None, alias="X-Client-Passphrase"),
    x_internal_secret: str = Header(None, alias="X-Internal-Secret"),
    x_ms_client_principal_id: str = Header(None, alias="X-MS-CLIENT-PRINCIPAL-ID"),
    x_forwarded_for: str = Header(None, alias="X-Forwarded-For"),
    user_agent: str = Header(None, alias="User-Agent")
):
    """
    Verify authentication for API endpoints.
    
    Authentication can be disabled via DISABLE_AUTH=true environment variable.
    
    Authentication methods supported (checked in order):
    0. Disabled: If DISABLE_AUTH=true, all requests are allowed (development only!)
    1. Internal Secret: X-Internal-Secret header (for container-to-container auth from frontend)
    2. Azure Managed Identity: X-MS-CLIENT-PRINCIPAL-ID header (when Easy Auth is properly configured)
    3. Passphrase: X-API-PASSPHRASE or X-Client-Passphrase header (for external Windows/macOS clients)
    
    NOTE: IP-based "internal network" detection (100.x.x.x) was REMOVED because it's insecure
    in Azure Container Apps - all traffic (internal AND external) routes through these IPs.
    
    This ensures:
    - Frontend container authenticates with shared internal secret (X-Internal-Secret)
    - Windows/macOS clients authenticate with passphrase (X-Client-Passphrase)
    - Random internet users get rejected (401 Unauthorized)
    """
    
    # Method 0: Authentication disabled via environment variable
    if DISABLE_AUTH:
        logger.debug(f"[SUCCESS] Authentication disabled via DISABLE_AUTH env var (User-Agent: {user_agent})")
        return {"method": "auth_disabled", "user_agent": user_agent}
    
    client_host = request.client.host if request.client else None
    
    # Method 1: Internal Secret authentication (for container-to-container, frontend→API)
    # This is the ONLY method for internal container communication - IP checks are NOT secure
    # in Azure Container Apps because ALL traffic (internal and external) goes through 100.x.x.x IPs
    if x_internal_secret:
        if not API_INTERNAL_SECRET:
            logger.error("[ERR] API_INTERNAL_SECRET not configured but client attempted internal secret auth")
            raise HTTPException(status_code=500, detail="Server internal authentication not configured")
        
        if x_internal_secret != API_INTERNAL_SECRET:
            logger.warning(f"[ERR] Invalid internal secret attempt from {user_agent} (IP: {client_host})")
            raise HTTPException(status_code=401, detail="Invalid internal authentication credentials")
        
        logger.info(f"[SUCCESS] Authenticated via internal secret from {user_agent} (IP: {client_host})")
        return {"method": "internal_secret", "user_agent": user_agent, "client_ip": client_host}
    
    # REMOVED: Internal network IP check (100.x.x.x, 10.x.x.x)
    # This was INSECURE because Azure Container Apps routes ALL traffic (including external)
    # through internal 100.x.x.x IPs. The X-Internal-Secret header is the only secure way
    # to verify internal container-to-container traffic.
    
    # Method 3: Azure Managed Identity (for when Easy Auth is properly configured)
    if x_ms_client_principal_id:
        logger.info(f"[SUCCESS] Authenticated via Azure Managed Identity: {x_ms_client_principal_id}")
        return {"method": "managed_identity", "principal_id": x_ms_client_principal_id}
    
    # Method 4: Passphrase authentication (for external Windows/macOS clients)
    # Accept both X-API-PASSPHRASE (testing) and X-Client-Passphrase (Windows/Mac clients)
    passphrase_header = x_api_passphrase or x_client_passphrase
    if passphrase_header:
        if not REPORTMATE_PASSPHRASE:
            logger.error("[ERR] REPORTMATE_PASSPHRASE not configured but client attempted passphrase auth")
            raise HTTPException(status_code=500, detail="Server authentication not configured")
        
        if passphrase_header != REPORTMATE_PASSPHRASE:
            logger.warning(f"[ERR] Invalid passphrase attempt from {user_agent} (IP: {client_host})")
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        header_type = "X-API-PASSPHRASE" if x_api_passphrase else "X-Client-Passphrase"
        logger.info(f"[SUCCESS] Authenticated via passphrase ({header_type}) from {user_agent} (IP: {client_host})")
        return {"method": "passphrase", "user_agent": user_agent, "client_ip": client_host}
    
    # No valid authentication method provided
    logger.warning(f"[ERR] Unauthenticated access attempt from {user_agent} (IP: {client_host}, X-Forwarded-For: {x_forwarded_for})")
    raise HTTPException(
        status_code=401,
        detail="Authentication required. X-Internal-Secret (internal), X-Client-Passphrase (clients), or internal network access required."
    )


def normalize_app_name(app_name: str) -> str:
    """
    Normalize application name by removing versions, editions, and architecture info.
    This matches the TypeScript normalization in the frontend filters API.
    """
    import re
    
    if not app_name or not isinstance(app_name, str):
        return ''
    
    normalized = app_name.strip()
    if not normalized:
        return ''
    
    # Remove placeholder/junk entries
    if '${{' in normalized or '}}' in normalized:
        return ''
    if normalized in ['Unknown', 'N/A']:
        return ''
    
    # Handle specific product lines
    if re.search(r'Microsoft Visual C\+\+ \d{4}', normalized, re.IGNORECASE):
        return 'Microsoft Visual C++ Redistributable'
    
    if normalized.startswith('Microsoft.NET') or 'Microsoft ASP.NET Core' in normalized:
        if 'Workload' in normalized:
            return 'Microsoft .NET Workload'
        if 'Sdk' in normalized or 'SDK' in normalized:
            return 'Microsoft .NET SDK'
        if 'ASP.NET Core' in normalized:
            return 'Microsoft ASP.NET Core'
        if any(x in normalized for x in ['Runtime', 'AppHost', 'Targeting Pack', 'Host FX Resolver']):
            return 'Microsoft .NET Runtime'
        return 'Microsoft .NET'
    
    if 'Microsoft Visual Studio Tools' in normalized:
        return 'Microsoft Visual Studio Tools'
    
    if re.search(r'Microsoft (365|Office 365)', normalized, re.IGNORECASE):
        return 'Microsoft 365'
    
    if re.search(r'Kinect for Windows Speech Recognition Language Pack', normalized, re.IGNORECASE):
        return 'Kinect for Windows Speech Recognition Language Pack'
    
    if re.search(r'Microsoft.*Language Pack', normalized, re.IGNORECASE):
        return 'Microsoft Language Pack'
    
    if re.search(r'Kits Configuration Installer', normalized, re.IGNORECASE):
        return 'Kits Configuration Installer'
    
    if re.search(r'Kofax VRS', normalized, re.IGNORECASE):
        return 'Kofax VRS'
    
    if normalized.startswith('Adobe '):
        match = re.search(r'Adobe ([A-Za-z\s]+)', normalized)
        if match:
            product = match.group(1).split()[0]
            if product != 'AIR':
                return f'Adobe {product}'
    
    if re.search(r'^7-Zip', normalized, re.IGNORECASE):
        return '7-Zip'
    
    if re.search(r'Google Chrome|Chrome', normalized, re.IGNORECASE):
        return 'Google Chrome'
    
    if re.search(r'Mozilla Firefox|Firefox', normalized, re.IGNORECASE):
        return 'Mozilla Firefox'
    
    # Generic version number removal
    normalized = re.sub(r'\s+v?\d+(\.\d+)*(\.\d+)*(\.\d+)*$', '', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\s+\d{4}(\.\d+)*$', '', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\s+-\s+\d+(\.\d+)*$', '', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\s+\(\d+(\.\d+)*(\.\d+)*\)$', '', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\s+build\s+\d+', '', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\s+\d+(\.\d+)*(\.\d+)*(\.\d+)*$', '', normalized, flags=re.IGNORECASE)
    
    # Remove architecture and platform info
    normalized = re.sub(r'\s+(x64|x86|64-bit|32-bit|amd64|i386)$', '', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\s+\((x64|x86|64-bit|32-bit|amd64|i386)\)$', '', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\s+\(Python\s+[\d\.]+\s+(64-bit|32-bit)\)$', '', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\s+\(git\s+[a-f0-9]+\)$', '', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\s+\([^)]*bit[^)]*\)', '', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\s+\([^)]*\d+\.\d+\.\d+[^)]*\)', '', normalized, flags=re.IGNORECASE)
    
    # Final cleanup
    normalized = re.sub(r'\s+', ' ', normalized)
    normalized = re.sub(r'\s*-\s*$', '', normalized)
    normalized = re.sub(r'^\s*-\s*', '', normalized)
    normalized = normalized.strip()
    
    if not normalized or len(normalized) < 2:
        return ''
    
    return normalized


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
                ssl_context=True,
                timeout=30  # 30 second connection timeout
            )
            # Set query timeout - increased for diagnostics
            cursor = conn.cursor()
            cursor.execute("SET statement_timeout = '120s'")  # 120 second query timeout
            conn.commit()
            cursor.close()
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

class InventorySummary(BaseModel):
    """Trimmed inventory data returned in bulk responses."""
    deviceName: Optional[str] = None
    assetTag: Optional[str] = None
    serialNumber: Optional[str] = None
    location: Optional[str] = None
    department: Optional[str] = None
    usage: Optional[str] = None
    catalog: Optional[str] = None
    owner: Optional[str] = None


class DeviceModules(BaseModel):
    """Device modules container for bulk endpoint - lightweight summaries only."""
    system: Optional[SystemModule] = None
    inventory: Optional[InventorySummary] = None  # Inventory summary for bulk response

class DeviceInfo(BaseModel):
    """
    Device information with database schema mapping.
    All inventory and system details are in nested modules.
    Frontend calculates status from lastSeen.
    """
    serialNumber: str  # PRIMARY KEY - Always use this
    deviceId: str      # UUID from device_id column
    deviceName: Optional[str] = None
    name: Optional[str] = None
    hostname: Optional[str] = None  # Network hostname for search
    lastSeen: Optional[str] = None
    createdAt: Optional[str] = None
    registrationDate: Optional[str] = None
    status: Optional[str] = None
    assetTag: Optional[str] = None
    platform: Optional[str] = None
    osName: Optional[str] = None
    osVersion: Optional[str] = None
    usage: Optional[str] = None
    catalog: Optional[str] = None
    department: Optional[str] = None
    location: Optional[str] = None
    owner: Optional[str] = None
    lastEventTime: Optional[str] = None
    totalEvents: Optional[int] = None
    inventory: Optional[InventorySummary] = None
    modules: Optional[DeviceModules] = None

class DevicesResponse(BaseModel):
    """Response model for bulk devices endpoint."""
    devices: List[DeviceInfo]
    total: int
    message: str
    page: Optional[int] = None
    pageSize: Optional[int] = None
    hasMore: Optional[bool] = None


def infer_platform(os_name: Optional[str]) -> Optional[str]:
    """Infer platform from OS name."""
    if not os_name:
        return None

    lower_name = os_name.lower()
    if "windows" in lower_name:
        return "Windows"
    if "mac" in lower_name or "darwin" in lower_name:
        return "macOS"
    if "linux" in lower_name:
        return "Linux"
    return None


def build_os_summary(os_name: Optional[str], os_version: Optional[str]) -> Dict[str, Optional[str]]:
    """Construct a minimal operating system summary for bulk responses."""
    summary: Dict[str, Optional[str]] = {
        "name": os_name,
        "version": os_version,
    }

    if os_version:
        parts = [part for part in os_version.split('.') if part]
        if len(parts) >= 3:
            summary["build"] = parts[2]
        if len(parts) >= 4:
            summary["featureUpdate"] = parts[3]

    return {key: value for key, value in summary.items() if value}

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

@app.get("/api/health", tags=["health"])
async def health_check():
    """
    Health check endpoint for monitoring and load balancers.
    
    **No authentication required.**
    
    **Response:**
    - status: "healthy" or "unhealthy"
    - database: Connection status
    - version: API version
    """
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

@app.get("/api/dashboard", dependencies=[Depends(verify_authentication)])
async def get_dashboard_data(
    events_limit: int = Query(default=50, ge=1, le=200, alias="eventsLimit"),
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
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # === DEVICES QUERY (from /api/devices) ===
        archive_filter_where = "" if include_archived else "WHERE d.archived = FALSE"
        
        # Get total device count
        total_devices = 0
        try:
            archive_filter = "" if include_archived else "WHERE archived = FALSE"
            cursor.execute(f"SELECT COUNT(*) FROM devices {archive_filter}")
            total_result = cursor.fetchone()
            if total_result and total_result[0] is not None:
                total_devices = int(total_result[0])
        except Exception as count_error:
            logger.warning(f"Failed to get total device count: {count_error}")

        # Fetch all devices with inventory and system data (NO installs - too large)
        # Install stats are calculated via optimized SQL queries below
        device_query = f"""
        SELECT 
            d.id,
            d.device_id,
            d.serial_number,
            d.name,
            d.os,
            d.os_name,
            d.os_version,
            d.last_seen,
            d.archived,
            d.created_at,
            i.data as inventory_data,
            s.data as system_data
        FROM devices d
        LEFT JOIN inventory i ON d.serial_number = i.device_id
        LEFT JOIN system s ON d.serial_number = s.device_id
        {archive_filter_where}
        ORDER BY d.last_seen DESC NULLS LAST
        """
        
        cursor.execute(device_query)
        device_rows = cursor.fetchall()
        
        devices = []
        for row in device_rows:
            (db_id, device_id, serial_number, device_name, os_val, os_name_db, os_version_db, 
             last_seen, archived, created_at, inventory_data_raw, system_data_raw) = row
            
            # Extract full OS details from system module
            system_os = {}
            if system_data_raw:
                try:
                    system_data = system_data_raw if isinstance(system_data_raw, dict) else json.loads(system_data_raw)
                    # System data might be a list or dict depending on how it was stored
                    if isinstance(system_data, list) and len(system_data) > 0:
                        system_data = system_data[0]
                    
                    # Extract operatingSystem from system module
                    if "operatingSystem" in system_data:
                        system_os = system_data["operatingSystem"]
                    elif "operating_system" in system_data:
                        system_os = system_data["operating_system"]
                except Exception as sys_error:
                    logger.warning(f"Failed to parse system data for {serial_number}: {sys_error}")
            
            # Use system module OS data if available, otherwise fall back to devices table
            final_os_name = system_os.get("name") or os_name_db or os_val or "Unknown"
            final_os_version = system_os.get("version") or os_version_db or ""
            os_build = system_os.get("build") or system_os.get("buildNumber") or ""
            os_display_version = system_os.get("displayVersion") or ""
            os_feature_update = system_os.get("featureUpdate") or ""
            os_edition = system_os.get("edition") or ""
            os_architecture = system_os.get("architecture") or ""
            
            # Determine platform from OS name
            platform = "Windows" if "windows" in (final_os_name or "").lower() else "macOS" if "mac" in (final_os_name or "").lower() else "Unknown"
            
            # Determine status based on last_seen
            status = "online"
            if last_seen:
                time_diff = datetime.now(timezone.utc) - last_seen.replace(tzinfo=timezone.utc) if last_seen.tzinfo is None else datetime.now(timezone.utc) - last_seen
                if time_diff.total_seconds() > 86400:  # 24 hours
                    status = "offline"
                elif time_diff.total_seconds() > 3600:  # 1 hour
                    status = "idle"
            
            # Extract inventory data (catalog, usage, department, location)
            inv_device_name = device_name
            inv_catalog = None
            inv_usage = None
            inv_department = None
            inv_location = None
            
            if inventory_data_raw:
                try:
                    inventory = inventory_data_raw if isinstance(inventory_data_raw, dict) else json.loads(inventory_data_raw)
                    inv_device_name = inventory.get("deviceName") or device_name
                    inv_catalog = inventory.get("catalog")
                    inv_usage = inventory.get("usage")
                    inv_department = inventory.get("department")
                    inv_location = inventory.get("location")
                except Exception as inv_error:
                    logger.warning(f"Failed to parse inventory for {serial_number}: {inv_error}")
            
            # NOTE: We no longer include full installs data in dashboard response
            # Install error/warning counts are calculated via optimized SQL queries below
            # This reduces response size from ~26MB to ~1MB
            
            # Build complete OS info object with all version details
            os_info = {
                "name": final_os_name,
                "version": final_os_version,
                "build": os_build,
                "displayVersion": os_display_version,
                "featureUpdate": os_feature_update,
                "edition": os_edition,
                "architecture": os_architecture
            }
            
            # Build modules object (NO installs - counts come from installStats)
            modules_obj = {
                "system": {
                    "operatingSystem": os_info
                }
            }
            
            # Add inventory if present
            if any([inv_catalog, inv_usage, inv_department, inv_location]):
                modules_obj["inventory"] = {
                    "catalog": inv_catalog,
                    "usage": inv_usage,
                    "department": inv_department,
                    "location": inv_location
                }
            
            device = {
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
            }
            devices.append(device)
        
        # === INSTALL STATS QUERY - OPTIMIZED FOR DASHBOARD ===
        # Count ITEMS (not devices) with errors and warnings
        # Includes both Cimian (Windows) and Munki (macOS) items
        install_stats = {
            "devicesWithErrors": 0,
            "devicesWithWarnings": 0,
            "totalErrorItems": 0,      # Total error items across all devices
            "totalWarningItems": 0,    # Total warning items across all devices
            "hasInstallData": False    # Whether any install data exists
        }
        
        try:
            # Count total ERROR ITEMS from Cimian (Windows)
            cursor.execute("""
                SELECT COUNT(*)
                FROM devices d
                INNER JOIN installs i ON d.serial_number = i.device_id
                CROSS JOIN LATERAL jsonb_array_elements(i.data->'cimian'->'items') AS item
                WHERE d.archived = FALSE
                    AND (
                        LOWER(item->>'currentStatus') LIKE '%error%'
                        OR LOWER(item->>'currentStatus') LIKE '%failed%'
                        OR LOWER(item->>'currentStatus') = 'problem'
                        OR LOWER(item->>'currentStatus') = 'install-error'
                    )
            """)
            cimian_errors = cursor.fetchone()
            if cimian_errors and cimian_errors[0]:
                install_stats["totalErrorItems"] += cimian_errors[0]
            
            # Count total ERROR ITEMS from Munki (macOS)
            cursor.execute("""
                SELECT COUNT(*)
                FROM devices d
                INNER JOIN installs i ON d.serial_number = i.device_id
                CROSS JOIN LATERAL jsonb_array_elements(i.data->'munki'->'items') AS item
                WHERE d.archived = FALSE
                    AND (
                        LOWER(item->>'status') LIKE '%error%'
                        OR LOWER(item->>'status') LIKE '%failed%'
                    )
            """)
            munki_errors = cursor.fetchone()
            if munki_errors and munki_errors[0]:
                install_stats["totalErrorItems"] += munki_errors[0]
            
            # Count total WARNING ITEMS from Cimian (Windows)
            # Note: 'pending' is NOT a warning - it's in the pending category
            cursor.execute("""
                SELECT COUNT(*)
                FROM devices d
                INNER JOIN installs i ON d.serial_number = i.device_id
                CROSS JOIN LATERAL jsonb_array_elements(i.data->'cimian'->'items') AS item
                WHERE d.archived = FALSE
                    AND (
                        LOWER(item->>'currentStatus') LIKE '%warning%'
                        OR LOWER(item->>'currentStatus') = 'needs-attention'
                    )
            """)
            cimian_warnings = cursor.fetchone()
            if cimian_warnings and cimian_warnings[0]:
                install_stats["totalWarningItems"] += cimian_warnings[0]
            
            # Count total WARNING ITEMS from Munki (macOS)
            cursor.execute("""
                SELECT COUNT(*)
                FROM devices d
                INNER JOIN installs i ON d.serial_number = i.device_id
                CROSS JOIN LATERAL jsonb_array_elements(i.data->'munki'->'items') AS item
                WHERE d.archived = FALSE
                    AND LOWER(item->>'status') LIKE '%warning%'
            """)
            munki_warnings = cursor.fetchone()
            if munki_warnings and munki_warnings[0]:
                install_stats["totalWarningItems"] += munki_warnings[0]
            
            # Check if any install data exists (for hasInstallData flag)
            cursor.execute("""
                SELECT EXISTS(
                    SELECT 1 FROM installs i
                    INNER JOIN devices d ON d.serial_number = i.device_id
                    WHERE d.archived = FALSE
                    AND (
                        jsonb_array_length(COALESCE(i.data->'cimian'->'items', '[]'::jsonb)) > 0
                        OR jsonb_array_length(COALESCE(i.data->'munki'->'items', '[]'::jsonb)) > 0
                    )
                )
            """)
            has_data = cursor.fetchone()
            install_stats["hasInstallData"] = has_data[0] if has_data else False
            
            logger.info(f"Install stats: {install_stats['totalErrorItems']} error items, {install_stats['totalWarningItems']} warning items, hasData={install_stats['hasInstallData']}")
        except Exception as stats_error:
            logger.warning(f"Failed to calculate install stats: {stats_error}")
            # Keep zeros if query fails
        
        # === EVENTS QUERY ===
        events = []
        try:
            cursor.execute("""
                SELECT 
                    e.id,
                    e.device_id,
                    COALESCE(i.data->>'device_name', i.data->>'deviceName') as device_name,
                    e.event_type,
                    e.message,
                    e.timestamp
                FROM events e
                LEFT JOIN inventory i ON e.device_id = i.device_id
                ORDER BY e.timestamp DESC 
                LIMIT %s
            """, (events_limit,))
            
            event_rows = cursor.fetchall()
            for row in event_rows:
                event_id, device_id, device_name, event_type, message, timestamp = row
                events.append({
                    "id": event_id,
                    "device": device_id,
                    "deviceName": device_name or device_id,
                    "kind": event_type,
                    "message": message,
                    "ts": timestamp.isoformat() if timestamp else None,
                    "serialNumber": device_id,
                    "eventType": event_type,
                    "timestamp": timestamp.isoformat() if timestamp else None
                })
        except Exception as events_error:
            logger.warning(f"Failed to get events for dashboard: {events_error}")
        
        conn.close()
        
        # Return consolidated dashboard data
        return {
            "devices": devices,
            "totalDevices": total_devices,
            "installStats": install_stats,
            "events": events,
            "totalEvents": len(events),
            "lastUpdated": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get dashboard data: {e}")
        if conn:
            conn.close()
        raise HTTPException(status_code=500, detail=f"Failed to retrieve dashboard data: {str(e)}")

@app.get("/api/devices", response_model=DevicesResponse, dependencies=[Depends(verify_authentication)], tags=["devices"])
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
        conn = get_db_connection()
        cursor = conn.cursor()

        # Build archive filter for count query
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
            n.data as network_data
        FROM devices d
        LEFT JOIN inventory i ON i.device_id = d.serial_number
        LEFT JOIN network n ON n.device_id = d.serial_number
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
            ) = row

            serial = serial_number or str(device_id)

            os_summary = build_os_summary(os_name or os, os_version)
            # Use stored platform from database, fall back to inference if not set
            device_platform = platform or infer_platform(os_name or os)

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
                        allowed_keys = [
                            "deviceName",
                            "assetTag",
                            "serialNumber",
                            "location",
                            "department",
                            "usage",
                            "catalog",
                            "owner",
                        ]
                        summary = {
                            key: raw_inventory.get(key)
                            for key in allowed_keys
                            if raw_inventory.get(key) not in (None, "")
                        }
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

        return {
            "devices": devices,
            "total": total_devices or len(devices),
            "message": f"Successfully retrieved {len(devices)} devices",
            "page": page,
            "pageSize": page_size,
            "hasMore": has_more,
        }

    except Exception as e:
        print(f"[ERROR] get_all_devices failed: {e}")
        logger.error(f"Failed to retrieve devices: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve devices: {str(e)}")
    finally:
        if conn:
            conn.close()

@app.get("/api/device/{serial_number}", dependencies=[Depends(verify_authentication)], tags=["devices"])
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
        module_tables = ["applications", "hardware", "installs", "network", "security", "inventory", "management", "profiles", "peripherals"]
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
        
        # Build response with clean schema (no top-level inventory duplication)
        response = {
            "success": True,
            "device": {
                "serialNumber": serial_num or device_id,
                "deviceId": device_uuid or device_id,
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


@app.get("/api/device/{serial_number}/installs/log", dependencies=[Depends(verify_authentication)])
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
@app.get("/api/device/{serial_number}/events", dependencies=[Depends(verify_authentication)])
async def get_device_events(serial_number: str, limit: int = 100):
    """
    Get events for a specific device.
    
    Returns event history for device activity logging and monitoring.
    Used by EventsTab for displaying device events.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get device record to verify it exists
        cursor.execute("""
            SELECT id FROM devices 
            WHERE serial_number = %s OR id = %s
        """, (serial_number, serial_number))
        
        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            raise HTTPException(status_code=404, detail="Device not found")
        
        device_id = device_row[0]
        
        # Get events for this device
        # NOTE: events.device_id contains the serial_number (same as devices.id)
        cursor.execute("""
            SELECT id, event_type, message, details, timestamp, created_at
            FROM events
            WHERE device_id = %s
            ORDER BY timestamp DESC
            LIMIT %s
        """, (device_id, limit))
        
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


@app.get("/api/device/{device_id}/info", dependencies=[Depends(verify_authentication)])
async def get_device_info_fast(device_id: str):
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
        
        # Get device record
        cursor.execute("""
            SELECT id, device_id, serial_number, last_seen, created_at
            FROM devices 
            WHERE serial_number = %s OR id = %s
        """, (device_id, device_id))
        
        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            raise HTTPException(status_code=404, detail="Device not found")
        
        _, device_uuid, serial_num, last_seen, created_at = device_row
        
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
                "modules": info_modules
            }
        }
        
        logger.info(f"Fast info fetch for {device_id}: {len(json.dumps(response))} bytes")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get fast info for {device_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve device info: {str(e)}")


@app.get("/api/device/{device_id}/modules/{module_name}", dependencies=[Depends(verify_authentication)])
async def get_device_module(device_id: str, module_name: str):
    """
    Get individual module data for progressive/on-demand loading.
    
    Supports all module types:
    - applications, hardware, installs, network, security
    - inventory, management, profiles, system
    
    Used for:
    1. Background progressive loading (after fast info load)
    2. On-demand loading when user clicks tabs
    """
    try:
        # Validate module name
        valid_modules = [
            "applications", "hardware", "installs", "network", "security",
            "inventory", "management", "profiles", "system", "displays",
            "printers", "peripherals"
        ]
        
        if module_name not in valid_modules:
            raise HTTPException(status_code=400, detail=f"Invalid module: {module_name}")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get device serial number
        cursor.execute("""
            SELECT serial_number FROM devices 
            WHERE serial_number = %s OR id = %s
        """, (device_id, device_id))
        
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
        
        logger.info(f"Module fetch {module_name} for {device_id}: {len(json.dumps(response))} bytes")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get module {module_name} for {device_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve module: {str(e)}")


@app.get("/api/devices/applications", dependencies=[Depends(verify_authentication)])
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
    loadAll: bool = False,
    include_archived: bool = Query(default=False, alias="includeArchived")
):
    """
    Bulk applications endpoint with filtering support.
    
    Returns flattened list of applications across all devices with filtering.
    Frontend is responsible for search/filtering logic - this is just data retrieval.
    
    By default, archived devices are excluded. Use includeArchived=true to include them.
    """
    try:
        logger.info(f"Fetching bulk applications (loadAll={loadAll}, includeArchived={include_archived}, filters={dict(request.query_params)})")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Parse comma-separated filter values
        device_name_list = deviceNames.split(',') if deviceNames else []
        app_name_list = applicationNames.split(',') if applicationNames else []
        publisher_list = publishers.split(',') if publishers else []
        category_list = categories.split(',') if categories else []
        version_list = versions.split(',') if versions else []
        
        # Build WHERE clause for device filtering (including archive filter)
        where_conditions = [
            "d.serial_number IS NOT NULL", 
            "d.serial_number NOT LIKE 'TEST-%'", 
            "d.serial_number != 'localhost'"
        ]
        
        # Add archive filter
        if not include_archived:
            where_conditions.append("d.archived = FALSE")
        
        query_params = []
        param_index = 1
        
        if device_name_list:
            placeholders = ', '.join([f'${i}' for i in range(param_index, param_index + len(device_name_list) * 3)])
            where_conditions.append(f"(COALESCE(inv.data->>'device_name', inv.data->>'deviceName') IN ({placeholders}) OR COALESCE(inv.data->>'computer_name', inv.data->>'computerName') IN ({placeholders}) OR d.serial_number IN ({placeholders}))")
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
            COALESCE(inv.data->>'device_name', inv.data->>'deviceName') as device_name,
            COALESCE(inv.data->>'computer_name', inv.data->>'computerName') as computer_name,
            inv.data->>'usage' as usage,
            inv.data->>'catalog' as catalog,
            inv.data->>'location' as location,
            COALESCE(inv.data->>'asset_tag', inv.data->>'assetTag') as asset_tag
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
                    # Note: Using substring matching to be more inclusive (shows "Bifrost" AND "Bifrost Extension" when "Bifrost" selected)
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

@app.get("/api/devices/hardware", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_hardware(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results")
):
    """
    Bulk hardware endpoint.
    
    Returns flattened list of hardware details across all devices.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers (serial number, device ID, name)
    - Hardware specs (manufacturer, model, CPU, memory, storage, GPU)
    - OS information (name, version, architecture)
    """
    try:
        logger.info("Fetching bulk hardware data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_hardware")
        
        cursor.execute(query, {"include_archived": include_archived})
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

@app.get("/api/devices/installs", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_installs(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results")
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
                        'source': 'cimian',
                        'raw': item
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
                        'source': 'munki',
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



@app.get("/api/devices/installs/full", dependencies=[Depends(verify_authentication)])
async def get_bulk_installs_full(
    include_archived: bool = Query(default=False, alias="includeArchived")
):
    """
    Bulk installs endpoint returning FULL device records with nested structure.
    
    Unlike /api/devices/installs (flat items), this returns devices with complete
    modules.installs structure including config, version, sessions etc.
    Used by /devices/installs page for full UI rendering.
    
    By default, archived devices are excluded. Use includeArchived=true to include them.
    """
    try:
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
                serial_number, device_uuid, last_seen, installs_data, device_name, usage, catalog, location, asset_tag = row
                
                # Extract only what UI needs from installs_data
                installs_obj = installs_data if isinstance(installs_data, dict) else {}
                cimian_data = installs_obj.get('cimian', {})
                munki_data = installs_obj.get('munki', {})
                
                # Build lightweight installs structure (exclude runLog which is huge)
                lightweight_installs = {}
                
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
        
        return devices
        
    except Exception as e:
        logger.error(f"Failed to get bulk installs (full): {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk installs: {str(e)}")


@app.get("/api/devices/network", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_network(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results")
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
                serial_number, device_uuid, last_seen, network_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag, os_name, os_version, build_number, uptime, boot_time = row
                
                device_obj = {
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': collected_at.isoformat() if collected_at else None,
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
        
        return devices
        
    except Exception as e:
        logger.error(f"Failed to get bulk network: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk network: {str(e)}")

@app.get("/api/devices/security", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_security(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results")
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
                serial_number, device_uuid, last_seen, security_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag = row
                
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
                    'raw': security_data
                })
            except Exception as e:
                logger.warning(f"Error processing security for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with security data")
        return devices
        
    except Exception as e:
        logger.error(f"Failed to get bulk security: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk security: {str(e)}")

@app.get("/api/devices/profiles", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_profiles(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results")
):
    """
    **DEPRECATED:** This endpoint is deprecated. Profiles functionality has been integrated into Management module.
    
    **Use `/api/devices/management` instead** for profile data.
    
    This endpoint is maintained for backward compatibility but will be removed in a future version.
    
    Bulk profiles endpoint for fleet-wide configuration profiles.
    
    Returns devices with MDM profiles and configuration policies.
    Used by /devices/profiles page for fleet-wide profile visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers and inventory
    - Profile data (MDM, Intune, security configurations)
    - Profile metadata and configuration details
    
    **Migration Guide:**
    - Replace `/api/devices/profiles` calls with `/api/devices/management`
    - Profile data is available in the `management` module of device responses
    - Use `/api/device/{serial}/modules/management` for individual device profiles
    """
    try:
        logger.info("Fetching bulk profiles data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_profiles")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        
        logger.info(f"Retrieved {len(rows)} devices with profiles data")
        
        devices = []
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, profiles_data, profiles_collected_at, profiles_updated_at, device_name, computer_name, usage, catalog, location, asset_tag = row
                
                # Parse profiles_data JSONB
                profile_data = json.loads(profiles_data) if isinstance(profiles_data, str) else profiles_data or {}
                
                # Count policies from profiles data if available
                intune_count = len(profile_data.get('intune_policies', profile_data.get('intunePolicies', [])))
                security_count = len(profile_data.get('security_policies', profile_data.get('securityPolicies', [])))
                mdm_count = len(profile_data.get('mdm_configurations', profile_data.get('mdmConfigurations', [])))
                total_policies = intune_count + security_count + mdm_count
                
                devices.append({
                    'id': serial_number,
                    'deviceId': serial_number,
                    'deviceName': device_name or computer_name or serial_number,
                    'serialNumber': serial_number,
                    'assetTag': asset_tag,
                    'lastSeen': last_seen.isoformat() if last_seen else None,
                    'collectedAt': profiles_updated_at.isoformat() if profiles_updated_at else None,
                    'usage': usage,
                    'catalog': catalog,
                    'location': location,
                    'totalPolicies': total_policies,
                    'intunePolicyCount': intune_count,
                    'securityPolicyCount': security_count,
                    'mdmConfigCount': mdm_count,
                    'raw': profile_data
                })
            except Exception as e:
                logger.warning(f"Error processing profiles for device {row[0]}: {e}")
                continue
        
        conn.close()
        logger.info(f"Processed {len(devices)} devices with profiles data")
        return devices
        
    except Exception as e:
        logger.error(f"Failed to get bulk profiles: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk profiles: {str(e)}")

@app.get("/api/devices/management", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_management(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results")
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
                serial_number, device_uuid, last_seen, management_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag, department = row
                
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
                
                # Provider detection - support multiple sources
                # Priority: explicit provider field > certificate issuer > "Unknown"
                provider = mdm_enrollment.get('provider')
                if not provider:
                    # Try to get from certificate data (Mac)
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
                    provider = 'Unknown'
                
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
                    # Extract flattened MDM fields for table display (using actual field names from data)
                    'provider': provider,
                    'enrollmentStatus': enrollment_status,
                    'enrollmentType': enrollment_type,
                    'intuneId': device_details.get('intuneDeviceId') or device_details.get('intune_device_id') or 'N/A',
                    'tenantName': tenant_details.get('tenantName') or tenant_details.get('tenant_name') or tenant_details.get('organization') or 'N/A',
                    'isEnrolled': is_enrolled,
                    'raw': management_data
                })
            except Exception as e:
                logger.warning(f"Error processing management for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with management data")
        return devices
        
    except Exception as e:
        logger.error(f"Failed to get bulk management: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk management: {str(e)}")

@app.get("/api/devices/inventory", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_inventory(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results")
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
                serial_number, device_uuid, last_seen, inventory_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag, department = row
                
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
                    'raw': inventory_data
                })
            except Exception as e:
                logger.warning(f"Error processing inventory for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with inventory data")
        return devices
        
    except Exception as e:
        logger.error(f"Failed to get bulk inventory: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk inventory: {str(e)}")

@app.get("/api/devices/system", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_system(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results")
):
    """
    Bulk system endpoint for fleet-wide OS and system information.
    
    Returns devices with OS details, uptime, updates, services, etc.
    Used by /devices/system page for fleet-wide system visibility.
    By default, archived devices are excluded. Use includeArchived=true to include them.
    
    **Response includes:**
    - Device identifiers and inventory
    - Operating system name, version, build number
    - System uptime, boot time
    - Pending updates and service status
    """
    try:
        logger.info("Fetching bulk system data")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Load SQL from external file - uses parameterized archive filter
        query = load_sql("devices/bulk_system")
        
        cursor.execute(query, {"include_archived": include_archived})
        rows = cursor.fetchall()
        conn.close()
        
        logger.info(f"Retrieved {len(rows)} devices with system data")
        
        devices = []
        for row in rows:
            try:
                serial_number, device_uuid, last_seen, system_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag = row
                
                # Extract system data (handle array format)
                if isinstance(system_data, list) and len(system_data) > 0:
                    system_data = system_data[0]
                
                # Extract operating system info from raw data
                os_info = system_data.get('operatingSystem', {}) if system_data else {}
                uptime_str = system_data.get('uptime') if system_data else None
                
                # Parse uptime string (format: "d.hh:mm:ss") to seconds
                uptime_seconds = None
                if uptime_str:
                    try:
                        parts = uptime_str.replace('.', ':').split(':')
                        if len(parts) >= 4:
                            days, hours, minutes, seconds = int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])
                            uptime_seconds = days * 86400 + hours * 3600 + minutes * 60 + seconds
                    except (ValueError, IndexError):
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
                    'operatingSystem': operating_system.strip() or None,
                    'osVersion': os_info.get('version'),
                    'buildNumber': os_info.get('build'),
                    'uptime': uptime_seconds,
                    'bootTime': system_data.get('bootTime') if system_data else None,
                    'raw': system_data
                })
            except Exception as e:
                logger.warning(f"Error processing system for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with system data")
        return devices
        
    except Exception as e:
        logger.error(f"Failed to get bulk system: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk system: {str(e)}")

@app.get("/api/devices/peripherals", dependencies=[Depends(verify_authentication)], tags=["fleet"])
async def get_bulk_peripherals(
    include_archived: bool = Query(default=False, alias="includeArchived", description="Include archived devices in results")
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
                serial_number, device_uuid, last_seen, peripherals_data, collected_at, device_name, computer_name, usage, catalog, location, asset_tag = row
                
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
                    'raw': peripherals_data or {}
                })
            except Exception as e:
                logger.warning(f"Error processing peripherals for device {row[0]}: {e}")
                continue
        
        logger.info(f"Processed {len(devices)} devices with peripherals data")
        return devices
        
    except Exception as e:
        logger.error(f"Failed to get bulk peripherals: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve bulk peripherals: {str(e)}")

@app.get("/api/events", dependencies=[Depends(verify_authentication)], tags=["events"])
async def get_events(
    limit: int = Query(default=100, ge=1, le=1000, description="Maximum number of events to return"),
    offset: int = Query(default=0, ge=0, description="Number of events to skip (for pagination)"),
    startDate: str = Query(default=None, description="Filter events after this ISO8601 date"),
    endDate: str = Query(default=None, description="Filter events before this ISO8601 date")
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
    
    **Response includes:**
    - Event ID, type, message, timestamp
    - Device serial number and name
    - Total count for pagination
    """
    try:
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
        
        # Get total count first for pagination info
        count_query = load_sql("events/count_events")
        cursor.execute(count_query, {"start_date": start_date, "end_date": end_date})
        total_count = cursor.fetchone()[0]
        
        # JOIN with inventory to get device names and assetTag in single query
        query = load_sql("events/list_events")
        cursor.execute(query, {
            "limit": limit, 
            "offset": offset,
            "start_date": start_date,
            "end_date": end_date
        })
        
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            event_id, device_id, device_name, asset_tag, event_type, message, timestamp = row
            events.append({
                # Essential fields for events page
                "id": event_id,
                "device": device_id,  # Serial number (used for links)
                "deviceName": device_name or device_id,  # Friendly name from inventory
                "assetTag": asset_tag,  # Asset tag for display
                "kind": event_type,  # Event type (success/warning/error/info)
                "message": message,  # User-friendly message
                "ts": timestamp.isoformat() if timestamp else None,  # Timestamp
                # Legacy compatibility fields (minimal)
                "serialNumber": device_id,
                "eventType": event_type,
                "timestamp": timestamp.isoformat() if timestamp else None
            })
        
        return {
            "success": True,
            "events": events, 
            "total": total_count,
            "totalEvents": total_count,  # Frontend expects this field
            "count": len(events),
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Failed to get events: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve events: {str(e)}")

@app.get("/api/events/{event_id}/payload", dependencies=[Depends(verify_authentication)])
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
                valid_tables = ['applications', 'displays', 'hardware', 'installs', 'inventory', 
                               'management', 'network', 'printers', 'profiles', 'security', 'system']
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


@app.get("/api/stats/applications/usage", dependencies=[Depends(verify_authentication)])
async def get_application_usage_stats(
    days: int = Query(default=30, ge=1, le=365, description="Number of days to look back for usage data"),
    include_archived: bool = Query(default=False, alias="includeArchived")
):
    """
    Get aggregated application usage statistics for fleet-wide analytics.
    
    Returns:
        - Top applications by total usage time
        - Top applications by launch count
        - Top users by usage time
        - Unused applications (no usage in specified days)
        - Summary statistics
    
    This endpoint queries the application_usage_events and application_usage_summary tables
    populated by the Windows client's kernel process telemetry.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if usage tables exist
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'application_usage_events'
            )
        """)
        usage_tables_exist = cursor.fetchone()[0]
        
        if not usage_tables_exist:
            # Usage tables don't exist yet - return empty stats with appropriate message
            logger.info("Application usage tables not yet created - returning empty stats")
            conn.close()
            return {
                "status": "unavailable",
                "message": "Application usage tracking not yet deployed. Run schema migration 005-application-usage-tracking.sql to enable.",
                "topAppsByTime": [],
                "topAppsByLaunches": [],
                "topUsers": [],
                "unusedApps": [],
                "summary": {
                    "totalAppsTracked": 0,
                    "totalUsageHours": 0,
                    "totalLaunches": 0,
                    "uniqueUsers": 0,
                    "devicesWithUsageData": 0,
                    "appsWithNoRecentUsage": 0
                },
                "lastUpdated": datetime.now(timezone.utc).isoformat(),
                "lookbackDays": days
            }
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Archive filter clause
        archive_join = ""
        archive_where = ""
        if not include_archived:
            archive_join = "INNER JOIN devices d ON e.device_id = d.serial_number"
            archive_where = "AND d.archived = FALSE"
        
        # Top applications by total usage time
        cursor.execute(f"""
            SELECT 
                e.application_name,
                SUM(e.duration_seconds) as total_seconds,
                COUNT(*) as launch_count,
                COUNT(DISTINCT e.username) as unique_users,
                MAX(e.end_time) as last_used
            FROM application_usage_events e
            {archive_join}
            WHERE e.start_time >= $1
            {archive_where}
            GROUP BY e.application_name
            ORDER BY total_seconds DESC
            LIMIT 20
        """, (cutoff_date,))
        
        top_by_time = []
        for row in cursor.fetchall():
            app_name, total_secs, launches, users, last_used = row
            top_by_time.append({
                "name": app_name,
                "totalSeconds": int(total_secs) if total_secs else 0,
                "launchCount": launches,
                "uniqueUsers": users,
                "lastUsed": last_used.isoformat() if last_used else None
            })
        
        # Top applications by launch count
        cursor.execute(f"""
            SELECT 
                e.application_name,
                COUNT(*) as launch_count,
                SUM(e.duration_seconds) as total_seconds,
                COUNT(DISTINCT e.username) as unique_users,
                MAX(e.end_time) as last_used
            FROM application_usage_events e
            {archive_join}
            WHERE e.start_time >= $1
            {archive_where}
            GROUP BY e.application_name
            ORDER BY launch_count DESC
            LIMIT 20
        """, (cutoff_date,))
        
        top_by_launches = []
        for row in cursor.fetchall():
            app_name, launches, total_secs, users, last_used = row
            top_by_launches.append({
                "name": app_name,
                "launchCount": launches,
                "totalSeconds": int(total_secs) if total_secs else 0,
                "uniqueUsers": users,
                "lastUsed": last_used.isoformat() if last_used else None
            })
        
        # Top users by total usage time
        cursor.execute(f"""
            SELECT 
                e.username,
                SUM(e.duration_seconds) as total_seconds,
                COUNT(*) as launch_count,
                COUNT(DISTINCT e.application_name) as apps_used
            FROM application_usage_events e
            {archive_join}
            WHERE e.start_time >= $1
                AND e.username IS NOT NULL
                AND e.username != ''
            {archive_where}
            GROUP BY e.username
            ORDER BY total_seconds DESC
            LIMIT 15
        """, (cutoff_date,))
        
        top_users = []
        for row in cursor.fetchall():
            username, total_secs, launches, apps = row
            top_users.append({
                "username": username,
                "totalSeconds": int(total_secs) if total_secs else 0,
                "launchCount": launches,
                "appsUsed": apps
            })
        
        # Summary statistics
        cursor.execute(f"""
            SELECT 
                COUNT(DISTINCT application_name) as total_apps,
                COALESCE(SUM(duration_seconds), 0) as total_seconds,
                COUNT(*) as total_launches,
                COUNT(DISTINCT username) as unique_users,
                COUNT(DISTINCT device_id) as devices
            FROM application_usage_events e
            {archive_join.replace('e.device_id', 'e.device_id') if archive_join else ''}
            WHERE start_time >= $1
            {archive_where}
        """, (cutoff_date,))
        
        summary_row = cursor.fetchone()
        total_apps, total_secs, total_launches, unique_users, devices = summary_row
        
        # Get count of installed apps with no recent usage
        # This requires joining with the applications table
        cursor.execute(f"""
            WITH recent_usage AS (
                SELECT DISTINCT application_name 
                FROM application_usage_events 
                WHERE start_time >= $1
            )
            SELECT COUNT(DISTINCT a.data->>'name')
            FROM applications a
            INNER JOIN devices d ON a.device_id = d.id
            WHERE NOT EXISTS (
                SELECT 1 FROM recent_usage ru 
                WHERE LOWER(ru.application_name) = LOWER(a.data->>'name')
            )
            {'AND d.archived = FALSE' if not include_archived else ''}
        """, (cutoff_date,))
        
        unused_count = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            "status": "available",
            "topAppsByTime": top_by_time,
            "topAppsByLaunches": top_by_launches,
            "topUsers": top_users,
            "summary": {
                "totalAppsTracked": total_apps or 0,
                "totalUsageHours": round((total_secs or 0) / 3600, 1),
                "totalLaunches": total_launches or 0,
                "uniqueUsers": unique_users or 0,
                "devicesWithUsageData": devices or 0,
                "appsWithNoRecentUsage": unused_count
            },
            "lastUpdated": datetime.now(timezone.utc).isoformat(),
            "lookbackDays": days
        }
        
    except Exception as e:
        logger.error(f"Failed to get application usage stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve application usage statistics: {str(e)}")


@app.get("/api/devices/applications/usage", dependencies=[Depends(verify_authentication)])
async def get_fleet_application_usage(
    days: int = Query(default=30, ge=1, le=365, description="Number of days to look back for usage data"),
    applicationNames: Optional[str] = Query(default=None, description="Comma-separated list of application names to filter"),
    usages: Optional[str] = Query(default=None, description="Comma-separated list of usage types (assigned, shared)"),
    catalogs: Optional[str] = Query(default=None, description="Comma-separated list of catalogs (curriculum, staff, faculty, kiosk)"),
    locations: Optional[str] = Query(default=None, description="Comma-separated list of locations/rooms"),
    minHours: Optional[float] = Query(default=None, description="Minimum total hours threshold"),
    minLaunches: Optional[int] = Query(default=None, description="Minimum launch count threshold"),
    includeUnused: bool = Query(default=True, description="Include apps with zero usage in period"),
    include_archived: bool = Query(default=False, alias="includeArchived")
):
    """
    Fleet-wide application utilization report with filtering support.
    
    Extracts usage data from the applications module JSONB stored on each device.
    The Windows client collects process telemetry and stores it as:
    - applications.data.usage.activeSessions[] - array of individual session records
    - Each session has: name, path, user, durationSeconds, startTime, etc.
    
    This endpoint aggregates activeSessions by app name across all devices.
    """
    try:
        logger.info(f"Fetching fleet application usage from applications module (days={days}, includeArchived={include_archived})")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Parse filter values
        app_name_list = [a.strip() for a in applicationNames.split(',')] if applicationNames else []
        usage_list = [u.lower().strip() for u in usages.split(',')] if usages else []
        catalog_list = [c.lower().strip() for c in catalogs.split(',')] if catalogs else []
        location_list = [l.strip() for l in locations.split(',')] if locations else []
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Build inventory filter WHERE clause
        inventory_where_parts = []
        if usage_list:
            placeholders = ', '.join([f"'{u}'" for u in usage_list])
            inventory_where_parts.append(f"LOWER(inv.data->>'usage') IN ({placeholders})")
        if catalog_list:
            placeholders = ', '.join([f"'{c}'" for c in catalog_list])
            inventory_where_parts.append(f"LOWER(inv.data->>'catalog') IN ({placeholders})")
        if location_list:
            loc_conditions = [f"inv.data->>'location' ILIKE '%{loc}%'" for loc in location_list]
            inventory_where_parts.append(f"({' OR '.join(loc_conditions)})")
        
        inventory_filter = f"AND {' AND '.join(inventory_where_parts)}" if inventory_where_parts else ""
        archive_filter = "AND d.archived = FALSE" if not include_archived else ""
        
        # Query: Extract usage data from applications module JSONB
        # ACTUAL data structure from Windows client:
        # applications.data.usage.activeSessions[] - array of session records
        # Each session: {name, path, user, durationSeconds, startTime, isActive, ...}
        # OPTIMIZED: Pre-extract installed apps to avoid nested EXISTS with jsonb_array_elements
        cursor.execute(f"""
            WITH device_usage AS (
                SELECT 
                    d.serial_number,
                    a.data->'usage' as usage_data,
                    a.data->'installedApplications' as installed_apps,
                    a.collected_at
                FROM applications a
                INNER JOIN devices d ON a.device_id = d.serial_number
                LEFT JOIN inventory inv ON inv.device_id = d.serial_number
                WHERE a.collected_at >= %s
                    {archive_filter}
                    {inventory_filter}
            ),
            installed_app_names AS (
                SELECT DISTINCT
                    du.serial_number,
                    app->>'name' as app_name
                FROM device_usage du,
                LATERAL jsonb_array_elements(
                    CASE 
                        WHEN du.installed_apps IS NOT NULL AND jsonb_typeof(du.installed_apps) = 'array'
                        THEN du.installed_apps
                        ELSE '[]'::jsonb
                    END
                ) as app
                WHERE app->>'name' IS NOT NULL AND app->>'name' != ''
            ),
            all_sessions AS (
                SELECT 
                    du.serial_number,
                    session->>'name' as app_name,
                    session->>'path' as app_path,
                    session->>'user' as username,
                    COALESCE((session->>'durationSeconds')::numeric, 0) as duration_seconds,
                    session->>'startTime' as start_time
                FROM device_usage du,
                LATERAL jsonb_array_elements(
                    CASE 
                        WHEN du.usage_data->'activeSessions' IS NOT NULL 
                             AND jsonb_typeof(du.usage_data->'activeSessions') = 'array'
                        THEN du.usage_data->'activeSessions'
                        ELSE '[]'::jsonb
                    END
                ) as session
                WHERE du.usage_data IS NOT NULL 
                  AND du.usage_data != 'null'::jsonb
                  AND (du.usage_data->>'isCaptureEnabled')::boolean = true
                  AND session->>'name' IS NOT NULL AND session->>'name' != ''
            ),
            sessions_extracted AS (
                SELECT 
                    s.serial_number,
                    s.app_name,
                    s.app_path,
                    s.username,
                    s.duration_seconds,
                    s.start_time
                FROM all_sessions s
                INNER JOIN installed_app_names ian ON 
                    ian.serial_number = s.serial_number AND 
                    ian.app_name = s.app_name
            ),
            app_summary AS (
                SELECT 
                    app_name,
                    app_path,
                    serial_number,
                    username,
                    SUM(duration_seconds) as total_seconds,
                    COUNT(*) as session_count,
                    MAX(start_time) as last_used,
                    MIN(start_time) as first_seen
                FROM sessions_extracted
                WHERE app_name IS NOT NULL AND app_name != ''
                GROUP BY app_name, app_path, serial_number, username
            )
            SELECT 
                app_name,
                MAX(app_path) as executable,
                '' as publisher,
                SUM(total_seconds) as total_seconds,
                SUM(session_count) as total_launches,
                COUNT(DISTINCT serial_number) as device_count,
                COUNT(DISTINCT username) FILTER (WHERE username IS NOT NULL) as unique_user_count,
                MAX(last_used) as last_used,
                MIN(first_seen) as first_seen,
                array_agg(DISTINCT serial_number) as devices,
                array_agg(DISTINCT username) FILTER (WHERE username IS NOT NULL) as users
            FROM app_summary
            WHERE total_seconds > 0
            GROUP BY app_name
            ORDER BY SUM(total_seconds) DESC
        """, (cutoff_date,))
        
        applications = []
        all_users = set()
        total_usage_seconds = 0
        total_launch_count = 0
        
        for row in cursor.fetchall():
            app_name, executable, publisher, total_secs, launches, devices, user_count, last_used, first_seen, device_list, user_list = row
            
            total_secs = float(total_secs or 0)
            launches = int(launches or 0)
            
            # Apply filters
            if app_name_list:
                if not any(filter_name.lower() in app_name.lower() for filter_name in app_name_list):
                    continue
            
            if minHours and total_secs < (minHours * 3600):
                continue
            
            if minLaunches and launches < minLaunches:
                continue
            
            total_usage_seconds += total_secs
            total_launch_count += launches
            
            # Track all users
            if user_list:
                for user in user_list:
                    if user:
                        all_users.add(user)
            
            applications.append({
                "name": app_name,
                "executable": executable or "",
                "publisher": publisher or "",
                "totalSeconds": int(total_secs),
                "totalHours": round(total_secs / 3600, 2),
                "launchCount": launches,
                "deviceCount": devices or 0,
                "userCount": user_count or 0,
                "lastUsed": last_used,
                "firstUsed": first_seen,
                "devices": device_list[:10] if device_list else [],
                "users": user_list[:10] if user_list else [],
                "isSingleUser": (user_count or 0) == 1
            })
        
        # Get unique devices and users from the query results
        unique_device_serials = set()
        for app in applications:
            for serial in app.get("devices", []):
                unique_device_serials.add(serial)
        
        # Get top users by aggregating from activeSessions
        try:
            cursor.execute(f"""
                WITH installed_apps_for_users AS (
                    -- Get installed applications from each device to filter usage
                    SELECT DISTINCT 
                        d.serial_number,
                        app_item->>'name' as app_name
                    FROM applications a
                    INNER JOIN devices d ON a.device_id = d.serial_number,
                    LATERAL jsonb_array_elements(
                        CASE 
                            WHEN a.data->'installedApplications' IS NOT NULL 
                                 AND jsonb_typeof(a.data->'installedApplications') = 'array'
                            THEN a.data->'installedApplications'
                            ELSE '[]'::jsonb
                        END
                    ) as app_item
                    WHERE a.collected_at >= %s
                      AND app_item->>'name' IS NOT NULL AND app_item->>'name' != ''
                ),
                all_sessions AS (
                    SELECT 
                        d.serial_number,
                        session->>'user' as username,
                        COALESCE((session->>'durationSeconds')::numeric, 0) as duration_seconds,
                        session->>'name' as app_name
                    FROM applications a
                    INNER JOIN devices d ON a.device_id = d.serial_number
                    LEFT JOIN inventory inv ON inv.device_id = d.serial_number,
                    LATERAL jsonb_array_elements(
                        CASE 
                            WHEN a.data->'usage'->'activeSessions' IS NOT NULL 
                                 AND jsonb_typeof(a.data->'usage'->'activeSessions') = 'array'
                            THEN a.data->'usage'->'activeSessions'
                            ELSE '[]'::jsonb
                        END
                    ) as session
                    WHERE a.collected_at >= %s
                        AND (a.data->'usage'->>'isCaptureEnabled')::boolean = true
                        AND session->>'name' IS NOT NULL AND session->>'name' != ''
                        {archive_filter}
                        {inventory_filter}
                ),
                device_sessions AS (
                    SELECT 
                        s.serial_number,
                        s.username,
                        s.duration_seconds,
                        s.app_name
                    FROM all_sessions s
                    INNER JOIN installed_apps_for_users ia ON 
                        ia.serial_number = s.serial_number AND 
                        ia.app_name = s.app_name
                ),
                user_stats AS (
                    SELECT 
                        username,
                        SUM(duration_seconds) as total_seconds,
                        COUNT(*) as session_count,
                        COUNT(DISTINCT app_name) as apps_used,
                        COUNT(DISTINCT serial_number) as devices_used
                    FROM device_sessions
                    WHERE username IS NOT NULL AND username != ''
                    GROUP BY username
                )
                SELECT username, total_seconds, session_count, apps_used, devices_used
                FROM user_stats
                ORDER BY total_seconds DESC
                LIMIT 25
            """, (cutoff_date, cutoff_date))
            
            # Aggregate and normalize usernames in Python
            user_data = {}
            for row in cursor.fetchall():
                raw_username, total_secs, sessions, apps_used, devices_used = row
                total_secs = float(total_secs or 0)
                
                # Normalize username: extract just the user part, skip machine accounts
                if not raw_username:
                    continue
                if raw_username.endswith('$'):  # Skip machine accounts like MACHINE$
                    continue
                    
                # Extract username after backslash (DOMAIN\user -> user)
                if '\\' in raw_username:
                    normalized = raw_username.split('\\')[-1].lower()
                else:
                    normalized = raw_username.lower()
                
                # Aggregate if same normalized username
                if normalized in user_data:
                    user_data[normalized]['totalSeconds'] += int(total_secs)
                    user_data[normalized]['launchCount'] += sessions or 0
                    user_data[normalized]['appsUsed'] = max(user_data[normalized]['appsUsed'], apps_used or 0)
                    user_data[normalized]['devicesUsed'] += devices_used or 0
                else:
                    user_data[normalized] = {
                        "username": normalized,
                        "totalSeconds": int(total_secs),
                        "launchCount": sessions or 0,
                        "appsUsed": apps_used or 0,
                        "devicesUsed": devices_used or 0
                    }
            
            # Convert to list and add totalHours
            top_users = []
            for udata in sorted(user_data.values(), key=lambda x: x['totalSeconds'], reverse=True)[:25]:
                udata['totalHours'] = round(udata['totalSeconds'] / 3600, 2)
                top_users.append(udata)
        except Exception as e:
            logger.warning(f"Failed to get top users: {e}")
            top_users = list({"username": u, "totalSeconds": 0, "totalHours": 0, "launchCount": 0, "appsUsed": 0, "devicesUsed": 1} for u in all_users)[:25]
        
        # Get single-user applications
        single_user_apps = [
            {"name": app["name"], "totalHours": app["totalHours"]}
            for app in applications
            if app.get("isSingleUser", False)
        ][:20]
        
        # Get unused apps - apps installed but with no usage data in activeSessions
        unused_apps = []
        if includeUnused:
            try:
                cursor.execute(f"""
                    WITH installed_apps AS (
                        SELECT DISTINCT 
                            app_item->>'name' as app_name,
                            d.serial_number
                        FROM applications a
                        INNER JOIN devices d ON a.device_id = d.serial_number,
                        LATERAL jsonb_array_elements(
                            CASE 
                                WHEN a.data->'installedApplications' IS NOT NULL 
                                     AND jsonb_typeof(a.data->'installedApplications') = 'array'
                                THEN a.data->'installedApplications'
                                ELSE '[]'::jsonb
                            END
                        ) as app_item
                        WHERE d.archived = FALSE
                          AND app_item->>'name' IS NOT NULL AND app_item->>'name' != ''
                    ),
                    used_apps AS (
                        SELECT DISTINCT session->>'name' as app_name
                        FROM applications a
                        INNER JOIN devices d ON a.device_id = d.serial_number,
                        LATERAL jsonb_array_elements(
                            CASE 
                                WHEN a.data->'usage'->'activeSessions' IS NOT NULL 
                                     AND jsonb_typeof(a.data->'usage'->'activeSessions') = 'array'
                                THEN a.data->'usage'->'activeSessions'
                                ELSE '[]'::jsonb
                            END
                        ) as session
                        WHERE d.archived = FALSE
                          AND (a.data->'usage'->>'isCaptureEnabled')::boolean = true
                    )
                    SELECT 
                        ia.app_name,
                        COUNT(DISTINCT ia.serial_number) as device_count
                    FROM installed_apps ia
                    WHERE ia.app_name IS NOT NULL
                      AND ia.app_name != ''
                      AND NOT EXISTS (
                          SELECT 1 FROM used_apps ua 
                          WHERE LOWER(ua.app_name) = LOWER(ia.app_name)
                      )
                    GROUP BY ia.app_name
                    ORDER BY device_count DESC
                    LIMIT 50
                """)
                
                for row in cursor.fetchall():
                    app_name, devices = row
                    unused_apps.append({
                        "name": app_name,
                        "deviceCount": devices,
                        "daysSinceUsed": days
                    })
            except Exception as e:
                logger.warning(f"Failed to get unused apps: {e}")
                # Rollback to recover from error state
                conn.rollback()
        
        # Get version distribution for each app from installedApplications
        # This provides device-level version breakdown for the Version Distribution widget
        version_distribution = {}
        try:
            cursor.execute(f"""
                WITH app_versions AS (
                    SELECT 
                        app_item->>'name' as app_name,
                        COALESCE(app_item->>'version', 'Unknown') as version,
                        d.serial_number,
                        COALESCE(inv.data->>'device_name', inv.data->>'deviceName', inv.data->>'computer_name', inv.data->>'computerName', d.serial_number) as device_name,
                        inv.data->>'location' as location,
                        inv.data->>'catalog' as catalog,
                        d.last_seen
                    FROM applications a
                    INNER JOIN devices d ON a.device_id = d.serial_number
                    LEFT JOIN inventory inv ON inv.device_id = d.serial_number,
                    LATERAL jsonb_array_elements(
                        CASE 
                            WHEN a.data->'installedApplications' IS NOT NULL 
                                 AND jsonb_typeof(a.data->'installedApplications') = 'array'
                            THEN a.data->'installedApplications'
                            ELSE '[]'::jsonb
                        END
                    ) as app_item
                    WHERE a.collected_at >= %s
                      AND app_item->>'name' IS NOT NULL AND app_item->>'name' != ''
                        {archive_filter}
                        {inventory_filter}
                )
                SELECT 
                    app_name,
                    version,
                    COUNT(*) as device_count,
                    json_agg(json_build_object(
                        'serialNumber', serial_number,
                        'deviceName', device_name,
                        'location', location,
                        'catalog', catalog,
                        'lastSeen', last_seen
                    )) as devices
                FROM app_versions
                GROUP BY app_name, version
                ORDER BY app_name, COUNT(*) DESC
            """, (cutoff_date,))
            
            for row in cursor.fetchall():
                app_name, version, device_count, devices_json = row
                if app_name not in version_distribution:
                    version_distribution[app_name] = {
                        "versions": {},
                        "totalDevices": 0
                    }
                version_distribution[app_name]["versions"][version] = {
                    "count": device_count,
                    "devices": devices_json[:50] if devices_json else []  # Limit to 50 devices per version
                }
                version_distribution[app_name]["totalDevices"] += device_count
                
        except Exception as e:
            logger.warning(f"Failed to get version distribution: {e}")
        
        conn.close()
        
        return {
            "status": "available",
            "dataSource": "applications_module",  # Indicate we're using module data
            "applications": applications,
            "topUsers": top_users,
            "singleUserApps": single_user_apps,
            "unusedApps": unused_apps,
            "versionDistribution": version_distribution,
            "summary": {
                "totalAppsTracked": len(applications),
                "totalUsageHours": round(total_usage_seconds / 3600, 1),
                "totalLaunches": total_launch_count,
                "uniqueUsers": len(top_users),
                "uniqueDevices": len(unique_device_serials),
                "singleUserAppCount": len(single_user_apps),
                "unusedAppCount": len(unused_apps)
            },
            "filters": {
                "days": days,
                "applicationNames": app_name_list,
                "usages": usage_list,
                "catalogs": catalog_list,
                "locations": location_list,
                "minHours": minHours,
                "minLaunches": minLaunches
            },
            "lastUpdated": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get fleet application usage: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve fleet application usage: {str(e)}")


@app.get("/api/device/{serial_number}/applications/usage", dependencies=[Depends(verify_authentication)])
async def get_device_application_usage(
    serial_number: str,
    days: int = Query(default=30, ge=1, le=365, description="Number of days to look back for usage data")
):
    """
    Get application usage statistics for a specific device.
    
    Returns usage data collected via kernel process telemetry for the specified device.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if usage tables exist
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'application_usage_events'
            )
        """)
        usage_tables_exist = cursor.fetchone()[0]
        
        if not usage_tables_exist:
            conn.close()
            return {
                "status": "unavailable",
                "message": "Application usage tracking not yet deployed",
                "applications": [],
                "users": [],
                "summary": {}
            }
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Get usage data aggregated by application
        cursor.execute("""
            SELECT 
                application_name,
                SUM(duration_seconds) as total_seconds,
                COUNT(*) as launch_count,
                array_agg(DISTINCT username) FILTER (WHERE username IS NOT NULL AND username != '') as users,
                MAX(end_time) as last_used,
                MIN(start_time) as first_seen,
                AVG(duration_seconds) as avg_session
            FROM application_usage_events
            WHERE device_id = $1
                AND start_time >= $2
            GROUP BY application_name
            ORDER BY total_seconds DESC
        """, (serial_number, cutoff_date))
        
        applications = []
        for row in cursor.fetchall():
            app_name, total_secs, launches, users, last_used, first_seen, avg_session = row
            applications.append({
                "name": app_name,
                "totalSeconds": int(total_secs) if total_secs else 0,
                "launchCount": launches,
                "users": users or [],
                "uniqueUserCount": len(users) if users else 0,
                "lastUsed": last_used.isoformat() if last_used else None,
                "firstSeen": first_seen.isoformat() if first_seen else None,
                "averageSessionSeconds": int(avg_session) if avg_session else 0
            })
        
        # Get usage by user for this device
        cursor.execute("""
            SELECT 
                username,
                SUM(duration_seconds) as total_seconds,
                COUNT(*) as launch_count,
                COUNT(DISTINCT application_name) as apps_used
            FROM application_usage_events
            WHERE device_id = $1
                AND start_time >= $2
                AND username IS NOT NULL
                AND username != ''
            GROUP BY username
            ORDER BY total_seconds DESC
        """, (serial_number, cutoff_date))
        
        users = []
        for row in cursor.fetchall():
            username, total_secs, launches, apps_used = row
            users.append({
                "username": username,
                "totalSeconds": int(total_secs) if total_secs else 0,
                "launchCount": launches,
                "appsUsed": apps_used
            })
        
        # Summary for device
        cursor.execute("""
            SELECT 
                COUNT(DISTINCT application_name) as total_apps,
                COALESCE(SUM(duration_seconds), 0) as total_seconds,
                COUNT(*) as total_launches,
                COUNT(DISTINCT username) as unique_users
            FROM application_usage_events
            WHERE device_id = $1
                AND start_time >= $2
        """, (serial_number, cutoff_date))
        
        summary_row = cursor.fetchone()
        total_apps, total_secs, total_launches, unique_users = summary_row
        
        conn.close()
        
        return {
            "status": "available",
            "serialNumber": serial_number,
            "applications": applications,
            "users": users,
            "summary": {
                "totalAppsUsed": total_apps or 0,
                "totalUsageHours": round((total_secs or 0) / 3600, 1),
                "totalLaunches": total_launches or 0,
                "uniqueUsers": unique_users or 0
            },
            "lookbackDays": days,
            "lastUpdated": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get device application usage for {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve device application usage: {str(e)}")


@app.get("/api/stats/installs", dependencies=[Depends(verify_authentication)])
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
        
        # Count devices with install errors from Cimian items (not events)
        # Items have currentStatus field with values like: failed, error, Pending Update, etc.
        logger.debug("Counting devices with install errors from cimian->items...")
        cursor.execute("""
            SELECT COUNT(DISTINCT i.device_id)
            FROM installs i
            CROSS JOIN LATERAL jsonb_array_elements(i.data->'cimian'->'items') as item
            WHERE LOWER(item->>'currentStatus') IN ('failed', 'error', 'needs_reinstall')
               OR LOWER(item->>'mappedStatus') IN ('failed', 'error')
        """)
        devices_with_errors = cursor.fetchone()[0] or 0
        logger.debug(f"Devices with errors: {devices_with_errors}")
        
        # Count devices with warnings (pending/update status, but NO errors)
        logger.debug("Counting devices with warnings (excluding devices with errors)...")
        cursor.execute("""
            SELECT COUNT(DISTINCT i.device_id)
            FROM installs i
            CROSS JOIN LATERAL jsonb_array_elements(i.data->'cimian'->'items') as item
            WHERE (LOWER(item->>'currentStatus') LIKE '%%pending%%'
                OR LOWER(item->>'currentStatus') LIKE '%%update%%'
                OR LOWER(item->>'currentStatus') = 'warning')
            AND i.device_id NOT IN (
                -- Exclude devices that have any errors
                SELECT DISTINCT device_id
                FROM installs
                CROSS JOIN LATERAL jsonb_array_elements(data->'cimian'->'items') as err_item
                WHERE LOWER(err_item->>'currentStatus') IN ('failed', 'error', 'needs_reinstall')
                   OR LOWER(err_item->>'mappedStatus') IN ('failed', 'error')
            )
        """)
        devices_with_warnings = cursor.fetchone()[0] or 0
        logger.debug(f"Devices with warnings: {devices_with_warnings}")
        
        # Count total failed install items across all devices
        logger.debug("Counting total failed installs...")
        cursor.execute("""
            SELECT COUNT(*)
            FROM installs i
            CROSS JOIN LATERAL jsonb_array_elements(i.data->'cimian'->'items') as item
            WHERE LOWER(item->>'currentStatus') IN ('failed', 'error', 'needs_reinstall')
               OR LOWER(item->>'mappedStatus') IN ('failed', 'error')
        """)
        total_failed = cursor.fetchone()[0] or 0
        
        # Count total warning items across all devices
        logger.debug("Counting total warnings...")
        cursor.execute("""
            SELECT COUNT(*)
            FROM installs i
            CROSS JOIN LATERAL jsonb_array_elements(i.data->'cimian'->'items') as item
            WHERE LOWER(item->>'currentStatus') LIKE '%%pending%%'
               OR LOWER(item->>'currentStatus') LIKE '%%update%%'
               OR LOWER(item->>'currentStatus') = 'warning'
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

@app.post("/api/events", dependencies=[Depends(verify_authentication)])
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
        
        # Extract metadata - support both snake_case and camelCase for Windows client compatibility
        metadata = payload.get('metadata', {})
        device_uuid = metadata.get('device_id') or metadata.get('deviceId', 'unknown-device')
        serial_number = metadata.get('serial_number') or metadata.get('serialNumber', 'unknown-serial')
        collected_at = metadata.get('collected_at') or metadata.get('collectedAt', datetime.now(timezone.utc).isoformat())
        client_version = metadata.get('client_version') or metadata.get('clientVersion', 'unknown')
        platform = metadata.get('platform', 'Unknown')
        collection_type = metadata.get('collection_type') or metadata.get('collectionType', 'Full')
        enabled_modules = metadata.get('enabled_modules') or metadata.get('enabledModules', [])
        
        # Validate required fields
        if device_uuid == 'unknown-device' or serial_number == 'unknown-serial':
            raise HTTPException(
                status_code=400,
                detail="Both deviceId (UUID) and serialNumber are required in metadata"
            )
        
        # VALIDATION: Reject serial numbers that look like hostnames
        # This prevents database pollution from client bugs where hostname is sent as serial
        # Valid serial numbers should NOT match common hostname patterns
        import re
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
            'profiles': 'profiles',
            'displays': 'displays',
            'printers': 'printers',
            'peripherals': 'peripherals'
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
                
                # VALIDATION: Events containing installs module MUST be success/warning/error
                if has_installs_module or (isinstance(details, dict) and details.get('module_status') in ['success', 'warning', 'error']):
                    allowed_types = {'success', 'warning', 'error'}
                    if event_type not in allowed_types:
                        logger.warning(f"Invalid event type '{event_type}' for installs module event, defaulting to 'info'")
                        # For installs events with invalid type, use 'info' but log the issue
                        # This ensures backward compatibility while flagging the problem
                        if event_type not in {'info', 'system'}:
                            event_type = 'warning'  # Default to warning for installs-related events
                
                # ENHANCED: For installs-related events, include full module data in details
                # This ensures that when users expand the event, they see ALL install details
                enhanced_details = details.copy() if isinstance(details, dict) else {}
                
                # If this is an installs event and we have installs module data, include it
                if has_installs_module and 'installs' in modules_data:
                    enhanced_details['full_installs_data'] = modules_data['installs']
                    logger.debug(f"Enhanced event details with full installs module data for device {serial_number}")
                
                # Store enhanced details as JSON
                details_json = json.dumps(enhanced_details)
                
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
                    if 'additional' in sanitized_payload_metadata and isinstance(sanitized_payloadMetadata['additional'], dict):
                        sanitized_payload_additional = sanitized_payloadMetadata['additional'].copy()
                        sanitized_payload_additional.pop('passphrase', None)
                        sanitized_payload_metadata['additional'] = sanitized_payload_additional
                    sanitized_payload['metadata'] = sanitized_payload_metadata
                
                # Store COMPLETE original payload in details column for full payload retrieval
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
                    RETURNING id
                """, (serial_number, collection_message, collection_details, collected_at, datetime.now(timezone.utc)))
                
                event_row = cursor.fetchone()
                event_id = event_row[0] if event_row else None
                
                events_stored += 1
                logger.info(f"Created fallback system event with full payload (no events in payload)")
                
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
        conn.close()
        
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

# Web PubSub connection string from environment
EVENTS_CONNECTION = os.getenv('EVENTS_CONNECTION')
WEB_PUBSUB_HUB = "events"  # Hub name for real-time events

# Cached WebPubSub service client for broadcasting
_webpubsub_service = None

def get_webpubsub_service():
    """Get or create a cached WebPubSub service client."""
    global _webpubsub_service
    if _webpubsub_service is None and WEBPUBSUB_AVAILABLE and EVENTS_CONNECTION:
        try:
            _webpubsub_service = WebPubSubServiceClient.from_connection_string(
                connection_string=EVENTS_CONNECTION,
                hub=WEB_PUBSUB_HUB
            )
        except Exception as e:
            logger.error(f"Failed to create WebPubSub service: {e}")
    return _webpubsub_service

async def broadcast_event(event_data: dict):
    """
    Broadcast an event to all connected WebSocket clients.
    
    Args:
        event_data: Event dictionary with id, device, kind, ts, payload
    """
    service = get_webpubsub_service()
    if not service:
        return  # WebPubSub not available, skip broadcasting
    
    try:
        # Send to all connected clients using the JSON subprotocol format
        # Azure Web PubSub will wrap this as: {"type": "message", "from": "server", "data": event_data}
        # The client receives it and extracts event_data from message.data
        service.send_to_all(
            message=event_data,  # Send the event data directly, WebPubSub wraps it
            content_type="application/json"
        )
        logger.info(f"Broadcast event to WebPubSub: {event_data.get('kind', 'unknown')} for {event_data.get('device', 'unknown')}")
    except Exception as e:
        logger.error(f"Failed to broadcast event: {e}")

@app.get("/api/negotiate")
async def signalr_negotiate(device: str = Query(default="dashboard")):
    """
    SignalR/WebPubSub negotiate endpoint.
    
    Generates a client access token for Azure Web PubSub connection.
    The token allows clients to connect and receive real-time events.
    
    Args:
        device: Optional device/client identifier for user tracking
    
    Returns:
        url: WebSocket URL with embedded access token
        accessToken: JWT token for authentication (also embedded in url)
    """
    if not WEBPUBSUB_AVAILABLE:
        logger.warning("Azure Web PubSub SDK not available, falling back to mock")
        return {
            "url": "wss://reportmate-signalr.webpubsub.azure.com/client/hubs/events",
            "accessToken": None,
            "error": "WebPubSub SDK not installed"
        }
    
    if not EVENTS_CONNECTION:
        logger.warning("EVENTS_CONNECTION not configured, SignalR unavailable")
        return {
            "url": None,
            "accessToken": None,
            "error": "EVENTS_CONNECTION not configured"
        }
    
    try:
        # Create Web PubSub service client from connection string
        service = WebPubSubServiceClient.from_connection_string(
            connection_string=EVENTS_CONNECTION,
            hub=WEB_PUBSUB_HUB
        )
        
        # Generate client access token with 60-minute expiry
        # The token allows the client to receive messages from the hub
        token_response = service.get_client_access_token(
            user_id=device,
            minutes_to_expire=60,
            roles=["webpubsub.joinLeaveGroup.events"]  # Allow joining the events group
        )
        
        logger.info(f"Generated WebPubSub token for client: {device}")
        
        return {
            "url": token_response.get("url"),
            "accessToken": token_response.get("token"),
            "expiresOn": (datetime.now(timezone.utc) + timedelta(minutes=60)).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to generate WebPubSub token: {e}", exc_info=True)
        return {
            "url": None,
            "accessToken": None,
            "error": f"Token generation failed: {str(e)}"
        }

@app.patch("/api/device/{serial_number}/archive", dependencies=[Depends(verify_authentication)])
async def archive_device(serial_number: str):
    """
    Archive a device (soft delete).
    
    Archived devices:
    - Are hidden from all bulk endpoints by default
    - Still exist in database with all module data intact
    - Can be unarchived later
    - Do NOT receive new data submissions (rejected at ingestion)
    
    This is useful for:
    - Decommissioned devices
    - Devices being retired/replaced
    - Test devices no longer needed
    - Keeping historical data while hiding from active reports
    
    **Authentication Required:**
    - Windows clients: X-API-PASSPHRASE header
    - Azure resources: X-MS-CLIENT-PRINCIPAL-ID header (Managed Identity)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if device exists
        check_query = load_sql("admin/check_device_archived")
        cursor.execute(check_query, {"serial_number": serial_number})
        
        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            raise HTTPException(status_code=404, detail=f"Device {serial_number} not found")
        
        device_id, currently_archived = device_row
        
        # Check if already archived
        if currently_archived:
            conn.close()
            return {
                "success": True,
                "message": f"Device {serial_number} is already archived",
                "serialNumber": serial_number,
                "archived": True,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        # Archive the device
        archive_query = load_sql("admin/archive_device")
        now = datetime.now(timezone.utc)
        cursor.execute(archive_query, {
            "serial_number": serial_number,
            "archived_at": now,
            "updated_at": now
        })
        
        conn.commit()
        conn.close()
        
        logger.info(f"[SUCCESS] Archived device: {serial_number}")
        
        return {
            "success": True,
            "message": f"Device {serial_number} has been archived",
            "serialNumber": serial_number,
            "archived": True,
            "archivedAt": now.isoformat(),
            "timestamp": now.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to archive device {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to archive device: {str(e)}")


@app.patch("/api/device/{serial_number}/unarchive", dependencies=[Depends(verify_authentication)])
async def unarchive_device(serial_number: str):
    """
    Unarchive a device (restore from soft delete).
    
    Unarchived devices:
    - Become visible in all bulk endpoints again
    - Can receive new data submissions
    - Restore to 'active' status
    - Retain all historical data
    
    **Authentication Required:**
    - Windows clients: X-API-PASSPHRASE header
    - Azure resources: X-MS-CLIENT-PRINCIPAL-ID header (Managed Identity)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if device exists
        check_query = load_sql("admin/check_device_archived")
        cursor.execute(check_query, {"serial_number": serial_number})
        
        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            raise HTTPException(status_code=404, detail=f"Device {serial_number} not found")
        
        device_id, currently_archived = device_row
        
        # Check if not archived
        if not currently_archived:
            conn.close()
            return {
                "success": True,
                "message": f"Device {serial_number} is not archived",
                "serialNumber": serial_number,
                "archived": False,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        # Unarchive the device
        unarchive_query = load_sql("admin/unarchive_device")
        now = datetime.now(timezone.utc)
        cursor.execute(unarchive_query, {
            "serial_number": serial_number,
            "updated_at": now
        })
        
        conn.commit()
        conn.close()
        
        logger.info(f"[SUCCESS] Unarchived device: {serial_number}")
        
        return {
            "success": True,
            "message": f"Device {serial_number} has been unarchived",
            "serialNumber": serial_number,
            "archived": False,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to unarchive device {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to unarchive device: {str(e)}")


@app.delete("/api/device/{serial_number}", dependencies=[Depends(verify_authentication)])
async def delete_device(serial_number: str, confirm: bool = Query(False)):
    """
    Permanently delete a device and all its data.
    
    **WARNING: This is a DESTRUCTIVE operation!**
    
    Deletion removes:
    - Device record from devices table
    - All module data (cascading delete via foreign keys)
    - All events history
    - ALL historical data - cannot be recovered
    
    This should only be used for:
    - Test devices that should not exist
    - Duplicate records
    - Data cleanup/GDPR compliance
    
    **RECOMMENDATION:** Use archive instead of delete to preserve historical data!
    
    Query Parameters:
    - confirm: Must be set to true to confirm deletion (safety check)
    
    **Authentication Required:**
    - Windows clients: X-API-PASSPHRASE header
    - Azure resources: X-MS-CLIENT-PRINCIPAL-ID header (Managed Identity)
    """
    try:
        # Safety check: require explicit confirmation
        if not confirm:
            raise HTTPException(
                status_code=400,
                detail="Deletion requires confirmation. Add ?confirm=true to the request. WARNING: This permanently deletes all device data!"
            )
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if device exists and get details for logging
        check_query = load_sql("admin/get_device_for_delete")
        cursor.execute(check_query, {"serial_number": serial_number})
        
        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            raise HTTPException(status_code=404, detail=f"Device {serial_number} not found")
        
        device_id, device_uuid, device_name, is_archived = device_row
        
        # Get module counts for logging
        module_tables = ["system", "hardware", "applications", "installs", "network", "security", 
                        "inventory", "management", "profiles", "displays", "printers"]
        module_counts = {}
        
        for table in module_tables:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE device_id = %s", (device_id,))
                count_result = cursor.fetchone()
                module_counts[table] = count_result[0] if count_result else 0
            except Exception:
                module_counts[table] = 0
        
        # Get event count
        cursor.execute("SELECT COUNT(*) FROM events WHERE device_id = %s", (device_id,))
        event_count_result = cursor.fetchone()
        event_count = event_count_result[0] if event_count_result else 0
        
        # Delete the device (CASCADE will delete all related module data and events)
        cursor.execute("""
            DELETE FROM devices 
            WHERE serial_number = %s OR id = %s
        """, (serial_number, serial_number))
        
        deleted_count = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        if deleted_count == 0:
            raise HTTPException(status_code=404, detail=f"Device {serial_number} not found")
        
        logger.warning(f"🗑️ DELETED device: {serial_number} (UUID: {device_uuid}, Name: {device_name})")
        logger.warning(f"   - Archived status: {is_archived}")
        logger.warning(f"   - Events deleted: {event_count}")
        logger.warning(f"   - Modules deleted: {sum(module_counts.values())} records across {len([k for k, v in module_counts.items() if v > 0])} tables")
        
        return {
            "success": True,
            "message": f"Device {serial_number} and all associated data has been permanently deleted",
            "serialNumber": serial_number,
            "deviceId": device_uuid,
            "deviceName": device_name,
            "wasArchived": is_archived,
            "deletedData": {
                "events": event_count,
                "modules": module_counts,
                "totalModuleRecords": sum(module_counts.values())
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "warning": "This data cannot be recovered"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete device {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete device: {str(e)}")


@app.get("/api/debug/database")
async def debug_database():
    """
    Database diagnostic endpoint - analyze storage usage and data cleanup opportunities.
    
    This endpoint helps identify:
    1. Duplicate records per device that should only have 1 row per module
    2. Orphaned records for devices that no longer exist
    3. Historical data retention issues
    4. Table bloat from dead tuples
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        diagnostics = {}
        
        # 1. Check for duplicate records in module tables (MAJOR ISSUE)
        module_tables = ['inventory', 'system', 'hardware', 'applications', 'network', 
                        'security', 'profiles', 'installs', 'management', 'displays', 'printers']
        duplicates = {}
        total_duplicate_rows = 0
        
        for table in module_tables:
            try:
                # Each device should have ONLY ONE record per module table
                cursor.execute(f"""
                    SELECT device_id, COUNT(*) as cnt 
                    FROM {table} 
                    GROUP BY device_id 
                    HAVING COUNT(*) > 1
                """)
                dups = cursor.fetchall()
                if dups:
                    device_count = len(dups)
                    total_rows = sum(d[1] for d in dups)
                    excess_rows = total_rows - device_count  # Should only be 1 per device
                    duplicates[table] = {
                        "devicesWithDuplicates": device_count,
                        "totalRows": total_rows,
                        "excessRows": excess_rows,
                        "topOffenders": [{"deviceId": d[0], "count": d[1]} for d in dups[:5]]
                    }
                    total_duplicate_rows += excess_rows
                else:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    total = cursor.fetchone()[0]
                    duplicates[table] = {
                        "devicesWithDuplicates": 0,
                        "totalRows": total,
                        "excessRows": 0
                    }
            except Exception as e:
                duplicates[table] = {"error": str(e)}
        
        diagnostics["duplicates"] = duplicates
        diagnostics["totalExcessRows"] = total_duplicate_rows
        
        # 2. Check for orphaned module records (device doesn't exist)
        orphaned = {}
        total_orphaned = 0
        for table in module_tables:
            try:
                cursor.execute(f"""
                    SELECT COUNT(*) 
                    FROM {table} m
                    LEFT JOIN devices d ON m.device_id = d.serial_number
                    WHERE d.serial_number IS NULL
                """)
                orphan_count = cursor.fetchone()[0]
                if orphan_count > 0:
                    orphaned[table] = orphan_count
                    total_orphaned += orphan_count
            except Exception:
                pass
        
        diagnostics["orphanedRecords"] = orphaned
        diagnostics["totalOrphanedRecords"] = total_orphaned
        
        # 3. Check events table - should we have retention policy?
        cursor.execute("SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM events")
        event_row = cursor.fetchone()
        diagnostics["events"] = {
            "totalEvents": event_row[0],
            "oldestEvent": event_row[1].isoformat() if event_row[1] else None,
            "newestEvent": event_row[2].isoformat() if event_row[2] else None
        }
        
        # 4. Table sizes
        cursor.execute("""
            SELECT 
                relname,
                n_live_tup,
                n_dead_tup,
                pg_size_pretty(pg_total_relation_size(relid)) as total_size
            FROM pg_stat_user_tables 
            WHERE relname IN ('devices', 'events', 'inventory', 'system', 'hardware', 
                             'applications', 'profiles', 'network', 'security')
            ORDER BY pg_total_relation_size(relid) DESC
        """)
        table_sizes = []
        for row in cursor.fetchall():
            table_sizes.append({
                "table": row[0],
                "liveRows": row[1],
                "deadRows": row[2],
                "totalSize": row[3]
            })
        diagnostics["tableSizes"] = table_sizes
        
        # 5. Cleanup recommendations
        recommendations = []
        if total_duplicate_rows > 0:
            recommendations.append(f"DELETE {total_duplicate_rows} duplicate rows from module tables (each device should have 1 record per module)")
        if total_orphaned > 0:
            recommendations.append(f"DELETE {total_orphaned} orphaned records (devices no longer exist)")
        
        diagnostics["recommendations"] = recommendations
        diagnostics["potentialStorageSavings"] = f"~{total_duplicate_rows + total_orphaned} records can be safely removed"
        
        conn.close()
        
        return {
            "database": "connected",
            "diagnostics": diagnostics,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Database diagnostic failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database diagnostic failed: {str(e)}")

# Error handlers
class SQLExecuteRequest(BaseModel):
    sql: str
    db_host: str = Field(default="reportmate-database.postgres.database.azure.com")
    db_name: str = Field(default="reportmate")
    db_user: str = Field(default="reportmate")
    db_pass: str

@app.post("/api/admin/execute-sql")
async def execute_sql(request: SQLExecuteRequest, auth: dict = Depends(verify_authentication)):
    """
    ADMIN-ONLY: Execute arbitrary SQL on the database.
    USE WITH EXTREME CAUTION.
    """
    try:
        # Check if this requires autocommit (CONCURRENTLY, VACUUM, etc.)
        sql_upper = request.sql.strip().upper()
        requires_autocommit = ('CONCURRENTLY' in sql_upper or 
                              sql_upper.startswith('VACUUM') or
                              sql_upper.startswith('REINDEX'))
        
        # Connect directly with provided credentials
        conn = pg8000.connect(
            host=request.db_host,
            port=5432,
            database=request.db_name,
            user=request.db_user,
            password=request.db_pass,
            ssl_context=True
        )
        
        # Set autocommit for commands that can't run in transaction blocks
        if requires_autocommit:
            conn.autocommit = True
        
        cursor = conn.cursor()
        
        # Execute SQL
        cursor.execute(request.sql)
        
        # Check if this is a SELECT query
        if sql_upper.startswith('SELECT'):
            results = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description] if cursor.description else []
            if not requires_autocommit:
                conn.commit()
            cursor.close()
            conn.close()
            return {
                "success": True,
                "rows": results,
                "columns": columns,
                "rowCount": len(results)
            }
        else:
            # For INSERT/UPDATE/DELETE/CREATE/etc
            rows_affected = cursor.rowcount
            if not requires_autocommit:
                conn.commit()
            cursor.close()
            conn.close()
            return {
                "success": True,
                "rowsAffected": rows_affected,
                "message": f"SQL executed successfully. Rows affected: {rows_affected}"
            }
    except Exception as e:
        logger.error(f"SQL execution error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"SQL execution failed: {str(e)}")

@app.post("/api/admin/migrate-platform-column")
async def migrate_platform_column(auth: dict = Depends(verify_authentication)):
    """
    Add platform column to devices table.
    This migration is idempotent and safe to run multiple times.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        migration_steps = []
        
        # Step 1: Add platform column
        try:
            cursor.execute("ALTER TABLE devices ADD COLUMN IF NOT EXISTS platform VARCHAR(50)")
            migration_steps.append("✓ Added platform column")
        except Exception as e:
            migration_steps.append(f"Platform column: {str(e)}")
        
        # Step 2: Create index
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_platform ON devices(platform)")
            migration_steps.append("✓ Created platform index")
        except Exception as e:
            migration_steps.append(f"Platform index: {str(e)}")
        
        # Step 3: Update existing devices with inferred platform
        try:
            cursor.execute("""
                UPDATE devices 
                SET platform = CASE
                    WHEN LOWER(os_name) LIKE '%windows%' OR LOWER(os) LIKE '%windows%' THEN 'Windows'
                    WHEN LOWER(os_name) LIKE '%mac%' OR LOWER(os) LIKE '%mac%' OR LOWER(os_name) LIKE '%darwin%' THEN 'macOS'
                    ELSE 'Unknown'
                END
                WHERE platform IS NULL
            """)
            rows_updated = cursor.rowcount
            migration_steps.append(f"✓ Updated {rows_updated} devices with inferred platform")
        except Exception as e:
            migration_steps.append(f"Update platforms: {str(e)}")
        
        conn.commit()
        
        # Step 4: Verify
        cursor.execute("SELECT serial_number, platform, os_name FROM devices LIMIT 5")
        sample_data = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return {
            "success": True,
            "steps": migration_steps,
            "sample_data": [
                {"serial": row[0], "platform": row[1], "os_name": row[2]}
                for row in sample_data
            ]
        }
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise HTTPException(status_code=500, detail=f"Migration failed: {str(e)}")

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