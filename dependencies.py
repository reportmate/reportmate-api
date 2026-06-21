"""
ReportMate API - Shared dependencies, models, and utilities.

This module contains all code shared across router modules:
- Database connection management (pg8000)
- Response cache (write-through invalidation)
- SQL query loader
- Authentication dependency
- Pydantic request/response models
- Utility functions (pagination, platform inference, etc.)
- WebPubSub real-time broadcasting
- Rate limiter instance
"""

import contextvars
import json
import logging
import os
import re
import time as _time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pg8000

pg8000.paramstyle = "pyformat"
from fastapi import HTTPException, Query, Request, Header, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

# Azure Web PubSub for real-time events
try:
    from azure.messaging.webpubsubservice import WebPubSubServiceClient

    WEBPUBSUB_AVAILABLE = True
except ImportError:
    WEBPUBSUB_AVAILABLE = False
    WebPubSubServiceClient = None

# Per-request correlation id, set by the request-id middleware and surfaced
# in every log line. Defaults to "-" outside of a request (startup, workers).
request_id_var: contextvars.ContextVar = contextvars.ContextVar(
    "request_id", default="-"
)


class _RequestIdFilter(logging.Filter):
    """Inject the current request id into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


# Structured logging: timestamp, level, request id, logger, message.
_log_handler = logging.StreamHandler()
_log_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s"
    )
)
_log_handler.addFilter(_RequestIdFilter())
logging.basicConfig(level=logging.INFO, handlers=[_log_handler])
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Endpoint response cache
# ---------------------------------------------------------------------------

_CACHE: dict = {}
_CACHE_TTL: dict = {
    "dashboard": 30,
    "devices": 30,
    "stats_installs": 30,
    "applications": 30,
    "applications_distribution": 60,
    "applications_filters": 60,
    "applications_usage": 60,
    "applications_usage_by_device": 60,
    "applications_collection_health": 120,
    "installs": 30,
    "installs_filters": 60,
    "installs_full": 30,
    "hardware": 30,
    "management": 30,
    "network": 30,
    "security": 30,
    "security_certs": 30,
    "peripherals": 30,
    "profiles": 30,
    "identity": 30,
    "system": 30,
    "inventory": 30,
    "events": 15,
    "settings": 30,
}


def cache_get(namespace: str, key: tuple = ()):
    """Return cached response or None if expired/missing."""
    entry = _CACHE.get((namespace, key))
    if entry is None:
        return None
    data, ts = entry
    ttl = _CACHE_TTL.get(namespace, 30)
    if (_time.monotonic() - ts) >= ttl:
        _CACHE.pop((namespace, key), None)
        return None
    return data


def cache_set(namespace: str, data, key: tuple = ()):
    """Store response in cache."""
    _CACHE[(namespace, key)] = (data, _time.monotonic())


def invalidate_caches():
    """Clear ALL cached responses. Called after any data write."""
    _CACHE.clear()
    logger.info("[CACHE] All caches invalidated (data write detected)")


# ---------------------------------------------------------------------------
# SQL Query Loader
# ---------------------------------------------------------------------------

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
    """
    if name in SQL_QUERIES:
        return SQL_QUERIES[name]

    if ".." in name or name.startswith("/") or name.startswith("\\"):
        raise ValueError(f"Invalid SQL query name (path traversal detected): {name}")

    sql_path = SQL_DIR / f"{name}.sql"

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
    """Preload all SQL queries at startup for faster execution."""
    sql_files = [
        "devices/bulk_hardware",
        "devices/bulk_installs",
        "devices/bulk_network",
        "devices/bulk_security",
        "devices/bulk_profiles",
        "devices/bulk_management",
        "devices/bulk_inventory",
        "devices/bulk_system",
        "devices/bulk_peripherals",
        "devices/bulk_identity",
        "devices/dashboard_devices",
        "devices/dashboard_events",
        "devices/list_devices",
        "devices/count_devices",
        "devices/get_device",
        "devices/get_device_module",
        "devices/get_device_profiles",
        "devices/get_policies_by_hash",
        "devices/get_installs_log",
        "devices/get_device_id",
        "devices/get_serial_number",
        "events/list_events",
        "events/get_device_events",
        "events/get_event_payload",
        "admin/archive_device",
        "admin/unarchive_device",
        "admin/get_device_for_delete",
        "admin/check_device_archived",
        "admin/check_duplicates",
        "admin/check_orphaned",
        "admin/events_stats",
        "admin/table_sizes",
        "settings/get",
        "settings/upsert",
        "settings/inventory_discover",
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
        logger.error(
            f"SQL preload incomplete: {len(failed)} queries failed to load: {failed}"
        )
    logger.info(f"Preloaded {loaded}/{len(sql_files)} SQL queries")


# Preload SQL queries at module import time
preload_sql_queries()

# ---------------------------------------------------------------------------
# Rate limiter (attached to app.state in main.py)
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])

# ---------------------------------------------------------------------------
# Database configuration
# ---------------------------------------------------------------------------

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://reportmate:password@localhost:5432/reportmate"
)

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

REPORTMATE_PASSPHRASE = os.getenv("REPORTMATE_PASSPHRASE")
API_INTERNAL_SECRET = os.getenv("API_INTERNAL_SECRET")
AZURE_MANAGED_IDENTITY_HEADER = "X-MS-CLIENT-PRINCIPAL-ID"
DISABLE_AUTH = os.getenv("DISABLE_AUTH", "false").lower() in ("true", "1", "yes")

if DISABLE_AUTH:
    # Surface this prominently — a deployment that ships with auth disabled is a
    # security hole, and the per-request bypass otherwise only logs at debug.
    logger.warning(
        "[SECURITY] DISABLE_AUTH is enabled: ALL API requests bypass authentication. "
        "This must never be set in production."
    )


async def verify_authentication(
    request: Request,
    x_api_passphrase: str = Header(None, alias="X-API-PASSPHRASE"),
    x_client_passphrase: str = Header(None, alias="X-Client-Passphrase"),
    x_internal_secret: str = Header(None, alias="X-Internal-Secret"),
    x_ms_client_principal_id: str = Header(None, alias="X-MS-CLIENT-PRINCIPAL-ID"),
    x_forwarded_for: str = Header(None, alias="X-Forwarded-For"),
    user_agent: str = Header(None, alias="User-Agent"),
):
    """
    Verify authentication for API endpoints.

    Authentication methods supported (checked in order):
    0. Disabled: If DISABLE_AUTH=true, all requests are allowed (development only!)
    1. Internal Secret: X-Internal-Secret header (container-to-container auth from frontend)
    2. Azure Managed Identity: X-MS-CLIENT-PRINCIPAL-ID header (Easy Auth)
    3. Passphrase: X-API-PASSPHRASE or X-Client-Passphrase header (Windows/macOS clients)
    """
    if DISABLE_AUTH:
        logger.debug(
            f"[SUCCESS] Authentication disabled via DISABLE_AUTH env var (User-Agent: {user_agent})"
        )
        return {"method": "auth_disabled", "user_agent": user_agent}

    client_host = request.client.host if request.client else None

    # Method 1: Internal Secret (container-to-container)
    if x_internal_secret:
        if not API_INTERNAL_SECRET:
            logger.error(
                "[ERR] API_INTERNAL_SECRET not configured but client attempted internal secret auth"
            )
            raise HTTPException(
                status_code=500, detail="Server internal authentication not configured"
            )

        if x_internal_secret != API_INTERNAL_SECRET:
            logger.warning(
                f"[ERR] Invalid internal secret attempt from {user_agent} (IP: {client_host})"
            )
            raise HTTPException(
                status_code=401, detail="Invalid internal authentication credentials"
            )

        logger.info(
            f"[SUCCESS] Authenticated via internal secret from {user_agent} (IP: {client_host})"
        )
        return {
            "method": "internal_secret",
            "user_agent": user_agent,
            "client_ip": client_host,
        }

    # Method 2: Azure Managed Identity
    if x_ms_client_principal_id:
        logger.info(
            f"[SUCCESS] Authenticated via Azure Managed Identity: {x_ms_client_principal_id}"
        )
        return {"method": "managed_identity", "principal_id": x_ms_client_principal_id}

    # Method 3: Passphrase (Windows/macOS clients)
    passphrase_header = x_api_passphrase or x_client_passphrase
    if passphrase_header:
        if not REPORTMATE_PASSPHRASE:
            logger.error(
                "[ERR] REPORTMATE_PASSPHRASE not configured but client attempted passphrase auth"
            )
            raise HTTPException(
                status_code=500, detail="Server authentication not configured"
            )

        if passphrase_header != REPORTMATE_PASSPHRASE:
            logger.warning(
                f"[ERR] Invalid passphrase attempt from {user_agent} (IP: {client_host})"
            )
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )

        header_type = "X-API-PASSPHRASE" if x_api_passphrase else "X-Client-Passphrase"
        logger.info(
            f"[SUCCESS] Authenticated via passphrase ({header_type}) from {user_agent} (IP: {client_host})"
        )
        return {
            "method": "passphrase",
            "user_agent": user_agent,
            "client_ip": client_host,
        }

    # No valid authentication
    logger.warning(
        f"[ERR] Unauthenticated access attempt from {user_agent} (IP: {client_host}, X-Forwarded-For: {x_forwarded_for})"
    )
    raise HTTPException(
        status_code=401,
        detail="Authentication required. X-Internal-Secret (internal), X-Client-Passphrase (clients), or internal network access required.",
    )


# ---------------------------------------------------------------------------
# Database connection
# ---------------------------------------------------------------------------


def get_db_connection():
    """Get database connection using pg8000 driver."""
    try:
        if DATABASE_URL.startswith("postgresql://"):
            url = DATABASE_URL[13:]

            if "?" in url:
                url, params = url.split("?", 1)

            auth_part, host_part = url.split("@")
            username, password = auth_part.split(":")

            if "/" in host_part:
                host_and_port, database_part = host_part.split("/", 1)
                database = database_part.split("?")[0]
            else:
                host_and_port = host_part
                database = "reportmate"

            if ":" in host_and_port:
                host, port = host_and_port.split(":")
                port = int(port)
            else:
                host = host_and_port
                port = 5432

            # SSL is required by Azure Postgres (default). Self-hosted/local
            # Postgres often has no TLS, so allow opting out via DB_SSL=false.
            db_ssl = os.getenv("DB_SSL", "true").lower() not in (
                "false",
                "0",
                "no",
                "disable",
            )
            logger.info(
                f"Connecting to database: {host}:{port}/{database} (ssl={db_ssl})"
            )
            conn = pg8000.connect(
                host=host,
                port=port,
                database=database,
                user=username,
                password=password,
                ssl_context=True if db_ssl else None,
                timeout=30,
            )
            cursor = conn.cursor()
            cursor.execute("SET statement_timeout = '120s'")
            conn.commit()
            cursor.close()
            return conn
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


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
    fleet: Optional[str] = None


class DeviceModules(BaseModel):
    """Device modules container for bulk endpoint."""

    system: Optional[SystemModule] = None
    inventory: Optional[InventorySummary] = None


class DeviceInfo(BaseModel):
    """Device information with database schema mapping."""

    serialNumber: str
    deviceId: str
    deviceName: Optional[str] = None
    name: Optional[str] = None
    hostname: Optional[str] = None
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


VALID_MODULE_NAMES = frozenset(
    {
        "system",
        "hardware",
        "network",
        "installs",
        "security",
        "applications",
        "inventory",
        "management",
        "peripherals",
        "identity",
    }
)


class ErrorResponse(BaseModel):
    """Standard error response body returned by all error handlers."""

    error: str
    detail: str
    status_code: int


class HealthResponse(BaseModel):
    """Response from /api/health."""

    status: str
    timestamp: str
    database: str
    version: str
    deviceIdStandard: str = "serialNumber"


class EventMetadata(BaseModel):
    """Metadata block for event submissions."""

    deviceId: str = Field(..., min_length=1, description="Device UUID")
    serialNumber: str = Field(..., min_length=1, description="Hardware serial number")
    collectedAt: Optional[str] = None
    clientVersion: Optional[str] = None
    platform: Optional[str] = Field(
        default="Unknown", pattern=r"^(Windows|macOS|Linux|Unknown)$"
    )
    collectionType: Optional[str] = Field(default="Full", pattern=r"^(Full|Single)$")
    enabledModules: Optional[List[str]] = None

    model_config = ConfigDict(populate_by_name=True)

    device_id: Optional[str] = Field(None, alias="device_id", exclude=True)
    serial_number: Optional[str] = Field(None, alias="serial_number", exclude=True)
    collected_at: Optional[str] = Field(None, alias="collected_at", exclude=True)
    client_version: Optional[str] = Field(None, alias="client_version", exclude=True)
    collection_type: Optional[str] = Field(None, alias="collection_type", exclude=True)
    enabled_modules: Optional[List[str]] = Field(
        None, alias="enabled_modules", exclude=True
    )


class EventSubmission(BaseModel):
    """Top-level payload for POST /api/events."""

    metadata: EventMetadata
    events: Optional[List[Dict[str, Any]]] = None
    modules: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(extra="allow")


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def paginate(items: list, limit: Optional[int], offset: int) -> list:
    """Apply offset/limit pagination to a list."""
    if offset:
        items = items[offset:]
    if limit is not None:
        items = items[:limit]
    return items


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


def build_os_summary(
    os_name: Optional[str], os_version: Optional[str]
) -> Dict[str, Optional[str]]:
    """Construct a minimal operating system summary for bulk responses."""
    summary: Dict[str, Optional[str]] = {
        "name": os_name,
        "version": os_version,
    }
    if os_version:
        parts = [part for part in os_version.split(".") if part]
        if len(parts) >= 3:
            summary["build"] = parts[2]
        if len(parts) >= 4:
            summary["featureUpdate"] = parts[3]
    return {key: value for key, value in summary.items() if value}


def normalize_app_name(app_name: str) -> str:
    """Normalize application name by removing versions, editions, and architecture info."""
    if not app_name or not isinstance(app_name, str):
        return ""

    normalized = app_name.strip()
    if not normalized:
        return ""

    # Exact product mappings
    if re.search(r"Microsoft Edge", normalized, re.IGNORECASE):
        return "Microsoft Edge"
    if re.search(r"Google Chrome", normalized, re.IGNORECASE):
        return "Google Chrome"
    if re.search(r"Mozilla Firefox|Firefox", normalized, re.IGNORECASE):
        return "Mozilla Firefox"

    # Generic version number removal
    normalized = re.sub(
        r"\s+v?\d+(\.\d+)*(\.\d+)*(\.\d+)*$", "", normalized, flags=re.IGNORECASE
    )
    normalized = re.sub(r"\s+\d{4}(\.\d+)*$", "", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\s+-\s+\d+(\.\d+)*$", "", normalized, flags=re.IGNORECASE)
    normalized = re.sub(
        r"\s+\(\d+(\.\d+)*(\.\d+)*\)$", "", normalized, flags=re.IGNORECASE
    )
    normalized = re.sub(r"\s+build\s+\d+", "", normalized, flags=re.IGNORECASE)
    normalized = re.sub(
        r"\s+\d+(\.\d+)*(\.\d+)*(\.\d+)*$", "", normalized, flags=re.IGNORECASE
    )

    # Remove architecture and platform info
    normalized = re.sub(
        r"\s+(x64|x86|64-bit|32-bit|amd64|i386)$", "", normalized, flags=re.IGNORECASE
    )
    normalized = re.sub(
        r"\s+\((x64|x86|64-bit|32-bit|amd64|i386)\)$",
        "",
        normalized,
        flags=re.IGNORECASE,
    )
    normalized = re.sub(
        r"\s+\(Python\s+[\d\.]+\s+(64-bit|32-bit)\)$",
        "",
        normalized,
        flags=re.IGNORECASE,
    )
    normalized = re.sub(r"\s+\(git\s+[a-f0-9]+\)$", "", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\s+\([^)]*bit[^)]*\)", "", normalized, flags=re.IGNORECASE)
    normalized = re.sub(
        r"\s+\([^)]*\d+\.\d+\.\d+[^)]*\)", "", normalized, flags=re.IGNORECASE
    )

    # Final cleanup
    normalized = re.sub(r"\s+", " ", normalized)
    normalized = re.sub(r"\s*-\s*$", "", normalized)
    normalized = re.sub(r"^\s*-\s*", "", normalized)
    normalized = normalized.strip()

    if not normalized or len(normalized) < 2:
        return ""

    return normalized


# Explicit alias map for fleet utilization rollups. Collapses vendor product
# families (launcher + main app + executable filename + version suffixes)
# into a single canonical name. Order matters — more specific patterns first.
# Patterns match case-insensitively against the raw app_name (substring).
_APP_NAME_ALIAS_RULES: List[tuple] = [
    # SideFX Houdini family
    (r"\bhoudini\b", "Houdini"),
    (r"\bhindie\b", "Houdini"),
    (r"\bhython\b", "Houdini"),
    # Autodesk
    (r"\bmaya\b", "Maya"),
    (r"\b3ds\s*max\b", "3ds Max"),
    (r"\bmotionbuilder\b", "MotionBuilder"),
    (r"\bmudbox\b", "Mudbox"),
    (r"\bautocad\b", "AutoCAD"),
    (r"\brevit\b", "Revit"),
    # Foundry
    (r"\bnukex\b", "Nuke"),
    (r"\bnuke\b", "Nuke"),
    (r"\bmari\b", "Mari"),
    (r"\bkatana\b", "Katana"),
    (r"\bmodo\b", "Modo"),
    # Maxon / Pixologic
    (r"\bcinema\s*4d\b", "Cinema 4D"),
    (r"\bc4d\b", "Cinema 4D"),
    (r"\bredshift\b", "Redshift"),
    (r"\bzbrush\b", "ZBrush"),
    # Adobe Substance (Adobe owns Allegorithmic now)
    (r"\badobesubstance\b", "Adobe Substance 3D"),
    (r"\bsubstance\s*sdl\b", "Adobe Substance 3D"),
    (r"\bsubstance\s*3d\s*painter\b", "Substance 3D Painter"),
    (r"\bsubstance\s*3d\s*designer\b", "Substance 3D Designer"),
    (r"\bsubstance\s*3d\s*sampler\b", "Substance 3D Sampler"),
    (r"\bsubstance\s*3d\s*stager\b", "Substance 3D Stager"),
    (r"\bsubstance\s*3d\s*modeler\b", "Substance 3D Modeler"),
    (r"\bsubstance\s*painter\b", "Substance 3D Painter"),
    (r"\bsubstance\s*designer\b", "Substance 3D Designer"),
    # Adobe Creative Cloud
    (r"\bphotoshop\b", "Adobe Photoshop"),
    (r"\billustrator\b", "Adobe Illustrator"),
    (r"\bafter\s*effects\b", "Adobe After Effects"),
    (r"\bpremiere\s*pro\b", "Adobe Premiere Pro"),
    (r"\bpremiere\b", "Adobe Premiere Pro"),
    (r"\bmedia\s*encoder\b", "Adobe Media Encoder"),
    (r"\bindesign\b", "Adobe InDesign"),
    (r"\baudition\b", "Adobe Audition"),
    (r"\badobe\s*animate\b", "Adobe Animate"),
    (r"\blightroom\s*classic\b", "Adobe Lightroom Classic"),
    (r"\blightroom\b", "Adobe Lightroom"),
    (r"\badobe\s*bridge\b", "Adobe Bridge"),
    (r"\badobe\s*xd\b", "Adobe XD"),
    (r"\badobe\s*dimension\b", "Adobe Dimension"),
    (r"\bcharacter\s*animator\b", "Adobe Character Animator"),
    # Blackmagic
    (r"\bdavinci\s*resolve\b", "DaVinci Resolve"),
    (r"\bfusion\s*studio\b", "Fusion Studio"),
    # Open-source
    (r"\bblender\b", "Blender"),
    (r"\bkrita\b", "Krita"),
    # Game engines
    (r"\bunreal\s*engine\b", "Unreal Engine"),
    (r"\bunreal\b", "Unreal Engine"),
    (r"\bunity\s*hub\b", "Unity Hub"),
    (r"\bunity\b", "Unity"),
    # Toon Boom
    (r"\btoon\s*boom\s*harmony\b", "Toon Boom Harmony"),
    (r"\btoon\s*boom\s*storyboard\b", "Toon Boom Storyboard Pro"),
    (r"\bharmony\s*premium\b", "Toon Boom Harmony"),
    (r"\bstoryboard\s*pro\b", "Toon Boom Storyboard Pro"),
    # 2D animation / painting
    (r"\btvpaint\b", "TVPaint Animation"),
    (r"\bclip\s*studio\s*paint\b", "Clip Studio Paint"),
    (r"\bsketchbook\b", "Autodesk SketchBook"),
    (r"\bstoryboarder\b", "Storyboarder"),
    (r"\bopentoonz\b", "OpenToonz"),
    # Look-dev / rendering / look-around
    (r"\bkeyshot\b", "KeyShot"),
    (r"\bmarmoset\s*toolbag\b", "Marmoset Toolbag"),
    (r"\bspeedtree\b", "SpeedTree"),
    (r"\bmarvelous\s*designer\b", "Marvelous Designer"),
    (r"\brhinoceros\b", "Rhinoceros"),
    (r"\brhino\s*\d", "Rhinoceros"),
    # Render farm (Thinkbox/AWS Deadline). Specific subtypes first.
    (r"\bdeadline\s*monitor\b", "Deadline Monitor"),
    (r"\bdeadline\s*launcher\b", "Deadline Launcher"),
    (r"\bdeadline\s*worker\b", "Deadline Worker"),
    (r"\bdeadline\s*slave\b", "Deadline Worker"),
    (r"\bdeadline\s*client\b", "Deadline Client"),
    (r"\bdeadline\b", "Deadline"),
    # Review / playback (Autodesk Shotgrid)
    (r"\bshotgrid\s*rv\b", "Shotgrid RV"),
    (r"\bshotgun\s*rv\b", "Shotgrid RV"),
    # Audio
    (r"\bpro\s*tools\b", "Pro Tools"),
    (r"\blogic\s*pro\b", "Logic Pro"),
    (r"\bgarageband\b", "GarageBand"),
    (r"\baudacity\b", "Audacity"),
    (r"\bobs\s*studio\b", "OBS Studio"),
    (r"\breaper\b", "REAPER"),
    (r"\bableton\s*live\b", "Ableton Live"),
    # Apple Pro Apps
    (r"\bfinal\s*cut\s*pro\b", "Final Cut Pro"),
    (r"\bcompressor\b", "Compressor"),
]

_APP_NAME_ALIAS_COMPILED = [
    (re.compile(pat, re.IGNORECASE), canon) for pat, canon in _APP_NAME_ALIAS_RULES
]


def canonicalize_app_name(app_name: str) -> str:
    """
    Canonicalize an application name for fleet utilization rollups.

    Strategy:
      1. Match against the explicit alias map (vendor product families).
         Collapses variants like "Houdini Launcher", "Houdini FX 21.0.440",
         "hindie.exe" into a single canonical "Houdini".
      2. Fall back to normalize_app_name() for generic version/arch stripping.
      3. If both produce empty, return the raw name unchanged.

    Applied at query time in fleet endpoints so alias rules can be iterated
    without re-collecting data or running migrations.
    """
    if not app_name or not isinstance(app_name, str):
        return ""

    raw = app_name.strip()
    if not raw:
        return ""

    for pattern, canonical in _APP_NAME_ALIAS_COMPILED:
        if pattern.search(raw):
            return canonical

    normalized = normalize_app_name(raw)
    return normalized if normalized else raw


# ---------------------------------------------------------------------------
# WebPubSub (real-time events)
# ---------------------------------------------------------------------------

EVENTS_CONNECTION = os.getenv("EVENTS_CONNECTION")
WEB_PUBSUB_HUB = "events"
_webpubsub_service = None


def get_webpubsub_service():
    """Get or create a cached WebPubSub service client."""
    global _webpubsub_service
    if _webpubsub_service is None and WEBPUBSUB_AVAILABLE and EVENTS_CONNECTION:
        try:
            _webpubsub_service = WebPubSubServiceClient.from_connection_string(
                connection_string=EVENTS_CONNECTION, hub=WEB_PUBSUB_HUB
            )
        except Exception as e:
            logger.error(f"Failed to create WebPubSub service: {e}")
    return _webpubsub_service


async def broadcast_event(event_data: dict):
    """Broadcast an event to all connected WebSocket clients."""
    service = get_webpubsub_service()
    if not service:
        return
    try:
        service.send_to_all(message=event_data, content_type="application/json")
        logger.info(
            f"Broadcast event to WebPubSub: {event_data.get('kind', 'unknown')} for {event_data.get('device', 'unknown')}"
        )
    except Exception as e:
        logger.error(f"Failed to broadcast event: {e}")
