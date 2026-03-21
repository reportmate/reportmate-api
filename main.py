#!/usr/bin/env python3
"""
ReportMate FastAPI Application -- thin app factory.

All endpoint logic lives in the ``routers/`` package.  Shared helpers,
models, and database access live in ``dependencies.py``.
"""

import logging
import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException

from dependencies import (
    get_db_connection,
    limiter,
    logger,
    preload_sql_queries,
)
from routers import admin, devices, events, fleet, health, statistics

# ── Pre-load SQL queries into memory ────────────────────────────
preload_sql_queries()

# ── FastAPI app ─────────────────────────────────────────────────
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
        "email": "support@ecuad.ca",
    },
    license_info={
        "name": "AGPL-3.0",
        "url": "https://www.gnu.org/licenses/agpl-3.0.html",
    },
    openapi_tags=[
        {"name": "health", "description": "Health checks and status endpoints"},
        {"name": "devices", "description": "Device management operations - list, get, archive, delete devices"},
        {"name": "fleet", "description": "Fleet-wide bulk data endpoints for analytics dashboards"},
        {"name": "events", "description": "Event logging, retrieval, and real-time notifications"},
        {"name": "statistics", "description": "Fleet analytics, usage statistics, and reporting"},
        {"name": "admin", "description": "Administrative operations and diagnostics"},
    ],
)

# ── Middleware ──────────────────────────────────────────────────
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else []
CORS_ORIGINS = [o.strip() for o in CORS_ORIGINS if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "X-Client-Passphrase",
        "X-Internal-Secret",
        "X-API-PASSPHRASE",
        "Content-Type",
        "Authorization",
    ],
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Routers ────────────────────────────────────────────────────
app.include_router(health.router)
app.include_router(devices.router)
app.include_router(fleet.router)
app.include_router(events.router)
app.include_router(statistics.router)
app.include_router(admin.router)

# ── Startup: ensure performance indexes ────────────────────────
_indexes_ensured = False


@app.on_event("startup")
async def ensure_performance_indexes():
    """Create indexes needed for fast dashboard queries (idempotent)."""
    global _indexes_ensured
    if _indexes_ensured:
        return
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp_desc ON events(timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_events_device_id ON events(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_installs_device_id ON installs(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_inventory_device_id ON inventory(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_system_device_id ON system(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_hardware_device_id ON hardware(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_network_device_id ON network(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_devices_serial ON devices(serial_number)",
            "CREATE INDEX IF NOT EXISTS idx_devices_archived ON devices(archived)",
            # usage_history table + indexes (migration 009)
            """CREATE TABLE IF NOT EXISTS usage_history (
                id BIGSERIAL PRIMARY KEY,
                device_id TEXT NOT NULL,
                date DATE NOT NULL,
                app_name TEXT NOT NULL,
                publisher TEXT NOT NULL DEFAULT '',
                launches INTEGER NOT NULL DEFAULT 0,
                total_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
                users JSONB NOT NULL DEFAULT '[]'::jsonb,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(device_id, date, app_name)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_usage_history_device_date ON usage_history(device_id, date DESC)",
            "CREATE INDEX IF NOT EXISTS idx_usage_history_app_date ON usage_history(app_name, date DESC)",
            "CREATE INDEX IF NOT EXISTS idx_usage_history_date ON usage_history(date)",
            # Module tables missing indexes
            "CREATE INDEX IF NOT EXISTS idx_security_device_id ON security(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_profiles_device_id ON profiles(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_management_device_id ON management(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_applications_device_id ON applications(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_applications_data_gin ON applications USING gin(data)",
            "CREATE INDEX IF NOT EXISTS idx_peripherals_device_id ON peripherals(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_identity_device_id ON identity(device_id)",
            # Composite indexes for DISTINCT ON ... ORDER BY updated_at DESC pattern
            "CREATE INDEX IF NOT EXISTS idx_applications_device_updated ON applications(device_id, updated_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_installs_device_updated ON installs(device_id, updated_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_security_device_updated ON security(device_id, updated_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_hardware_device_updated ON hardware(device_id, updated_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_network_device_updated ON network(device_id, updated_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_management_device_updated ON management(device_id, updated_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_profiles_device_updated ON profiles(device_id, updated_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_system_device_updated ON system(device_id, updated_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_inventory_device_updated ON inventory(device_id, updated_at DESC)",
        ]:
            try:
                cursor.execute(stmt)
            except Exception:
                pass  # Index may already exist or table may not exist yet
        conn.commit()
        conn.close()
        _indexes_ensured = True
        logger.info("[STARTUP] Performance indexes ensured")
    except Exception as e:
        logger.warning(f"[STARTUP] Could not ensure indexes: {e}")


# ── Error handlers ─────────────────────────────────────────────
_HTTP_ERROR_LABELS = {
    400: "Bad request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not found",
    405: "Method not allowed",
    409: "Conflict",
    422: "Validation error",
    429: "Too many requests",
    500: "Internal server error",
    502: "Bad gateway",
    503: "Service unavailable",
}


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    label = _HTTP_ERROR_LABELS.get(exc.status_code, "Error")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": label, "detail": exc.detail or label, "status_code": exc.status_code},
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc), "status_code": 500},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
