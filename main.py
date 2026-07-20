#!/usr/bin/env python3
"""
ReportMate FastAPI Application -- thin app factory.

All endpoint logic lives in the ``routers/`` package.  Shared helpers,
models, and database access live in ``dependencies.py``.
"""

import logging
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException

from etag import ETagMiddleware
from pagination import PAGINATION_HEADERS
from metrics import MetricsMiddleware
from rate_limit import GlobalRateLimitMiddleware
from dependencies import (
    assert_auth_enabled_for_prod,
    close_db_pool,
    limiter,
    logger,
    preload_sql_queries,
    request_id_var,
)
from migrations import run_migrations
from routers import (
    admin,
    api_keys,
    devices,
    events,
    fleet,
    health,
    settings,
    statistics,
)

# ── Pre-load SQL queries into memory ────────────────────────────
preload_sql_queries()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: bring the schema to head on startup.

    Runs Alembic migrations (versioned, idempotent) before serving traffic,
    replacing the former ad-hoc startup DDL. Migration failure is logged but
    non-fatal so the app can still start (and serve reads) if a migration
    cannot be applied — the readiness probe remains the source of truth for
    whether the database is usable.
    """
    # Refuse to boot with authentication disabled in a production deployment.
    assert_auth_enabled_for_prod()
    try:
        run_migrations()
        logger.info("[STARTUP] Database migrations at head")
    except Exception as e:
        logger.error(f"[STARTUP] Migrations failed: {e}")
    yield
    # Drain the connection pool on shutdown.
    close_db_pool()


# ── FastAPI app ─────────────────────────────────────────────────
app = FastAPI(
    lifespan=lifespan,
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
        {
            "name": "devices",
            "description": "Device management operations - list, get, archive, delete devices",
        },
        {
            "name": "fleet",
            "description": "Fleet-wide bulk data endpoints for analytics dashboards",
        },
        {
            "name": "events",
            "description": "Event logging, retrieval, and real-time notifications",
        },
        {
            "name": "statistics",
            "description": "Fleet analytics, usage statistics, and reporting",
        },
        {"name": "admin", "description": "Administrative operations and diagnostics"},
        {
            "name": "settings",
            "description": "Server-side org settings: inventory mapping and security rules",
        },
    ],
)

# ── Middleware ──────────────────────────────────────────────────
CORS_ORIGINS = (
    os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else []
)
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
        "X-Request-ID",
        "Content-Type",
        "Authorization",
    ],
    expose_headers=["X-Request-ID", "ETag", *PAGINATION_HEADERS],
)

# Innermost of the custom middlewares: 429s (rate limit) and error responses
# skip it, and request-id still stamps 304s.
app.add_middleware(ETagMiddleware)

# Added before the request-id middleware so request-id wraps it and 429
# responses still carry X-Request-ID.
app.add_middleware(GlobalRateLimitMiddleware)

# Records request counts/latencies; skips the scrape endpoint itself.
app.add_middleware(MetricsMiddleware)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Assign or propagate a correlation id for every request.

    Honours an inbound ``X-Request-ID`` (so a caller/proxy trace flows through)
    and otherwise mints one. The id is bound to a contextvar for structured
    logging, stashed on request.state for the error handlers, and echoed back
    on the response.
    """
    rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]
    request.state.request_id = rid
    token = request_id_var.set(rid)
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response
    finally:
        request_id_var.reset(token)


# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Routers ────────────────────────────────────────────────────
# Canonical versioned prefix (appears in OpenAPI schema)
for _router_mod in (
    health,
    devices,
    fleet,
    events,
    statistics,
    admin,
    settings,
    api_keys,
):
    app.include_router(_router_mod.router, prefix="/api/v1")

# ── Root endpoint (unversioned) ────────────────────────────────
@app.get("/", tags=["health"])
async def root():
    """API root endpoint with service information."""
    return {
        "name": "ReportMate API",
        "version": "1.0.0",
        "status": "running",
        "platform": "FastAPI on Azure Container Apps",
        "deviceIdStandard": "serialNumber",
        "apiVersion": "v1",
        "endpoints": {
            "health": "/api/v1/health",
            "devices": "/api/v1/devices",
            "device": "/api/v1/device/{serial_number}",
            "modules": "/api/v1/{module}",
            "events": "/api/v1/events",
            "events_submit": "/api/v1/events (POST)",
            "negotiate": "/api/v1/negotiate",
            "dashboard": "/api/v1/dashboard",
        },
    }


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


def _error_reference(request: Request) -> str:
    """Correlation id tying a client-visible error to a server log line.

    Reuses the request's correlation id (from the request-id middleware) so the
    masked error body, the ``X-Request-ID`` response header, and the server log
    all share one id; falls back to a fresh id if the middleware did not run.
    """
    return getattr(request.state, "request_id", None) or uuid.uuid4().hex[:12]


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    label = _HTTP_ERROR_LABELS.get(exc.status_code, "Error")

    # Server-error (>=500) detail may carry internal state -- exception text,
    # SQL, connection strings, stack fragments. Never return it to the caller:
    # log it server-side against a reference and respond with a generic body.
    # Client-error (<500) detail is intended for the caller and is preserved.
    if exc.status_code >= 500:
        ref = _error_reference(request)
        logger.error(
            f"{request.method} {request.url.path} -> {exc.status_code}: {exc.detail}"
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": label,
                "detail": f"{label}. Reference: {ref}",
                "reference": ref,
                "status_code": exc.status_code,
            },
            headers={"X-Request-ID": ref},
        )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": label,
            "detail": exc.detail or label,
            "status_code": exc.status_code,
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Catch-all for anything not raised as an HTTPException. Log the full
    # traceback server-side; return a masked body with a reference id.
    ref = _error_reference(request)
    logger.exception(
        f"Unhandled exception on {request.method} {request.url.path}: {exc}"
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": f"Internal server error. Reference: {ref}",
            "reference": ref,
            "status_code": 500,
        },
        headers={"X-Request-ID": ref},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
