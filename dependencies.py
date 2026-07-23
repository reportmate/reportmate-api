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
import hashlib
import hmac
import json
import logging
import os
import random
import re
import secrets
import socket
import threading
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

from oidc_auth import verify_oidc_bearer

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
    "events_failures": 15,
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
        "events/list_ingest_failures",
        "events/count_ingest_failures",
        "events/summary_ingest_failures",
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

# Connection-pool sizing. Defaults are conservative for a scale-to-zero
# container serving one fleet; raise DB_POOL_MAX for higher concurrency.
_DB_POOL_MIN = int(os.getenv("DB_POOL_MIN", "2"))
_DB_POOL_MAX = int(os.getenv("DB_POOL_MAX", "10"))

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

REPORTMATE_PASSPHRASE = os.getenv("REPORTMATE_PASSPHRASE")
API_INTERNAL_SECRET = os.getenv("API_INTERNAL_SECRET")
AZURE_MANAGED_IDENTITY_HEADER = "X-MS-CLIENT-PRINCIPAL-ID"
DISABLE_AUTH = os.getenv("DISABLE_AUTH", "false").lower() in ("true", "1", "yes")

# X-MS-CLIENT-PRINCIPAL-ID is only evidence of identity when Azure Easy Auth
# fronts this app: the platform strips inbound X-MS-* headers and injects
# validated values. Without that guarantee anyone can type the header, so it
# is ignored unless the operator explicitly opts in.
TRUST_EASYAUTH_PRINCIPAL_HEADER = os.getenv(
    "TRUST_EASYAUTH_PRINCIPAL_HEADER", "false"
).lower() in ("true", "1", "yes")

# Deployment environment marker (optional). Used only to gate the DISABLE_AUTH
# safety check below; absence is treated as "unknown", not "non-prod".
APP_ENV = os.getenv("APP_ENV", os.getenv("ENVIRONMENT", "")).strip().lower()
_NONPROD_ENVS = {"development", "dev", "local", "test", "testing"}
_PROD_ENVS = {"production", "prod", "staging", "stage"}

if DISABLE_AUTH:
    # Surface this prominently — a deployment that ships with auth disabled is a
    # security hole, and the per-request bypass otherwise only logs at debug.
    logger.warning(
        "[SECURITY] DISABLE_AUTH is enabled: ALL API requests bypass authentication. "
        "This must never be set in production."
    )


def assert_auth_enabled_for_prod() -> None:
    """Fail fast if authentication is disabled in a production-like deployment.

    Called from application startup. ``DISABLE_AUTH`` is a development-only
    escape hatch; refusing to boot with it set in production turns a silent,
    fleet-wide security hole into a loud, unmissable deploy failure.

    A deployment is treated as production-like when EITHER ``APP_ENV`` names a
    prod/staging environment OR real auth secrets (``REPORTMATE_PASSPHRASE`` /
    ``API_INTERNAL_SECRET``) are configured -- so no new infrastructure marker
    is required. An explicit non-prod ``APP_ENV`` (development/local/test) is
    the deliberate escape hatch and is always allowed.
    """
    if not DISABLE_AUTH:
        return
    if APP_ENV in _NONPROD_ENVS:
        return  # explicit dev/test opt-in
    secrets_configured = bool(REPORTMATE_PASSPHRASE or API_INTERNAL_SECRET)
    if APP_ENV in _PROD_ENVS or secrets_configured:
        raise RuntimeError(
            "Refusing to start: DISABLE_AUTH=true with a production-like "
            f"configuration (APP_ENV={APP_ENV or 'unset'}, "
            f"secrets_configured={secrets_configured}). Authentication must not "
            "be disabled in production. Set APP_ENV=development to use "
            "DISABLE_AUTH locally, or unset DISABLE_AUTH."
        )


# ---------------------------------------------------------------------------
# Authorization scopes and per-client API keys
# ---------------------------------------------------------------------------
#
# Scopes are least-privilege buckets enforced per request:
#   read   -- fleet/device GETs
#   ingest -- POST telemetry (events, device upsert)
#   admin  -- mutations, deletes, and admin endpoints
#
# Legacy credentials (shared passphrase, internal secret, managed identity)
# are granted ALL scopes for backward compatibility, so nothing in the fleet
# breaks. Only per-client API keys are scope-limited; migrate callers onto
# scoped keys over time, then retire the shared passphrase.

ALL_SCOPES = ("read", "ingest", "admin")
API_KEY_PREFIX = "rm"


def _required_scope(method: str, path: str) -> str:
    """Map an HTTP request to the scope it requires."""
    if "/admin" in path:
        return "admin"
    if method in ("GET", "HEAD", "OPTIONS"):
        return "read"
    if method == "POST":
        return "ingest"
    return "admin"  # PUT, PATCH, DELETE


def _enforce_scope(request: Request, scopes) -> None:
    """Raise 403 if the authenticated principal lacks the required scope."""
    required = _required_scope(request.method, request.url.path)
    if required not in (scopes or []):
        raise HTTPException(
            status_code=403,
            detail=f"This credential lacks the required '{required}' scope.",
        )


def _hash_secret(secret: str) -> str:
    """sha256 hex of an API key secret (only the hash is ever stored)."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_api_key():
    """Mint a new key. Returns (key_id, secret, full_key).

    Format: ``rm_<id>_<secret>`` -- ``id`` is the public lookup handle,
    ``secret`` is shown to the operator exactly once and never stored in clear.
    """
    key_id = secrets.token_hex(6)  # 12 hex chars, public
    secret = secrets.token_hex(24)  # 48 hex chars
    return key_id, secret, f"{API_KEY_PREFIX}_{key_id}_{secret}"


def parse_api_key(presented: str):
    """Split ``rm_<id>_<secret>``. Returns (key_id, secret) or None if malformed."""
    if not presented or not isinstance(presented, str):
        return None
    parts = presented.split("_", 2)
    if len(parts) != 3 or parts[0] != API_KEY_PREFIX:
        return None
    _, key_id, secret = parts
    if not key_id or not secret:
        return None
    return key_id, secret


def get_api_key_record(key_id: str):
    """Look up an api_keys row by public id.

    Returns ``{client_id, key_hash, scopes:list, active:bool}`` or None.
    Isolated so tests can monkeypatch the lookup without a database.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT client_id, key_hash, scopes, active FROM api_keys WHERE id = %s",
            (key_id,),
        )
        row = cursor.fetchone()
        conn.close()
    except Exception as e:
        logger.error(f"API key lookup failed: {e}")
        return None
    if not row:
        return None
    client_id, key_hash, scopes, active = row
    if isinstance(scopes, str):
        try:
            scopes = json.loads(scopes)
        except Exception:
            scopes = []
    return {
        "client_id": client_id,
        "key_hash": key_hash,
        "scopes": list(scopes or []),
        "active": bool(active),
    }


def _touch_api_key_last_used(key_id: str) -> None:
    """Best-effort last_used stamp; failures must not break authentication."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE api_keys SET last_used = NOW() WHERE id = %s", (key_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.debug(f"Could not update api_keys.last_used for {key_id}: {e}")


def verify_api_key(presented: str, client_host=None):
    """Validate an ``X-API-Key`` value. Returns an auth dict or None.

    Constant-time hash comparison; rejects malformed, unknown, inactive, or
    mismatched keys. The auth dict carries the key's scopes for enforcement.
    """
    parsed = parse_api_key(presented)
    if not parsed:
        return None
    key_id, secret = parsed
    record = get_api_key_record(key_id)
    if not record or not record["active"]:
        return None
    if not hmac.compare_digest(_hash_secret(secret), record["key_hash"] or ""):
        return None
    _touch_api_key_last_used(key_id)
    return {
        "method": "api_key",
        "key_id": key_id,
        "client_id": record["client_id"],
        "scopes": record["scopes"],
        "client_ip": client_host,
    }


def audit_api_key(key_id, action: str, actor=None, detail=None) -> None:
    """Append an api_key_audit row. Best-effort; never blocks the operation."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO api_key_audit (key_id, action, actor, detail) "
            "VALUES (%s, %s, %s, %s)",
            (key_id, action, actor, json.dumps(detail or {})),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"API key audit write failed ({action} {key_id}): {e}")


# ---------------------------------------------------------------------------
# Ingest failure recording
# ---------------------------------------------------------------------------
#
# A device that fails auth or payload validation still told us exactly who it
# is -- the client sends serial/UUID/hostname alongside its credentials in the
# same request. Persisting rejections makes "machine X is trying to check in
# but being turned away" visible in the product (GET /api/v1/events/failures)
# instead of only in container stdout. Best-effort by design: recording must
# never break or slow the rejection path, so every error here is swallowed
# after a log line. No FK to devices -- a rejected machine is typically not
# registered yet, which is the whole point of recording it.

INGEST_FAILURES_RETENTION_DAYS = int(
    os.getenv("INGEST_FAILURES_RETENTION_DAYS", "30")
)
# Hard row cap so the table stays bounded even under a fleet-wide outage or a
# scanner flood; oldest rows beyond the cap are trimmed on the purge cycle.
INGEST_FAILURES_MAX_ROWS = int(os.getenv("INGEST_FAILURES_MAX_ROWS", "50000"))
# A device retrying in a loop produces identical failures; collapse repeats of
# the same (serial, reason, ip) within this window into the first row.
INGEST_FAILURES_DEDUP_MINUTES = int(os.getenv("INGEST_FAILURES_DEDUP_MINUTES", "15"))

_INGEST_IDENTITY_FIELDS = (
    "serial_number",
    "device_uuid",
    "device_name",
    "platform",
    "client_version",
)


def extract_ingest_identity(payload) -> Dict[str, Optional[str]]:
    """Best-effort device identity from a (possibly malformed) ingest payload.

    Accepts the parsed payload dict, raw request bytes, or None. Never raises.
    """
    identity: Dict[str, Optional[str]] = {f: None for f in _INGEST_IDENTITY_FIELDS}
    try:
        if isinstance(payload, (bytes, bytearray)):
            payload = json.loads(payload)
        if not isinstance(payload, dict):
            return identity
        meta = payload.get("metadata")
        if not isinstance(meta, dict):
            return identity
        identity["serial_number"] = meta.get("serialNumber") or meta.get("serial_number")
        identity["device_uuid"] = meta.get("deviceId") or meta.get("device_id")
        identity["platform"] = meta.get("platform")
        identity["client_version"] = meta.get("clientVersion") or meta.get("client_version")
        additional = meta.get("additional")
        if isinstance(additional, dict):
            identity["device_name"] = additional.get("deviceName") or additional.get("device_name")
    except Exception:
        pass
    return {
        k: (str(v)[:255] if v not in (None, "") else None)
        for k, v in identity.items()
    }


def record_ingest_failure(
    *,
    failure_type: str,
    reason: str,
    status_code: Optional[int] = None,
    detail: Optional[str] = None,
    endpoint: Optional[str] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    identity: Optional[Dict[str, Optional[str]]] = None,
) -> None:
    """Persist one rejected check-in to ingest_failures. Never raises."""
    try:
        ident = identity or {}
        conn = get_db_connection()
        inserted = False
        try:
            cursor = conn.cursor()
            # Burst guard: a client retrying in a loop (or a scanner hammering
            # the endpoint) repeats the same failure -- keep the first row per
            # (serial, reason, ip) per dedup window instead of one per attempt.
            cursor.execute(
                """INSERT INTO ingest_failures
                       (failure_type, reason, status_code, detail, endpoint,
                        client_ip, user_agent, serial_number, device_uuid,
                        device_name, platform, client_version)
                   SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                   WHERE NOT EXISTS (
                       SELECT 1 FROM ingest_failures
                       WHERE reason = %s
                         AND serial_number IS NOT DISTINCT FROM %s
                         AND client_ip IS NOT DISTINCT FROM %s
                         AND occurred_at > NOW() - make_interval(mins => %s)
                   )
                   RETURNING id""",
                (
                    failure_type[:20],
                    reason[:50],
                    status_code,
                    (detail or "")[:2000] or None,
                    (endpoint or "")[:200] or None,
                    (client_ip or "")[:64] or None,
                    (user_agent or "")[:400] or None,
                    ident.get("serial_number"),
                    ident.get("device_uuid"),
                    ident.get("device_name"),
                    ident.get("platform"),
                    ident.get("client_version"),
                    reason[:50],
                    ident.get("serial_number"),
                    (client_ip or "")[:64] or None,
                    INGEST_FAILURES_DEDUP_MINUTES,
                ),
            )
            inserted = cursor.fetchone() is not None
            # Opportunistic purge, same pattern as the events table: age out
            # old rows AND trim to a hard cap so the table stays bounded even
            # under a fleet-wide outage.
            if random.random() < 0.02:
                cursor.execute(
                    "DELETE FROM ingest_failures"
                    " WHERE occurred_at < NOW() - make_interval(days => %s)",
                    (INGEST_FAILURES_RETENTION_DAYS,),
                )
                cursor.execute(
                    """DELETE FROM ingest_failures
                       WHERE id <= COALESCE((
                           SELECT id FROM ingest_failures
                           ORDER BY id DESC
                           OFFSET %s LIMIT 1
                       ), 0)""",
                    (INGEST_FAILURES_MAX_ROWS,),
                )
            conn.commit()
        finally:
            conn.close()
        if inserted:
            logger.info(
                f"[INGEST-FAILURE] Recorded {failure_type}/{reason} "
                f"(serial={ident.get('serial_number')}, ip={client_ip})"
            )
    except Exception as e:
        logger.warning(f"[INGEST-FAILURE] Could not record {failure_type}/{reason}: {e}")


def _is_ingest_request(request: Request) -> bool:
    return request.method == "POST" and request.url.path.rstrip("/").endswith("/events")


async def _record_auth_failure(
    request: Request,
    *,
    reason: str,
    status_code: int,
    detail: str,
    user_agent: Optional[str],
) -> None:
    """Record an auth rejection worth surfacing. Never raises.

    Ingest POSTs are always recorded -- that is a device trying to check in,
    and its body carries the identity of the machine that failed. Other
    endpoints are recorded only when the caller presented a device-style
    credential (wrong passphrase / API key), so unauthenticated scanner
    probes of GET endpoints don't flood the table.
    """
    try:
        is_ingest = _is_ingest_request(request)
        if not is_ingest and reason not in ("invalid_passphrase", "invalid_api_key"):
            return
        identity = None
        if is_ingest:
            body = await request.body()
            if body:
                identity = extract_ingest_identity(body)
        record_ingest_failure(
            failure_type="auth",
            reason=reason,
            status_code=status_code,
            detail=detail,
            endpoint=request.url.path,
            client_ip=request.client.host if request.client else None,
            user_agent=user_agent,
            identity=identity,
        )
    except Exception as e:
        logger.warning(f"[INGEST-FAILURE] Auth-failure recording skipped: {e}")


async def verify_authentication(
    request: Request,
    x_api_passphrase: str = Header(None, alias="X-API-PASSPHRASE"),
    x_client_passphrase: str = Header(None, alias="X-Client-Passphrase"),
    x_internal_secret: str = Header(None, alias="X-Internal-Secret"),
    x_ms_client_principal_id: str = Header(None, alias="X-MS-CLIENT-PRINCIPAL-ID"),
    x_api_key: str = Header(None, alias="X-API-Key"),
    authorization: str = Header(None, alias="Authorization"),
    x_forwarded_for: str = Header(None, alias="X-Forwarded-For"),
    user_agent: str = Header(None, alias="User-Agent"),
):
    """
    Verify authentication and authorize the request against required scopes.

    Each branch resolves an ``auth`` principal carrying a ``scopes`` list; a
    single ``_enforce_scope`` gate at the end authorizes the request. Methods
    are checked in order:
    0. Disabled: DISABLE_AUTH=true bypasses auth (development only; guarded
       against production by ``assert_auth_enabled_for_prod`` at startup).
    1. Internal Secret: X-Internal-Secret (BFF/container-to-container) -- legacy, full access.
    2. Managed Identity: X-MS-CLIENT-PRINCIPAL-ID (Azure Easy Auth) -- legacy, full access.
    3. API Key: X-API-Key (per-client, scope-limited).
    3.5 OIDC bearer: Authorization: Bearer <jwt> (federated SSO, IdP-agnostic,
       scope-limited via IdP roles) -- secretless; inert until configured.
    4. Passphrase: X-API-PASSPHRASE / X-Client-Passphrase (clients, functions) -- legacy, full access.

    Legacy credentials receive ALL scopes for backward compatibility; per-client
    API keys carry only their granted scopes. This keeps the deployed fleet
    working while callers migrate onto scoped keys.
    """
    if DISABLE_AUTH:
        logger.debug(
            f"[SUCCESS] Authentication disabled via DISABLE_AUTH env var (User-Agent: {user_agent})"
        )
        return {
            "method": "auth_disabled",
            "user_agent": user_agent,
            "scopes": list(ALL_SCOPES),
        }

    client_host = request.client.host if request.client else None
    auth = None

    # Method 1: Internal Secret (BFF / container-to-container) -- full access.
    if x_internal_secret:
        if not API_INTERNAL_SECRET:
            logger.error(
                "[ERR] API_INTERNAL_SECRET not configured but client attempted internal secret auth"
            )
            raise HTTPException(
                status_code=500, detail="Server internal authentication not configured"
            )
        if not hmac.compare_digest(x_internal_secret, API_INTERNAL_SECRET):
            logger.warning(
                f"[ERR] Invalid internal secret attempt from {user_agent} (IP: {client_host})"
            )
            await _record_auth_failure(
                request,
                reason="invalid_internal_secret",
                status_code=401,
                detail="X-Internal-Secret did not match",
                user_agent=user_agent,
            )
            raise HTTPException(
                status_code=401, detail="Invalid internal authentication credentials"
            )
        auth = {
            "method": "internal_secret",
            "user_agent": user_agent,
            "client_ip": client_host,
            "scopes": list(ALL_SCOPES),
        }

    # Method 2: Azure Managed Identity (Easy Auth) -- legacy IdP integration,
    # full access. Honoured only behind an explicit opt-in (see the config
    # comment on TRUST_EASYAUTH_PRINCIPAL_HEADER); otherwise the header is
    # attacker-typable and the branch would be a full-scope bypass.
    elif x_ms_client_principal_id and TRUST_EASYAUTH_PRINCIPAL_HEADER:
        auth = {
            "method": "managed_identity",
            "principal_id": x_ms_client_principal_id,
            "scopes": list(ALL_SCOPES),
        }

    # Method 3: Per-client API key (scope-limited).
    elif x_api_key:
        auth = verify_api_key(x_api_key, client_host=client_host)
        if auth is None:
            # The deployed Windows client sends BOTH X-API-Key and
            # X-Client-Passphrase (ApiService.cs adds each when configured).
            # Hard-failing here rejected every fleet device before its valid
            # passphrase was ever considered - 100% ingestion outage on the
            # 0056ae0 rollout. When another credential accompanies a failed
            # API key, fall through to it; only reject outright when the API
            # key was the sole credential presented.
            if x_api_passphrase or x_client_passphrase:
                logger.warning(
                    f"[WARN] Invalid API key from {user_agent} (IP: {client_host}) - "
                    "falling back to accompanying passphrase credential"
                )
            else:
                logger.warning(
                    f"[ERR] Invalid API key attempt from {user_agent} (IP: {client_host})"
                )
                await _record_auth_failure(
                    request,
                    reason="invalid_api_key",
                    status_code=401,
                    detail="X-API-Key was not recognized (sole credential presented)",
                    user_agent=user_agent,
                )
                raise HTTPException(status_code=401, detail="Invalid API key")

    # Method 3.5: Federated identity -- provider-agnostic OIDC bearer token.
    # Validates an Authorization: Bearer JWT against configurable issuer(s)/
    # audience/JWKS (env OIDC_ISSUERS / OIDC_AUDIENCE / OIDC_JWKS_URI), for any
    # OIDC provider (Entra, Okta, Auth0, Keycloak, Google) and multiple issuers
    # at once. The IdP proves identity by signature -- ReportMate stores no
    # secret for this path. IdP roles/scopes map to ReportMate scopes and flow
    # through the same _enforce_scope gate below. Inert until configured
    # (ENABLE_OIDC_AUTH + issuers + audience), so this is purely additive.
    elif authorization and authorization.lower().startswith("bearer "):
        auth = verify_oidc_bearer(authorization, client_host=client_host)
        if auth is None:
            # Mirror the API-key fall-through: if another credential accompanies
            # a rejected bearer, let it be considered; only hard-fail when the
            # bearer token was the sole credential presented.
            if x_api_passphrase or x_client_passphrase:
                logger.warning(
                    f"[WARN] Rejected bearer token from {user_agent} (IP: {client_host}) - "
                    "falling back to accompanying passphrase credential"
                )
            else:
                logger.warning(
                    f"[ERR] Rejected bearer token from {user_agent} (IP: {client_host})"
                )
                await _record_auth_failure(
                    request,
                    reason="invalid_bearer_token",
                    status_code=401,
                    detail="Bearer token was rejected (sole credential presented)",
                    user_agent=user_agent,
                )
                raise HTTPException(
                    status_code=401, detail="Invalid or unaccepted bearer token"
                )

    # Method 4: Passphrase (Windows/macOS clients, alert functions) -- legacy, full access.
    # Note: `auth is None` (not elif) so a failed-but-accompanied API key above
    # falls through to the passphrase instead of locking the fleet out.
    if auth is None and (x_api_passphrase or x_client_passphrase):
        if not REPORTMATE_PASSPHRASE:
            logger.error(
                "[ERR] REPORTMATE_PASSPHRASE not configured but client attempted passphrase auth"
            )
            raise HTTPException(
                status_code=500, detail="Server authentication not configured"
            )
        presented = x_api_passphrase or x_client_passphrase
        if not hmac.compare_digest(presented, REPORTMATE_PASSPHRASE):
            logger.warning(
                f"[ERR] Invalid passphrase attempt from {user_agent} (IP: {client_host})"
            )
            await _record_auth_failure(
                request,
                reason="invalid_passphrase",
                status_code=401,
                detail="Client passphrase did not match",
                user_agent=user_agent,
            )
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )
        auth = {
            "method": "passphrase",
            "user_agent": user_agent,
            "client_ip": client_host,
            "scopes": list(ALL_SCOPES),
        }

    if auth is None:
        if x_ms_client_principal_id and not TRUST_EASYAUTH_PRINCIPAL_HEADER:
            logger.warning(
                f"[ERR] X-MS-CLIENT-PRINCIPAL-ID presented without TRUST_EASYAUTH_PRINCIPAL_HEADER enabled; header ignored (IP: {client_host})"
            )
        logger.warning(
            f"[ERR] Unauthenticated access attempt from {user_agent} (IP: {client_host}, X-Forwarded-For: {x_forwarded_for})"
        )
        await _record_auth_failure(
            request,
            reason="missing_credentials",
            status_code=401,
            detail="No credentials presented (client likely has no passphrase/API key configured)",
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Supply X-API-Key (per-client), "
            "X-Client-Passphrase (clients), or X-Internal-Secret (internal).",
        )

    try:
        _enforce_scope(request, auth.get("scopes", []))
    except HTTPException as scope_exc:
        await _record_auth_failure(
            request,
            reason="insufficient_scope",
            status_code=scope_exc.status_code,
            detail=str(scope_exc.detail),
            user_agent=user_agent,
        )
        raise
    return auth


# ---------------------------------------------------------------------------
# Database connection
# ---------------------------------------------------------------------------


def _parse_database_url(url: str) -> dict:
    """Parse a postgres[ql] URL into pg8000 connect kwargs.

    Accepts both ``postgresql://`` and ``postgres://`` (cloud providers emit
    either). Raises ValueError on an unrecognized scheme.
    """
    if url.startswith("postgresql://"):
        rest = url[len("postgresql://") :]
    elif url.startswith("postgres://"):
        rest = url[len("postgres://") :]
    else:
        raise ValueError("DATABASE_URL must start with postgresql:// or postgres://")

    if "?" in rest:
        rest, _params = rest.split("?", 1)

    auth_part, host_part = rest.split("@")
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

    # SSL is required by Azure Postgres (default). Self-hosted/local Postgres
    # often has no TLS, so allow opting out via DB_SSL=false.
    db_ssl = os.getenv("DB_SSL", "true").lower() not in ("false", "0", "no", "disable")

    return {
        "host": host,
        "port": port,
        "database": database,
        "user": username,
        "password": password,
        "ssl_context": True if db_ssl else None,
        "timeout": 30,
    }


# Connection pool (DBUtils PooledDB over pg8000). Built lazily on first use so
# the module imports without a database, and rebuilt automatically if the URL
# changes (tests). Every request borrows a pooled connection via
# get_db_connection() and returns it by calling .close() — PooledDB's proxy
# returns the connection to the pool (rolling back any open transaction) rather
# than tearing down the TCP+TLS socket, which eliminates a per-request Azure
# Postgres handshake.
_pool = None
_pool_url = None
_pool_lock = threading.Lock()


def _enable_tcp_keepalive(conn):
    """Keep idle pooled sockets alive under the Azure NAT gateway idle timeout.

    A pooled connection that sits idle longer than the NAT gateway's flow idle
    timeout (default ~4 min) has its TCP flow silently dropped; the next borrow
    then fails with ``OSError: cannot read from timed out object`` deep inside
    pg8000. Enabling OS keepalives with probes starting well under that window
    keeps the flow warm so it is not dropped in the first place.

    Best-effort: this reaches for pg8000's private socket and the keepalive
    knobs are platform-specific (TCP_KEEPIDLE et al. are Linux; absent on
    macOS). Any failure here is non-fatal — the pool's ``failures`` reconnect
    (see ``_get_pool``) still recovers a dropped socket on next use.
    """
    sock = getattr(conn, "_usock", None)
    if sock is None:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Probe after 60s idle, every 30s, drop after 3 failures — all under the
        # ~240s NAT idle window so an idle pooled connection stays established.
        for opt_name, value in (
            ("TCP_KEEPIDLE", 60),
            ("TCP_KEEPINTVL", 30),
            ("TCP_KEEPCNT", 3),
        ):
            opt = getattr(socket, opt_name, None)
            if opt is not None:
                sock.setsockopt(socket.IPPROTO_TCP, opt, value)
    except OSError as e:  # pragma: no cover - platform-dependent, non-fatal
        logger.debug(f"TCP keepalive setup skipped: {e}")


def _get_pool():
    global _pool, _pool_url
    if _pool is not None and _pool_url == DATABASE_URL:
        return _pool
    with _pool_lock:
        if _pool is not None and _pool_url == DATABASE_URL:
            return _pool
        from dbutils.pooled_db import PooledDB

        kwargs = _parse_database_url(DATABASE_URL)

        def _creator():
            # Apply statement_timeout once per physical connection and COMMIT it
            # (via autocommit) so it survives PooledDB's rollback-on-return; a
            # SET left inside an uncommitted transaction would be undone by the
            # reset. The connection is handed back with autocommit off so the
            # routers keep their explicit commit/rollback semantics.
            conn = pg8000.connect(**kwargs)
            _enable_tcp_keepalive(conn)
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute("SET statement_timeout TO '120s'")
            cur.close()
            conn.autocommit = False
            return conn

        # Name the DB-API module explicitly so DBUtils uses pg8000's own
        # threadsafety and exception classes instead of inferring them from a
        # returned connection object.
        _creator.dbapi = pg8000

        logger.info(
            f"Building DB pool: {kwargs['host']}:{kwargs['port']}/{kwargs['database']} "
            f"(ssl={kwargs['ssl_context'] is not None}, "
            f"min={_DB_POOL_MIN}, max={_DB_POOL_MAX})"
        )
        _pool = PooledDB(
            creator=_creator,
            mincached=_DB_POOL_MIN,
            maxcached=_DB_POOL_MAX,
            maxconnections=_DB_POOL_MAX,
            blocking=True,  # wait for a free connection instead of erroring
            # ping=1 is ineffective with pg8000: DBUtils calls conn.ping(),
            # which pg8000 does not implement, so it disables the check after the
            # first attempt and stale connections are handed out unvalidated.
            # The real guard is `failures` below: a dropped socket surfaces as a
            # bare OSError ("cannot read from timed out object") which is NOT in
            # SteadyDB's default failover set (OperationalError/InterfaceError/
            # InternalError), so without listing it here a NAT idle-drop poisons
            # the pooled connection until the container restarts. Including
            # OSError lets SteadyDB transparently reconnect and retry on borrow.
            ping=1,
            failures=(
                pg8000.InterfaceError,
                pg8000.OperationalError,
                pg8000.InternalError,
                OSError,
            ),
            reset=True,  # rollback any open transaction on return to the pool
        )
        _pool_url = DATABASE_URL
        return _pool


def close_db_pool():
    """Close the pool and all its connections (called on app shutdown)."""
    global _pool, _pool_url
    with _pool_lock:
        if _pool is not None:
            try:
                _pool.close()
            except Exception as e:  # pragma: no cover - best-effort shutdown
                logger.warning(f"Error closing DB pool: {e}")
            _pool = None
            _pool_url = None


def get_db_connection():
    """Borrow a pooled database connection.

    Callers use it exactly as before — ``cursor()``, ``commit()``,
    ``rollback()`` — and release it by calling ``close()`` in a finally block,
    which returns it to the pool.
    """
    try:
        return _get_pool().connection()
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
