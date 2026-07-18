"""
Health, root, and WebSocket negotiate endpoints.
"""

from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from dependencies import (
    logger,
    verify_authentication,
    get_db_connection,
    HealthResponse,
    WEBPUBSUB_AVAILABLE,
    EVENTS_CONNECTION,
    WEB_PUBSUB_HUB,
)

try:
    from azure.messaging.webpubsubservice import WebPubSubServiceClient
except ImportError:
    WebPubSubServiceClient = None

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, tags=["health"])
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
        cursor.fetchone()
        conn.close()

        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": "connected",
            "version": "1.0.0",
            "deviceIdStandard": "serialNumber",
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "unhealthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "database": "unavailable",
            },
        )


@router.get("/health/live", tags=["health"])
async def liveness():
    """
    Liveness probe -- the process is up and serving.

    **No authentication required. No dependencies checked.** Use this as the
    load-balancer/orchestrator liveness target so a transient database outage
    does not cause healthy replicas to be killed.
    """
    return {"status": "ok"}


@router.get("/health/ready", tags=["health"])
async def readiness():
    """
    Readiness probe -- verifies the API can reach its database.

    **No authentication required.** Returns 503 when the database is
    unreachable so orchestrators stop routing traffic to this replica until it
    recovers. No internal error detail is exposed.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        conn.close()
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "database": "unavailable",
            },
        )

    return {
        "status": "ready",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": "connected",
    }


@router.get("/negotiate", dependencies=[Depends(verify_authentication)], tags=["health"])
async def signalr_negotiate(device: str = Query(default="dashboard")):
    """
    SignalR/WebPubSub negotiate endpoint.

    Generates a client access token for Azure Web PubSub connection. The token
    grants a live view of the fleet event stream, so callers must authenticate;
    the dashboard reaches this through the BFF proxy, which supplies the
    internal secret.
    """
    if not WEBPUBSUB_AVAILABLE:
        logger.warning("Azure Web PubSub SDK not available, falling back to mock")
        return {
            "url": "wss://reportmate-signalr.webpubsub.azure.com/client/hubs/events",
            "accessToken": None,
            "error": "WebPubSub SDK not installed",
        }

    if not EVENTS_CONNECTION:
        logger.warning("EVENTS_CONNECTION not configured, SignalR unavailable")
        return {
            "url": None,
            "accessToken": None,
            "error": "EVENTS_CONNECTION not configured",
        }

    try:
        service = WebPubSubServiceClient.from_connection_string(
            connection_string=EVENTS_CONNECTION, hub=WEB_PUBSUB_HUB
        )

        token_response = service.get_client_access_token(
            user_id=device,
            minutes_to_expire=60,
            roles=["webpubsub.joinLeaveGroup.events"],
        )

        logger.info(f"Generated WebPubSub token for client: {device}")

        return {
            "url": token_response.get("url"),
            "accessToken": token_response.get("token"),
            "expiresOn": (
                datetime.now(timezone.utc) + timedelta(minutes=60)
            ).isoformat(),
        }

    except Exception as e:
        logger.error(f"Failed to generate WebPubSub token: {e}", exc_info=True)
        return {
            "url": None,
            "accessToken": None,
            "error": f"Token generation failed: {str(e)}",
        }
