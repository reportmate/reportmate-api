"""
Health, root, and WebSocket negotiate endpoints.
"""

from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from dependencies import (
    logger, get_db_connection, HealthResponse,
    WEBPUBSUB_AVAILABLE, EVENTS_CONNECTION, WEB_PUBSUB_HUB,
)

try:
    from azure.messaging.webpubsubservice import WebPubSubServiceClient
except ImportError:
    WebPubSubServiceClient = None

router = APIRouter()


@router.get("/")
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
            "debug_database": "/api/debug/database (admin)"
        }
    }


@router.get("/api/health", response_model=HealthResponse, tags=["health"])
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


@router.get("/api/negotiate", tags=["health"])
async def signalr_negotiate(device: str = Query(default="dashboard")):
    """
    SignalR/WebPubSub negotiate endpoint.

    Generates a client access token for Azure Web PubSub connection.
    The token allows clients to connect and receive real-time events.
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
        service = WebPubSubServiceClient.from_connection_string(
            connection_string=EVENTS_CONNECTION,
            hub=WEB_PUBSUB_HUB
        )

        token_response = service.get_client_access_token(
            user_id=device,
            minutes_to_expire=60,
            roles=["webpubsub.joinLeaveGroup.events"]
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
