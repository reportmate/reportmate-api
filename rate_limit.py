"""Global request rate limiting.

slowapi's SlowAPIMiddleware cannot resolve route handlers under this FastAPI
version's _IncludedRouter routing structure, so the Limiter's declared
default_limits never applied to anything. This middleware enforces the global
default directly: fixed-window counting in process memory (per replica),
mirroring slowapi's in-memory storage semantics. Requests carrying the valid
internal secret bypass the default — the BFF funnels every dashboard user
through a handful of egress IPs and would otherwise starve real users.

Two buckets, because one address is not one device. Every on-campus machine
leaves through the same public egress, so a single per-address bucket put the
entire fleet in one 120/min allowance: 108 distinct devices were observed
making 457 requests in two minutes, and fleet-wide traffic peaks at 705/min
against a 120/min limit (median 9, p95 196, p99 347). That threw away 1,319
check-ins a day, each retried three times and then abandoned.

So the per-device bucket keys on the X-Device-Serial header the clients send,
and the per-address bucket remains as the flood shield, sized for the fleet
rather than for one machine. A serial header is spoofable and deliberately
still counted against the address bucket; this limiter exists to survive a
fleet stampede, not an adversary, and the endpoint requires authentication in
any case. Clients that do not send the header are governed by the address
bucket alone, which is what makes this a working mitigation before the client
carrying the header has finished rolling out.
"""

import hmac
import os
import threading
import time
from typing import Dict, Optional, Tuple

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

DEFAULT_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
# ~4x the observed fleet-wide peak of 705/min, so ordinary bursts and fleet
# growth pass while a genuine flood is still bounded.
DEFAULT_IP_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_IP_PER_MINUTE", "3000"))


def _presented_serial(request) -> Optional[str]:
    """The device serial the request claims, or None.

    Bounded and character-restricted before it becomes a bucket key: the value
    is unauthenticated at this point in the stack, and an unbounded key is a
    memory-growth vector against the in-process counter map.
    """
    raw = request.headers.get("X-Device-Serial")
    if not raw:
        return None
    cleaned = "".join(c for c in raw.strip() if c.isalnum() or c in "-_")[:64]
    return cleaned or None


class GlobalRateLimitMiddleware(BaseHTTPMiddleware):
    # Window state is class-level: the middleware instance lives inside the
    # app's built middleware stack where tests can't reach it, and one process
    # serves one app, so shared state is both the simplest and the correct
    # scope. reset() exists for tests.
    _lock = threading.Lock()
    _window_start = 0
    _counts: Dict[str, int] = {}

    def __init__(
        self,
        app,
        limit_per_minute: int = DEFAULT_LIMIT_PER_MINUTE,
        ip_limit_per_minute: int = DEFAULT_IP_LIMIT_PER_MINUTE,
    ):
        super().__init__(app)
        self.limit = limit_per_minute
        self.ip_limit = ip_limit_per_minute

    @classmethod
    def _allow(cls, key: str, limit: int) -> Tuple[bool, int]:
        now = int(time.time())
        window = now - (now % 60)
        with cls._lock:
            if window != cls._window_start:
                cls._window_start = window
                cls._counts = {}
            count = cls._counts.get(key, 0) + 1
            cls._counts[key] = count
            return count <= limit, 60 - (now % 60)

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._window_start = 0
            cls._counts = {}

    async def dispatch(self, request, call_next):
        from dependencies import API_INTERNAL_SECRET, resolve_client_ip

        presented = request.headers.get("X-Internal-Secret")
        if (
            presented
            and API_INTERNAL_SECRET
            and hmac.compare_digest(presented, API_INTERNAL_SECRET)
        ):
            return await call_next(request)

        # Key on the ORIGINATING client, not the ingress connection: a
        # per-connection-IP key collapsed ~370 devices into two shared 120/min
        # buckets and mass-429'd device event submissions within hours of
        # rollout. resolve_client_ip carries the reasoning.
        client = resolve_client_ip(request) or "unknown"
        serial = _presented_serial(request)

        # Both buckets are always counted, even when the device bucket is the
        # one that rejects: the address ceiling is a flood shield and must see
        # every request to be one.
        ip_ok, ip_retry = self._allow(f"ip:{client}", self.ip_limit)
        if serial is not None:
            dev_ok, dev_retry = self._allow(f"dev:{serial}", self.limit)
        else:
            dev_ok, dev_retry = True, 0

        if not ip_ok or not dev_ok:
            scope = "address" if not ip_ok else "device"
            limit = self.ip_limit if not ip_ok else self.limit
            retry_after = ip_retry if not ip_ok else dev_retry
            detail = f"Rate limit exceeded: {limit} per minute per {scope}"
            self._record(request, client, serial, detail)
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too many requests",
                    "detail": detail,
                    "status_code": 429,
                },
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)

    @staticmethod
    def _record(request, client, serial, detail) -> None:
        """Persist a throttled check-in. Never raises, never blocks the 429.

        Rate limiting was the largest single class of rejected check-in and
        the only one absent from ingest_failures entirely, so the view that
        exists to answer "installed but never appeared" could not see the
        answer. Only ingest POSTs are recorded -- dashboard traffic throttling
        is not a device problem and would bury the devices.
        """
        try:
            from dependencies import (
                _is_ingest_request,
                extract_ingest_identity_headers,
                record_ingest_failure,
            )

            if not _is_ingest_request(request):
                return
            record_ingest_failure(
                failure_type="throttle",
                reason="rate_limited",
                status_code=429,
                detail=detail,
                endpoint=request.url.path,
                client_ip=client,
                user_agent=request.headers.get("user-agent"),
                identity=extract_ingest_identity_headers(request),
            )
        except Exception:
            # Recording is diagnostic; a device must never be held up by it.
            pass
