"""Global request rate limiting.

slowapi's SlowAPIMiddleware cannot resolve route handlers under this FastAPI
version's _IncludedRouter routing structure, so the Limiter's declared
default_limits never applied to anything. This middleware enforces the global
default directly: fixed-window counting per client IP in process memory (per
replica), mirroring slowapi's in-memory storage semantics. Requests carrying
the valid internal secret bypass the default — the BFF funnels every dashboard
user through a handful of egress IPs and would otherwise starve real users.
Per-route slowapi decorator limits (e.g. POST /events) apply independently.
"""

import hmac
import threading
import time
from typing import Dict, Tuple

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

DEFAULT_LIMIT_PER_MINUTE = 120


class GlobalRateLimitMiddleware(BaseHTTPMiddleware):
    # Window state is class-level: the middleware instance lives inside the
    # app's built middleware stack where tests can't reach it, and one process
    # serves one app, so shared state is both the simplest and the correct
    # scope. reset() exists for tests.
    _lock = threading.Lock()
    _window_start = 0
    _counts: Dict[str, int] = {}

    def __init__(self, app, limit_per_minute: int = DEFAULT_LIMIT_PER_MINUTE):
        super().__init__(app)
        self.limit = limit_per_minute

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
        from dependencies import API_INTERNAL_SECRET

        presented = request.headers.get("X-Internal-Secret")
        if (
            presented
            and API_INTERNAL_SECRET
            and hmac.compare_digest(presented, API_INTERNAL_SECRET)
        ):
            return await call_next(request)

        client = request.client.host if request.client else "unknown"
        allowed, retry_after = self._allow(client, self.limit)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too many requests",
                    "detail": f"Rate limit exceeded: {self.limit} per minute",
                    "status_code": 429,
                },
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)
