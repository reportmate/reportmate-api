"""Prometheus metrics.

A middleware records request counts and latencies, and a scrape endpoint
exposes them. Path labels use the matched *route template*
(e.g. ``/api/v1/device/{serial_number}``), never the raw path, so a fleet of
serial numbers can't explode label cardinality.
"""

import time

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

# A dedicated registry keeps the app's series isolated and easy to reason about.
REGISTRY = CollectorRegistry()

REQUESTS = Counter(
    "reportmate_http_requests_total",
    "Total HTTP requests.",
    ["method", "path", "status"],
    registry=REGISTRY,
)
LATENCY = Histogram(
    "reportmate_http_request_duration_seconds",
    "HTTP request latency in seconds.",
    ["method", "path"],
    registry=REGISTRY,
)
IN_PROGRESS = Gauge(
    "reportmate_http_requests_in_progress",
    "In-flight HTTP requests.",
    registry=REGISTRY,
)


def _route_template(request) -> str:
    """The matched route's path template, or 'unmatched' for 404s.

    Using the template (not request.url.path) bounds label cardinality.
    """
    route = request.scope.get("route")
    return getattr(route, "path", None) or "unmatched"


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Don't measure the scrape endpoint itself.
        if request.url.path.endswith("/metrics"):
            return await call_next(request)

        IN_PROGRESS.inc()
        start = time.perf_counter()
        status = "500"
        try:
            response = await call_next(request)
            status = str(response.status_code)
            return response
        finally:
            elapsed = time.perf_counter() - start
            path = _route_template(request)
            REQUESTS.labels(request.method, path, status).inc()
            LATENCY.labels(request.method, path).observe(elapsed)
            IN_PROGRESS.dec()


def render_latest() -> Response:
    return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)
