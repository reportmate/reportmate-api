"""Conditional GET support.

Weak ETags computed from the serialized body of successful API GET responses.
A matching ``If-None-Match`` short-circuits to an empty 304, so pollers (the
BFF, dashboards, integrations) stop re-downloading multi-megabyte fleet
payloads that have not changed. This saves transfer, not database work — the
handler still runs; the win is on the wire.
"""

import hashlib

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

_STRIPPED_ON_304 = {"content-length", "content-type"}


class ETagMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if request.method != "GET" or response.status_code != 200:
            return response
        if not request.url.path.startswith("/api/v1/"):
            return response

        body = b""
        async for chunk in response.body_iterator:
            body += chunk

        etag = f'W/"{hashlib.sha256(body).hexdigest()[:32]}"'
        headers = dict(response.headers)
        headers["ETag"] = etag

        if request.headers.get("If-None-Match") == etag:
            return Response(
                status_code=304,
                headers={
                    k: v
                    for k, v in headers.items()
                    if k.lower() not in _STRIPPED_ON_304
                },
            )

        headers.pop("content-length", None)
        return Response(content=body, status_code=200, headers=headers)
