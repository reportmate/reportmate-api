"""Pagination header helpers.

Additive, GitHub-style pagination metadata carried in response headers so
list bodies stay unchanged: ``X-Total-Count``, ``X-Limit``, ``X-Offset``,
plus an RFC 5988 ``Link`` header with ``next``/``prev`` relations built
from the request URL.
"""

from typing import Optional

from fastapi import Request, Response

PAGINATION_HEADERS = ["Link", "X-Total-Count", "X-Limit", "X-Offset"]


def add_pagination_headers(
    response: Response,
    request: Request,
    *,
    total: int,
    limit: Optional[int],
    offset: int = 0,
) -> None:
    """Attach pagination headers for an offset/limit windowed list response.

    When no limit was requested the endpoint returned the full set, so only
    the totals are emitted — a ``Link`` relation would be meaningless.
    """
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Offset"] = str(offset)
    if limit is None:
        return
    response.headers["X-Limit"] = str(limit)

    relations = []
    if offset + limit < total:
        relations.append(("next", offset + limit))
    if offset > 0:
        relations.append(("prev", max(offset - limit, 0)))
    if relations:
        response.headers["Link"] = ", ".join(
            f'<{request.url.include_query_params(offset=target)}>; rel="{rel}"'
            for rel, target in relations
        )
