"""GET /api/v1/dashboard/insights: the dashboard insight cards in one cached call.

The computation (dashboard_insights.compute_insights) is a dozen aggregate
queries. It is cached in process per (platform, includeArchived) for five
minutes, and a refresh is single-flight: however many dashboards ask at once,
one computation runs and they all receive its result. Once a value exists it
is served immediately even when it has expired, while one background refresh
replaces it, so after the first computation no request waits on the database.
"""

from __future__ import annotations

import asyncio
import os
import time as _time
from typing import Any, Dict, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from starlette.concurrency import run_in_threadpool

import dashboard_insights
from dependencies import logger, verify_authentication

router = APIRouter(tags=["statistics"])

CACHE_TTL_SECONDS = int(os.getenv("INSIGHTS_CACHE_TTL_SECONDS", "300"))
#: A result with a failed card is retried sooner than a clean one.
ERROR_TTL_SECONDS = int(os.getenv("INSIGHTS_ERROR_TTL_SECONDS", "60"))
WARM_ON_STARTUP = os.getenv("INSIGHTS_WARM_ON_STARTUP", "true").lower() in (
    "true",
    "1",
    "yes",
)
WARM_DELAY_SECONDS = float(os.getenv("INSIGHTS_WARM_DELAY_SECONDS", "15"))

CacheKey = Tuple[str, bool]

_entries: Dict[CacheKey, Tuple[Dict[str, Any], float]] = {}
_inflight: Dict[CacheKey, asyncio.Task] = {}
_warm_task: Optional[asyncio.Task] = None


def _ttl_for(result: Dict[str, Any]) -> int:
    cards = result.get("cards") or {}
    return (
        ERROR_TTL_SECONDS
        if any("error" in c for c in cards.values())
        else CACHE_TTL_SECONDS
    )


async def _compute(key: CacheKey) -> Dict[str, Any]:
    result = await run_in_threadpool(dashboard_insights.compute_insights, *key)
    _entries[key] = (result, _time.monotonic())
    return result


def _finished(key: CacheKey, task: asyncio.Task) -> None:
    if _inflight.get(key) is task:
        _inflight.pop(key, None)
    if not task.cancelled() and task.exception() is not None:
        logger.error(f"[INSIGHTS] refresh {key} failed: {task.exception()}")


def _refresh(key: CacheKey) -> asyncio.Task:
    """The running computation for ``key``, started if there is none."""
    loop = asyncio.get_running_loop()
    task = _inflight.get(key)
    if task is None or task.done() or task.get_loop() is not loop:
        task = loop.create_task(_compute(key))
        _inflight[key] = task
        task.add_done_callback(lambda t, k=key: _finished(k, t))
    return task


async def get_insights(key: CacheKey) -> Tuple[Dict[str, Any], str, float]:
    """(result, cache state, age in seconds). State is ``fresh``, ``stale``
    (expired, served while a refresh runs) or ``miss`` (computed for this call)."""
    entry = _entries.get(key)
    if entry is not None:
        result, stored_at = entry
        age = _time.monotonic() - stored_at
        if age < _ttl_for(result):
            return result, "fresh", age
        _refresh(key)
        return result, "stale", age
    # shield: a caller that disconnects must not cancel the computation the
    # other waiting callers share.
    result = await asyncio.shield(_refresh(key))
    return result, "miss", 0.0


def reset_cache() -> None:
    """Drop every cached value and forget running refreshes (tests)."""
    _entries.clear()
    _inflight.clear()


async def _warm() -> None:
    try:
        await asyncio.sleep(WARM_DELAY_SECONDS)
        await _refresh(("all", False))
        logger.info("[INSIGHTS] warmed the platform=all cache")
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning(f"[INSIGHTS] warm-up failed: {exc}")


def start_warmup() -> None:
    """Fill the default entry in the background after startup. Never blocks it."""
    global _warm_task
    if WARM_ON_STARTUP and _warm_task is None:
        _warm_task = asyncio.get_running_loop().create_task(_warm())


def stop_warmup() -> None:
    global _warm_task
    if _warm_task is not None and not _warm_task.done():
        _warm_task.cancel()
    _warm_task = None


@router.get(
    "/dashboard/insights",
    dependencies=[Depends(verify_authentication)],
    tags=["statistics"],
)
async def get_dashboard_insights(
    response: Response,
    platform: str = Query(default="all", description="all, macOS or Windows"),
    include_archived: bool = Query(default=False, alias="includeArchived"),
):
    """
    The twelve dashboard insight cards in one call.

    Each card answers one question (devices up 30+ days, devices without
    disk encryption, managed items failing on the most devices, ...) with
    counts and short top-N lists only, never device rows. Every item carries
    ``link: {path, params}``, the report and filter it opens in the apps.

    Computed with aggregate SQL and cached per (platform, includeArchived)
    for five minutes. An expired value is served while one background
    refresh replaces it; ``X-Insights-Cache`` says which (fresh, stale,
    miss) and ``Age`` how old it is. A card that failed server-side is
    ``{"error": "..."}`` and the others still return.

    Returns ``{generatedAt, platform, includeArchived, computeSeconds,
    cards: {rebootDebt, protectionGaps, unmanagedDevices, hardwareAtRisk,
    installHealth, checkinGaps, osCurrency, softwareRisk,
    expiringCertificates, localAdminExposure, unusedSoftware,
    connectivityProblems}}``.
    """
    normalized = dashboard_insights.normalize_platform(platform)
    if normalized is None:
        raise HTTPException(
            status_code=422, detail="platform must be all, macOS or Windows"
        )

    result, state, age = await get_insights((normalized, include_archived))
    response.headers["X-Insights-Cache"] = state
    response.headers["Age"] = str(int(age))
    return result
