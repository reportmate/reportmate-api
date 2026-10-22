"""The dashboard insight cards: one endpoint per card, and all of them at once.

    GET /api/v1/dashboard/insights/{card}?platform=&includeArchived=
    GET /api/v1/dashboard/insights/appUsage?platform=&usages=&catalogs=&days=
    GET /api/v1/dashboard/insights?platform=&includeArchived=

Every card is cached on its own, per scope, so a client can request the cards
in parallel and paint each as it arrives, and the combined document is
assembled from the same per-card cache.

In steady state no request waits on SQL. A background refresher recomputes
every card for all, macOS and Windows every few minutes, one card at a time,
so at most one card query runs for it at once. Requests are answered from the
cache. A value past its TTL is still served while a single background refresh
replaces it. Only a scope nobody has asked for yet (a cold start, an
includeArchived view, an App Usage filter combination) computes on request,
and that is single-flight: concurrent callers share one computation.

Every body is stable for a given computation, so the ETag middleware answers
a poll that brings If-None-Match with 304 and no body.
"""

from __future__ import annotations

import asyncio
import os
import time as _time
from collections import OrderedDict
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from starlette.concurrency import run_in_threadpool

import dashboard_insights
from dependencies import logger, verify_authentication

router = APIRouter(tags=["statistics"])

CACHE_TTL_SECONDS = int(os.getenv("INSIGHTS_CACHE_TTL_SECONDS", "300"))
#: A card that failed is retried sooner than a clean one.
ERROR_TTL_SECONDS = int(os.getenv("INSIGHTS_ERROR_TTL_SECONDS", "60"))
#: The refresher starts a pass this often; it finishes well inside the TTL.
REFRESH_INTERVAL_SECONDS = int(os.getenv("INSIGHTS_REFRESH_INTERVAL_SECONDS", "240"))
#: Pause between two cards of a refresh pass, so the pass is a trickle.
REFRESH_STAGGER_SECONDS = float(os.getenv("INSIGHTS_REFRESH_STAGGER_SECONDS", "1"))
BACKGROUND_REFRESH = os.getenv(
    "INSIGHTS_BACKGROUND_REFRESH", os.getenv("INSIGHTS_WARM_ON_STARTUP", "true")
).lower() in ("true", "1", "yes")
WARM_DELAY_SECONDS = float(os.getenv("INSIGHTS_WARM_DELAY_SECONDS", "15"))
MAX_ENTRIES = int(os.getenv("INSIGHTS_CACHE_MAX_ENTRIES", "256"))

APP_USAGE = "appUsage"
TOOL_DEVICES = "managementToolErrors/devices"
CARDS = tuple(dashboard_insights.CARD_KEYS) + (APP_USAGE,)
REFRESH_PLATFORMS = ("all", "macOS", "Windows")

CacheKey = Tuple[Any, ...]

_entries: "OrderedDict[CacheKey, Tuple[Dict[str, Any], float]]" = OrderedDict()
_inflight: Dict[CacheKey, asyncio.Task] = {}
_refresher: Optional[asyncio.Task] = None
_on_demand: Optional[asyncio.Semaphore] = None


def _ttl_for(result: Dict[str, Any]) -> int:
    return ERROR_TTL_SECONDS if "error" in result else CACHE_TTL_SECONDS


def _store(key: CacheKey, result: Dict[str, Any]) -> None:
    _entries[key] = (result, _time.monotonic())
    _entries.move_to_end(key)
    while len(_entries) > MAX_ENTRIES:
        _entries.popitem(last=False)


def _semaphore() -> asyncio.Semaphore:
    """Bounds on-demand computations, so a cold combined request does not
    take more pooled connections than the computation would on its own."""
    global _on_demand
    loop = asyncio.get_running_loop()
    if _on_demand is None or getattr(_on_demand, "_rm_loop", None) is not loop:
        _on_demand = asyncio.Semaphore(dashboard_insights.CONCURRENCY)
        _on_demand._rm_loop = loop  # type: ignore[attr-defined]
    return _on_demand


def _computation(key: CacheKey) -> Callable[[], Dict[str, Any]]:
    if key[0] == TOOL_DEVICES:
        _, tool, level, hours, platform = key
        return lambda: dashboard_insights.compute_tool_devices(tool, level, hours, platform)
    if key[0] == APP_USAGE:
        _, platform, usages, catalogs, days = key
        return lambda: dashboard_insights.compute_app_usage(
            platform, usages, catalogs, days
        )
    card, platform, include_archived = key
    return lambda: dashboard_insights.compute_card(card, platform, include_archived)


async def _compute(key: CacheKey) -> Dict[str, Any]:
    async with _semaphore():
        result = await run_in_threadpool(_computation(key))
    _store(key, result)
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


async def get_cached(key: CacheKey) -> Tuple[Dict[str, Any], str, float]:
    """(result, cache state, age in seconds). State is ``fresh``, ``stale``
    (past its TTL, served while one refresh runs) or ``miss`` (computed now)."""
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


# ── Background refresher ────────────────────────────────────────


def _default_keys() -> List[CacheKey]:
    keys: List[CacheKey] = []
    for platform in REFRESH_PLATFORMS:
        keys.extend((card, platform, False) for card in dashboard_insights.CARD_KEYS)
        keys.append((APP_USAGE, platform, (), (), dashboard_insights.USAGE_DAYS))
    return keys


async def refresh_pass() -> None:
    """Recompute every default card, one at a time."""
    t0 = _time.monotonic()
    for key in _default_keys():
        try:
            task = _inflight.get(key)
            if task is not None and not task.done():
                await asyncio.shield(task)
            else:
                result = await run_in_threadpool(_computation(key))
                _store(key, result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(f"[INSIGHTS] background refresh of {key} failed: {exc}")
        await asyncio.sleep(REFRESH_STAGGER_SECONDS)
    logger.info(f"[INSIGHTS] background refresh pass: {_time.monotonic() - t0:.1f}s")


async def _refresh_loop() -> None:
    await asyncio.sleep(WARM_DELAY_SECONDS)
    while True:
        started = _time.monotonic()
        try:
            await refresh_pass()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(f"[INSIGHTS] background refresh pass failed: {exc}")
        await asyncio.sleep(
            max(1.0, REFRESH_INTERVAL_SECONDS - (_time.monotonic() - started))
        )


def start_warmup() -> None:
    """Start the background refresher. Never blocks startup."""
    global _refresher
    if BACKGROUND_REFRESH and _refresher is None:
        _refresher = asyncio.get_running_loop().create_task(_refresh_loop())


def stop_warmup() -> None:
    global _refresher
    if _refresher is not None and not _refresher.done():
        _refresher.cancel()
    _refresher = None


# ── Endpoints ───────────────────────────────────────────────────


def _platform(value: str) -> str:
    normalized = dashboard_insights.normalize_platform(value)
    if normalized is None:
        raise HTTPException(
            status_code=422, detail="platform must be all, macOS or Windows"
        )
    return normalized


def _list(value: Optional[str]) -> Tuple[str, ...]:
    """A comma-separated filter as a sorted, de-duplicated key part."""
    seen = {v.strip().lower(): v.strip() for v in (value or "").split(",") if v.strip()}
    return tuple(seen[k] for k in sorted(seen))


def _headers(response: Response, state: str, age: float) -> None:
    response.headers["X-Insights-Cache"] = state
    response.headers["Age"] = str(int(age))


def _envelope(
    card: str, platform: str, include_archived: bool, data: Dict[str, Any]
) -> Dict[str, Any]:
    return {
        "card": card,
        "platform": platform,
        "includeArchived": include_archived,
        "generatedAt": data.get("generatedAt"),
        "data": data,
    }


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
    Every dashboard insight card in one document, assembled from the per-card
    caches (see GET /dashboard/insights/{card}).

    Returns ``{generatedAt, platform, includeArchived, cards}``. ``cards`` holds
    installHealth, rebootDebt, protectionGaps, managementToolErrors, storage,
    checkinGaps, osCurrency, softwareRisk, expiringCertificates, directoryJoin
    and connectivityProblems. Each card carries its own ``generatedAt``, and a
    card that failed server-side is ``{"error": "..."}``. App Usage has its own
    endpoint because it takes its own filters.
    """
    scope = _platform(platform)
    results = await asyncio.gather(
        *(
            get_cached((card, scope, include_archived))
            for card in dashboard_insights.CARD_KEYS
        )
    )
    states = {state for _r, state, _a in results}
    state = "miss" if "miss" in states else "stale" if "stale" in states else "fresh"
    _headers(response, state, max(age for _r, _s, age in results))
    cards = {
        card: r for card, (r, _s, _a) in zip(dashboard_insights.CARD_KEYS, results)
    }
    return {
        "generatedAt": max(
            (c.get("generatedAt") or "" for c in cards.values()), default=None
        ),
        "platform": scope,
        "includeArchived": include_archived,
        "cards": cards,
    }


@router.get(
    "/dashboard/insights/appUsage",
    dependencies=[Depends(verify_authentication)],
    tags=["statistics"],
)
@router.get(
    "/dashboard/insights/app-usage",
    dependencies=[Depends(verify_authentication)],
    tags=["statistics"],
    include_in_schema=False,
)
async def get_app_usage_insight(
    response: Response,
    platform: str = Query(default="all", description="all, macOS or Windows"),
    usages: Optional[str] = Query(
        default=None, description="Comma-separated inventory usages"
    ),
    catalogs: Optional[str] = Query(
        default=None, description="Comma-separated inventory catalogs"
    ),
    days: int = Query(default=30, ge=1, le=365),
):
    """
    The App Usage card: the ten most-used apps by hours in the window, within
    the usage and catalog filters, and the usage and catalog values available
    to filter by. Each app link carries the filters. Cached per combination.
    """
    scope = _platform(platform)
    key = (APP_USAGE, scope, _list(usages), _list(catalogs), days)
    result, state, age = await get_cached(key)
    _headers(response, state, age)
    return _envelope(APP_USAGE, scope, False, result)


@router.get(
    "/dashboard/insights/managementToolErrors/devices",
    dependencies=[Depends(verify_authentication)],
    tags=["statistics"],
)
async def get_tool_error_devices(
    response: Response,
    tool: str = Query(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$",
                      description="Log root key, as in a Management Tools Errors link (installs, bootstrap, mdm, ...)"),
    level: str = Query(default="error", pattern="^(error|warning)$"),
    hours: int = Query(default=24, ge=1, le=168),
    platform: str = Query(default="all", description="all, macOS or Windows"),
):
    """
    The devices behind a Management Tools Errors row: those whose log for
    ``tool`` has ``level`` lines in the last ``hours``, most lines first.

    Returns ``{tool, level, hours, platform, generatedAt, devices: [{serialNumber,
    deviceName, platform, count, lastAt, link}]}``. ``lastAt`` is the start of
    the latest UTC hour with such a line, and ``link`` opens the device log
    viewer on that tool and level. Computed from the levelSummary ingest
    stores on each log root and cached like the cards.
    """
    scope = _platform(platform)
    result, state, age = await get_cached((TOOL_DEVICES, tool.lower(), level, hours, scope))
    _headers(response, state, age)
    return result


@router.get(
    "/dashboard/insights/{card}",
    dependencies=[Depends(verify_authentication)],
    tags=["statistics"],
)
async def get_dashboard_insight(
    card: str,
    response: Response,
    platform: str = Query(default="all", description="all, macOS or Windows"),
    include_archived: bool = Query(default=False, alias="includeArchived"),
):
    """
    One dashboard insight card: ``{card, platform, includeArchived,
    generatedAt, data}``. ``data`` is the card, the same object the combined
    endpoint returns under ``cards[card]``. ``X-Insights-Cache`` says whether
    it came from the cache (fresh, stale) or was computed for this call (miss).
    """
    if card not in dashboard_insights.CARD_KEYS:
        raise HTTPException(
            status_code=404, detail=f"Unknown card. Cards: {', '.join(CARDS)}"
        )
    scope = _platform(platform)
    result, state, age = await get_cached((card, scope, include_archived))
    _headers(response, state, age)
    return _envelope(card, scope, include_archived, result)
