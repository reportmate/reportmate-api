"""The ingest path must not run on the asyncio event loop.

`submit_events` is `async def` because reading the request body is genuinely
asynchronous, but everything after that -- JSON parsing of payloads averaging
418 KB, Pydantic validation, and a long run of synchronous pg8000 round trips
-- is blocking work. Running it inline blocked the event loop for the whole
request, which is what produced an 11.7s average response time, 4,241
ReplicaUnhealthy events in 3 days and a container pinned at max replicas while
CPU sat below 1%.

These tests lock in the shape of the fix rather than its performance: the
blocking half runs off the loop, and the liveness probe is answerable without
touching the threadpool at all.
"""

import asyncio
import inspect
import threading

from fastapi.testclient import TestClient

import dependencies
from main import app
from routers import events as events_router
from routers import health as health_router

AUTH = {"X-Client-Passphrase": "test-passphrase"}
PAYLOAD = {
    "metadata": {
        "deviceId": "11111111-2222-3333-4444-555555555555",
        "serialNumber": "TESTSERIAL0001",
        "platform": "Windows",
        "clientVersion": "2026.07.21",
        "collectionType": "Single",
        "enabledModules": ["inventory"],
    }
}


def test_liveness_is_answered_on_the_event_loop():
    """A plain `def` here would queue behind saturated worker threads --
    precisely the condition a liveness probe exists to survive."""
    assert inspect.iscoroutinefunction(health_router.liveness)


def test_readiness_and_health_stay_off_the_event_loop():
    """Both touch the database, so they belong in the threadpool where a
    blocking driver call cannot stall everything else."""
    assert not inspect.iscoroutinefunction(health_router.readiness)
    assert not inspect.iscoroutinefunction(health_router.health_check)


def test_broadcast_event_is_not_falsely_async():
    """The Web PubSub SDK client is synchronous; declaring the wrapper `async`
    only hid a blocking HTTP call from the reader."""
    assert not inspect.iscoroutinefunction(dependencies.broadcast_event)


def test_submission_processing_runs_off_the_event_loop(monkeypatch):
    """The blocking worker must execute on a threadpool thread, not the
    thread running the event loop."""
    seen = {}

    def fake_process(request, raw_body):
        seen["thread"] = threading.current_thread()
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            seen["on_loop"] = False
        else:
            seen["on_loop"] = True
        return {"success": True}

    monkeypatch.setattr(events_router, "_process_submission", fake_process)

    with TestClient(app) as client:
        response = client.post("/api/v1/events", json=PAYLOAD, headers=AUTH)

    assert response.status_code == 200
    assert seen["on_loop"] is False, "ingest ran on the event loop"
    assert seen["thread"] is not threading.main_thread()


def test_empty_body_is_rejected_by_the_worker(monkeypatch):
    """The empty-body guard moved into the threadpool half along with the rest
    of validation, because rejecting a check-in writes an ingest_failures row
    -- itself a blocking database call that has no business on the loop."""
    recorded = {}

    def fake_record(**kwargs):
        recorded.update(kwargs)

    monkeypatch.setattr(events_router, "record_ingest_failure", fake_record)

    with TestClient(app) as client:
        response = client.post("/api/v1/events", content=b"", headers=AUTH)

    assert response.status_code == 400
    assert recorded["reason"] == "empty_body"
