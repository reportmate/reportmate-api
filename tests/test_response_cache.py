"""Bounds on the in-process response cache.

The cache keys most endpoints on the request's whole query string, so its key
space is every filter combination, offset and search term any caller has ever
sent. Nothing evicted an entry that was written and never read again, and each
entry holds a full response payload -- tens of megabytes for the fleet lists.
The container walked from ~200 MB to its 4 GiB ceiling over a few hours and was
OOM-killed several times a day, taking the daily alert cards with it.
"""

import time

import pytest

import dependencies as deps


@pytest.fixture(autouse=True)
def _clean_cache():
    deps.invalidate_caches()
    yield
    deps.invalidate_caches()


def test_a_stored_response_is_returned():
    deps.cache_set("system", {"devices": 1}, ("a",))
    assert deps.cache_get("system", ("a",)) == {"devices": 1}


def test_an_entry_nobody_reads_again_does_not_outlive_its_ttl(monkeypatch):
    """The leak: eviction only ever happened on a read of that same key."""
    monkeypatch.setitem(deps._CACHE_TTL, "system", 0.05)
    deps.cache_set("system", {"big": "payload"}, ("never-read-again",))
    assert len(deps._CACHE) == 1

    time.sleep(0.06)
    deps.cache_set("system", {"big": "payload"}, ("some-other-key",))

    assert ("system", ("never-read-again",)) not in deps._CACHE
    assert len(deps._CACHE) == 1


def test_a_burst_of_distinct_keys_is_capped(monkeypatch):
    """A dashboard sweeping filters can outrun any TTL-based sweep."""
    monkeypatch.setattr(deps, "_CACHE_MAX_ENTRIES", 8)

    for i in range(50):
        deps.cache_set("installs_full", {"payload": i}, (f"filter-{i}",))

    assert len(deps._CACHE) == 8


def test_the_cap_evicts_the_oldest_first(monkeypatch):
    monkeypatch.setattr(deps, "_CACHE_MAX_ENTRIES", 3)

    for i in range(5):
        deps.cache_set("system", {"payload": i}, (f"k{i}",))

    assert deps.cache_get("system", ("k0",)) is None
    assert deps.cache_get("system", ("k4",)) == {"payload": 4}


def test_rewriting_a_key_keeps_it_fresh_rather_than_duplicating(monkeypatch):
    monkeypatch.setattr(deps, "_CACHE_MAX_ENTRIES", 3)

    deps.cache_set("system", {"payload": "first"}, ("k",))
    for i in range(2):
        deps.cache_set("system", {"payload": i}, (f"other{i}",))
    deps.cache_set("system", {"payload": "second"}, ("k",))
    deps.cache_set("system", {"payload": "new"}, ("newest",))

    assert deps.cache_get("system", ("k",)) == {"payload": "second"}
    assert len(deps._CACHE) == 3


def test_an_expired_entry_is_not_served():
    deps._CACHE[("system", ("stale",))] = ({"old": True}, time.monotonic() - 10_000)
    assert deps.cache_get("system", ("stale",)) is None
