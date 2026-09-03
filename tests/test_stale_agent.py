"""A management agent that stopped running must be detectable.

The gap this guards: every install metric is per-item, and a device whose agent
has died keeps re-uploading the last report it produced. Those records froze on
the day the agent stopped -- overwhelmingly "installed" -- so the device carries
no errors and no warnings and reads as one of the healthiest in the fleet while
receiving no software updates at all. Driving the error and warning counts to
zero cannot surface it, because it never contributed to them.

The signal is the gap between a device still checking in and its agent's last
completed session. These exercise the endpoint's own functions so the test
cannot drift from the rule it is checking.
"""
from datetime import datetime, timedelta, timezone

from routers.fleet import (
    STALE_AGENT_THRESHOLD_DAYS,
    agent_last_run,
    agent_stale_days,
)

NOW = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)


def iso(dt):
    return dt.isoformat()


def test_last_run_uses_newest_session_not_first():
    """Ordering is the producer's convention, not a guarantee."""
    sessions = [
        {"end_time": iso(NOW - timedelta(days=10))},
        {"end_time": iso(NOW - timedelta(days=2))},
        {"end_time": iso(NOW - timedelta(days=40))},
    ]
    assert agent_last_run(sessions) == NOW - timedelta(days=2)


def test_last_run_falls_back_to_start_time():
    """A session cut short mid-run has no end_time but still proves it ran."""
    sessions = [{"start_time": iso(NOW - timedelta(hours=3))}]
    assert agent_last_run(sessions) == NOW - timedelta(hours=3)


def test_last_run_handles_missing_and_malformed():
    assert agent_last_run(None) is None
    assert agent_last_run([]) is None
    assert agent_last_run([{"end_time": "not a timestamp"}]) is None
    assert agent_last_run(["not a dict"]) is None


def test_naive_timestamp_does_not_raise():
    """Client timestamps are not reliably tz-aware; comparison must still work."""
    sessions = [{"end_time": "2026-09-01T12:00:00"}]
    last_run = agent_last_run(sessions)
    assert last_run is not None
    assert agent_stale_days(last_run, NOW) == 1.0


def test_offset_timestamp_is_normalised():
    """The Windows client emits local time with an offset, not UTC.

    05:00-07:00 is 12:00Z, so against a 12:00Z check-in a day later this is
    exactly one day. Reading the wall-clock 05:00 and ignoring the offset
    would give 1.29 days instead.
    """
    sessions = [{"end_time": "2026-09-01T05:00:00-07:00"}]
    assert agent_stale_days(agent_last_run(sessions), NOW) == 1.0


def test_dead_agent_on_a_reporting_device_is_stale():
    """The real shape: checking in today, last ran seven weeks ago."""
    sessions = [{"end_time": iso(NOW - timedelta(days=48))}]
    stale = agent_stale_days(agent_last_run(sessions), NOW)
    assert stale == 48.0
    assert stale >= STALE_AGENT_THRESHOLD_DAYS


def test_healthy_hourly_agent_is_not_stale():
    sessions = [{"end_time": iso(NOW - timedelta(minutes=20))}]
    stale = agent_stale_days(agent_last_run(sessions), NOW)
    assert stale < STALE_AGENT_THRESHOLD_DAYS


def test_powered_off_device_is_absent_not_stale():
    """Both timestamps old means the machine is off, which is not this defect.

    This is why staleness is measured against the device's own last check-in
    rather than wall-clock now: a laptop in a drawer for a month would
    otherwise be indistinguishable from an agent that died on a running
    machine, and only the second one needs fixing.
    """
    last_seen = NOW - timedelta(days=30)
    sessions = [{"end_time": iso(last_seen - timedelta(minutes=5))}]
    stale = agent_stale_days(agent_last_run(sessions), last_seen)
    assert stale < STALE_AGENT_THRESHOLD_DAYS


def test_no_session_history_is_not_reported_stale():
    """Absence of evidence must not become evidence of a dead agent."""
    assert agent_stale_days(agent_last_run([]), NOW) is None
    assert agent_stale_days(None, NOW) is None


def test_missing_last_seen_is_not_stale():
    assert agent_stale_days(NOW, None) is None


def test_run_recorded_after_last_checkin_clamps_to_zero():
    """Clock drift between the two timestamps must not produce a negative age."""
    sessions = [{"end_time": iso(NOW + timedelta(hours=2))}]
    assert agent_stale_days(agent_last_run(sessions), NOW) == 0.0
