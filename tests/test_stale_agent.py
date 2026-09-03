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
    assert agent_last_run({"sessions": sessions}) == NOW - timedelta(days=2)


def test_last_run_falls_back_to_start_time():
    """A session cut short mid-run has no end_time but still proves it ran."""
    sessions = [{"start_time": iso(NOW - timedelta(hours=3))}]
    assert agent_last_run({"sessions": sessions}) == NOW - timedelta(hours=3)


def test_last_run_handles_missing_and_malformed():
    assert agent_last_run(None) is None
    assert agent_last_run({"sessions": []}) is None
    assert agent_last_run({"sessions": [{"end_time": "not a timestamp"}]}) is None
    assert agent_last_run({"sessions": ["not a dict"]}) is None


def test_naive_timestamp_does_not_raise():
    """Client timestamps are not reliably tz-aware; comparison must still work."""
    sessions = [{"end_time": "2026-09-01T12:00:00"}]
    last_run = agent_last_run({"sessions": sessions})
    assert last_run is not None
    assert agent_stale_days(last_run, NOW) == 1.0


def test_offset_timestamp_is_normalised():
    """The Windows client emits local time with an offset, not UTC.

    05:00-07:00 is 12:00Z, so against a 12:00Z check-in a day later this is
    exactly one day. Reading the wall-clock 05:00 and ignoring the offset
    would give 1.29 days instead.
    """
    sessions = [{"end_time": "2026-09-01T05:00:00-07:00"}]
    assert agent_stale_days(agent_last_run({"sessions": sessions}), NOW) == 1.0


def test_dead_agent_on_a_reporting_device_is_stale():
    """The real shape: checking in today, last ran seven weeks ago."""
    sessions = [{"end_time": iso(NOW - timedelta(days=48))}]
    stale = agent_stale_days(agent_last_run({"sessions": sessions}), NOW)
    assert stale == 48.0
    assert stale >= STALE_AGENT_THRESHOLD_DAYS


def test_healthy_hourly_agent_is_not_stale():
    sessions = [{"end_time": iso(NOW - timedelta(minutes=20))}]
    stale = agent_stale_days(agent_last_run({"sessions": sessions}), NOW)
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
    stale = agent_stale_days(agent_last_run({"sessions": sessions}), last_seen)
    assert stale < STALE_AGENT_THRESHOLD_DAYS


def test_no_session_history_is_not_reported_stale():
    """Absence of evidence must not become evidence of a dead agent."""
    assert agent_stale_days(agent_last_run({"sessions": []}), NOW) is None
    assert agent_stale_days(None, NOW) is None


def test_missing_last_seen_is_not_stale():
    assert agent_stale_days(NOW, None) is None


def test_run_recorded_after_last_checkin_clamps_to_zero():
    """Clock drift between the two timestamps must not produce a negative age."""
    sessions = [{"end_time": iso(NOW + timedelta(hours=2))}]
    assert agent_stale_days(agent_last_run({"sessions": sessions}), NOW) == 0.0


# --- the second agent shape -------------------------------------------------
# Munki has no sessions[] at all: it reports a single startTime/endTime on the
# module itself. Reading only the sessions shape returns None for every macOS
# device, which is parity in code and a silent no-op in practice -- the exact
# failure this whole signal exists to catch, reproduced in the detector.


def test_module_level_timestamps_are_used_when_there_are_no_sessions():
    agent = {"startTime": iso(NOW - timedelta(days=9)),
             "endTime": iso(NOW - timedelta(days=9) + timedelta(seconds=50))}
    last_run = agent_last_run(agent)
    assert last_run is not None, "an agent without sessions[] must still report a run time"
    assert agent_stale_days(last_run, NOW) > STALE_AGENT_THRESHOLD_DAYS


def test_module_level_end_time_preferred_over_start_time():
    agent = {"startTime": iso(NOW - timedelta(days=3)),
             "endTime": iso(NOW - timedelta(days=2))}
    assert agent_last_run(agent) == NOW - timedelta(days=2)


def test_module_level_start_time_alone_still_counts():
    agent = {"startTime": iso(NOW - timedelta(hours=1))}
    assert agent_last_run(agent) == NOW - timedelta(hours=1)


def test_healthy_module_level_agent_is_not_stale():
    agent = {"endTime": iso(NOW - timedelta(minutes=30))}
    assert agent_stale_days(agent_last_run(agent), NOW) < STALE_AGENT_THRESHOLD_DAYS


def test_sessions_win_over_module_level_when_both_present():
    """Sessions are the finer-grained record, so they decide when available."""
    agent = {"sessions": [{"end_time": iso(NOW - timedelta(hours=2))}],
             "endTime": iso(NOW - timedelta(days=30))}
    assert agent_last_run(agent) == NOW - timedelta(hours=2)


def test_empty_sessions_list_falls_through_to_module_level():
    agent = {"sessions": [], "endTime": iso(NOW - timedelta(days=5))}
    assert agent_last_run(agent) == NOW - timedelta(days=5)


def test_agent_with_no_timestamps_anywhere_is_unknown():
    assert agent_last_run({"version": "1.0", "status": "Active"}) is None
    assert agent_last_run({}) is None


def test_snake_case_sessions_from_the_macos_agent():
    """The macOS agent's session reports use Cimian's schema, deliberately.

    Its Swift model encodes startTime/endTime with convertToSnakeCase, so the
    JSON keys are start_time/end_time -- the same spelling the Windows agent
    writes. One reader must work for both, and it must keep working while the
    macOS reporting client is mid-transition: devices not yet sending
    sessions[] fall back to the module's own timestamps, and devices that are
    sending them get the finer-grained reading with no change here.
    """
    agent = {
        "sessions": [{"start_time": iso(NOW - timedelta(days=4)),
                      "end_time": iso(NOW - timedelta(days=4) + timedelta(minutes=1))}],
        "endTime": iso(NOW - timedelta(days=90)),
    }
    last_run = agent_last_run(agent)
    assert last_run == NOW - timedelta(days=4) + timedelta(minutes=1)
    assert agent_stale_days(last_run, NOW) > STALE_AGENT_THRESHOLD_DAYS
