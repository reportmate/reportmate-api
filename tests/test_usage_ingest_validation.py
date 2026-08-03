"""Bounds checks for dailyUsageHistory ingestion.

These lock in the sanitization contract for usage rows: negative or
non-numeric durations are rejected, malformed or implausible dates are
rejected (one bad date would otherwise abort the whole batch at INSERT
time), and the accumulate upsert caps active/foreground at 24h per
(device, date, app) — total_seconds is deliberately uncapped because
process-lifetime seconds for multi-process apps legitimately exceed 24h
in a real day.
"""

from datetime import datetime, timedelta, timezone

from routers.events import (
    USAGE_DAY_SECONDS_CAP,
    _usage_entry_date,
    _usage_entry_numbers,
)


def _entry(**over):
    base = {
        "date": "2026-08-03",
        "appName": "Safari",
        "launches": 2,
        "totalSeconds": 3600,
        "activeSeconds": 1800,
        "foregroundSeconds": 1200,
    }
    base.update(over)
    return base


def test_valid_entry_passes_through():
    assert _usage_entry_numbers(_entry()) == (2, 3600.0, 1800.0, 1200.0)


def test_missing_optional_fields_default_to_zero():
    entry = {"date": "2026-08-03", "appName": "Safari"}
    assert _usage_entry_numbers(entry) == (0, 0.0, 0.0, 0.0)


def test_null_fields_default_to_zero():
    assert _usage_entry_numbers(_entry(activeSeconds=None, launches=None)) == (
        0,
        3600.0,
        0.0,
        1200.0,
    )


def test_negative_duration_rejected():
    assert _usage_entry_numbers(_entry(foregroundSeconds=-1)) is None
    assert _usage_entry_numbers(_entry(totalSeconds=-0.5)) is None
    assert _usage_entry_numbers(_entry(launches=-3)) is None


def test_non_numeric_rejected():
    assert _usage_entry_numbers(_entry(totalSeconds="lots")) is None
    assert _usage_entry_numbers(_entry(activeSeconds={"nested": 1})) is None
    assert _usage_entry_numbers(_entry(launches=[1])) is None


def test_non_finite_rejected():
    assert _usage_entry_numbers(_entry(totalSeconds="Infinity")) is None
    assert _usage_entry_numbers(_entry(activeSeconds="NaN")) is None
    assert _usage_entry_numbers(_entry(foregroundSeconds=float("inf"))) is None


def test_falsy_garbage_coerces_to_zero():
    # Empty string/list/dict fall through the `or 0` default rather than
    # rejecting the row -- they carry no signal either way.
    assert _usage_entry_numbers(_entry(activeSeconds={}, launches="")) == (
        0,
        3600.0,
        0.0,
        1200.0,
    )


def test_oversized_values_are_not_rejected_here():
    # A >24h delta is not dropped in Python: the SQL LEAST() holds
    # active/foreground at the ceiling and RETURNING surfaces it, while an
    # oversized total is legitimate (multi-process apps).
    numbers = _usage_entry_numbers(_entry(totalSeconds=200000, activeSeconds=90000))
    assert numbers == (2, 200000.0, 90000.0, 1200.0)
    assert USAGE_DAY_SECONDS_CAP == 86400


def test_plain_date_accepted():
    assert _usage_entry_date({"date": "2026-08-03"}) == "2026-08-03"


def test_datetime_string_truncates_to_date():
    assert _usage_entry_date({"date": "2026-08-03T12:34:56Z"}) == "2026-08-03"


def test_malformed_dates_rejected():
    assert _usage_entry_date({"date": "garbage"}) is None
    assert _usage_entry_date({"date": "08/03/2026"}) is None
    assert _usage_entry_date({"date": ""}) is None
    assert _usage_entry_date({"date": None}) is None
    assert _usage_entry_date({}) is None


def test_implausible_dates_rejected():
    assert _usage_entry_date({"date": "2019-12-31"}) is None
    assert _usage_entry_date({"date": "2999-01-01"}) is None


def test_timezone_skew_tolerated_but_not_more():
    today = datetime.now(timezone.utc).date()
    tomorrow = (today + timedelta(days=1)).isoformat()
    far = (today + timedelta(days=3)).isoformat()
    assert _usage_entry_date({"date": tomorrow}) == tomorrow
    assert _usage_entry_date({"date": far}) is None
