from datetime import datetime, timezone

import pytest

from log_tails import classify_line, normalize_message, parse_levels, sql_pattern_for_levels
from routers.fleet import _shape_fleet_log_rows


CMTRACE_WARN = '<![LOG[Key not found]LOG]!><time="10:00:00.000" date="9-2-2026" component="IME" context="" type="2" thread="4" file="">'
CMTRACE_ERR = '<![LOG[Boom]LOG]!><time="10:00:00.000" date="9-2-2026" component="IME" context="" type="3" thread="4" file="">'
DAEMON_ERR = "2026-09-02 10:00:00:123 | IntuneMDM-Daemon | E | 12 | Enrollment | token refresh failed"


def test_classify_line_covers_every_shape():
    assert classify_line("[2026-09-02 10:00:00] ERROR  boom") == "error"
    assert classify_line("[2026-09-02 10:00:00]  WARN  careful") == "warning"
    assert classify_line("[2026-09-02 10:00:00] DEBUG  chatter") == "debug"
    assert classify_line("[2026-09-02 10:00:00]  INFO  fine") == "info"
    assert classify_line(CMTRACE_WARN) == "warning"
    assert classify_line(CMTRACE_ERR) == "error"
    assert classify_line(DAEMON_ERR) == "error"
    assert classify_line('{"level": "warning", "message": "x"}') == "warning"
    assert classify_line("plain text with no level") == "info"
    # the stamped level wins over words in the message
    assert classify_line("[2026-09-02 03:00:46]  INFO  CRITICAL PACKAGE: SbinInstaller (x64) - using aggressive retry strategy") == "info"
    assert classify_line("[2026-09-02 03:00:46] DEBUG  CRITICAL PACKAGE INSTALLED") == "debug"
    assert classify_line("[2026-09-02 03:00:46] FATAL  MSI Version value missing") == "error"


def test_parse_levels_defaults_aliases_and_rejects_unknown():
    assert parse_levels(None) == ["error", "warning"]
    assert parse_levels("") == ["error", "warning"]
    assert parse_levels("warn, INFO, error") == ["warning", "info", "error"]
    assert parse_levels("debug") == ["debug"]
    with pytest.raises(ValueError):
        parse_levels("error,verbose")


def test_sql_pattern_only_when_info_is_excluded():
    assert sql_pattern_for_levels(["error", "info"]) is None
    pattern = sql_pattern_for_levels(["error", "warning"])
    assert "FATAL" in pattern and "WRN" in pattern and 'type="3"' in pattern
    assert "DEBUG" not in pattern


def test_normalize_message_strips_envelopes_and_noise():
    a = normalize_message("[2026-09-02 10:00:01] ERROR  MSI installer failed with exit code 1603 (attempt 2/5)")
    b = normalize_message("[2026-09-03 08:12:44] ERROR  MSI installer failed with exit code 1618 (attempt 4/5)")
    assert a == b == "MSI installer failed with exit code <n> (attempt <n>/<n>)"
    assert normalize_message(CMTRACE_ERR) == "Boom"
    assert normalize_message(DAEMON_ERR) == "token refresh failed"
    assert "<guid>" in normalize_message("id 0fc77450-1111-2222-3333-444444444444 done")


def _rows():
    seen = datetime(2026, 9, 2, 22, 0, tzinfo=timezone.utc)
    root = {"name": "Managed Bootstrap", "path": "C:\\ProgramData\\ManagedBootstrap\\logs", "newestModified": "2026-09-02T21:00:00Z", "errorCount": 2, "warningCount": 1}
    return [
        ("WIN1", seen, "Lab PC", "Windows", root, "run.log", [
            "[2026-09-02 10:00:00]  INFO  starting",
            "[2026-09-02 10:00:01] ERROR  MSI installer failed with exit code 1603 (attempt 1/5)",
            "[2026-09-02 10:00:02]  WARN  retrying",
            "[2026-09-02 10:00:03] DEBUG  chatter",
        ]),
        ("WIN1", seen, "Lab PC", "Windows", root, "events.jsonl", ['{"level":"error","message":"MSI installer failed with exit code 1618 (attempt 2/5)"}']),
        ("MAC1", seen, "Lab Mac", "macOS", {**root, "path": "/Library/Managed Bootstrap/logs"}, "2026-09-01-090000.log", [
            "[2026-09-01 09:00:00] ERROR  MSI installer failed with exit code 7 (attempt 1/5)",
            "[2026-09-01 09:00:01]  INFO  done",
        ]),
    ]


def test_shape_enforces_levels_and_groups_per_device():
    shaped = _shape_fleet_log_rows(_rows(), ["error", "warning"], None, None, None, 200, True)
    assert shaped["devicesScanned"] == 2 and shaped["devicesMatched"] == 2
    assert shaped["lineTotals"] == {"error": 3, "warning": 1, "info": 0, "debug": 0}
    win = next(r for r in shaped["results"] if r["serialNumber"] == "WIN1")
    assert win["counts"] == {"error": 2, "warning": 1, "info": 0, "debug": 0}
    assert [l["file"] for l in win["lines"]] == ["run.log", "run.log", "events.jsonl"]
    assert win["root"]["path"].endswith("ManagedBootstrap\\logs")
    # the same fault on both devices and in both files is one pattern with a device count of 2
    top = shaped["patterns"][0]
    assert top["message"] == "MSI installer failed with exit code <n> (attempt <n>/<n>)"
    assert top["devices"] == 2 and top["lines"] == 3 and top["level"] == "error"
    # devices with more errors sort first
    assert [r["serialNumber"] for r in shaped["results"]] == ["WIN1", "MAC1"]


def test_shape_info_debug_platform_file_and_text_filters():
    only_debug = _shape_fleet_log_rows(_rows(), ["debug"], None, None, None, 200, False)
    assert only_debug["devicesMatched"] == 1 and only_debug["lineTotals"]["debug"] == 1
    assert only_debug["patterns"] is None
    info_mac = _shape_fleet_log_rows(_rows(), ["info"], None, None, "macos", 200, False)
    assert [r["serialNumber"] for r in info_mac["results"]] == ["MAC1"]
    assert info_mac["results"][0]["lines"][0]["line"].endswith("done")
    jsonl_only = _shape_fleet_log_rows(_rows(), ["error"], None, "events.jsonl", None, 200, False)
    assert jsonl_only["lineTotals"]["error"] == 1
    text = _shape_fleet_log_rows(_rows(), ["error", "warning", "info", "debug"], "RETRY", None, None, 200, False)
    assert text["lineTotals"] == {"error": 0, "warning": 1, "info": 0, "debug": 0}


def test_shape_caps_lines_per_device_and_reports_truncation():
    shaped = _shape_fleet_log_rows(_rows(), ["error", "warning", "info", "debug"], None, None, "windows", 2, False)
    win = shaped["results"][0]
    assert len(win["lines"]) == 2 and win["truncated"] is True
    assert win["counts"]["error"] == 2  # counts cover every matching line, not just the kept ones
    assert shaped["devicesTruncated"] == 1
