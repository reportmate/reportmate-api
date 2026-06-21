"""Pure helper functions in dependencies.py — no DB, fully deterministic."""

from dependencies import (
    build_os_summary,
    infer_platform,
    normalize_app_name,
    paginate,
)


def test_paginate_offset_and_limit():
    items = list(range(10))
    assert paginate(items, 3, 2) == [2, 3, 4]
    assert paginate(items, None, 5) == [5, 6, 7, 8, 9]
    assert paginate(items, 2, 0) == [0, 1]


def test_infer_platform():
    assert infer_platform("Microsoft Windows 11") == "Windows"
    assert infer_platform("macOS Sonoma") == "macOS"
    assert infer_platform("Darwin 23.0") == "macOS"
    assert infer_platform("Ubuntu Linux") == "Linux"
    assert infer_platform(None) is None
    assert infer_platform("Plan9") is None


def test_build_os_summary_extracts_build():
    s = build_os_summary("Windows 11", "10.0.22631.1")
    assert s["name"] == "Windows 11"
    assert s["version"] == "10.0.22631.1"
    assert s["build"] == "22631"


def test_build_os_summary_drops_empty():
    s = build_os_summary(None, None)
    assert "name" not in s
    assert "version" not in s


def test_normalize_app_name():
    assert normalize_app_name("") == ""
    assert normalize_app_name(None) == ""
    assert normalize_app_name("Microsoft Edge 120.0.1") == "Microsoft Edge"
    assert normalize_app_name("Google Chrome") == "Google Chrome"
    assert normalize_app_name("Firefox") == "Mozilla Firefox"
    assert normalize_app_name("Slack (x64)") == "Slack"
