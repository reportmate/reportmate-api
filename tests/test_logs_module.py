"""The logs module: tails are stripped from summaries and served per tool."""

from log_tails import find_log_root, strip_log_tails


def _module():
    return {
        "moduleId": "logs",
        "platform": "macOS",
        "roots": [
            {
                "tool": "installs",
                "name": "Managed Installs",
                "path": "/Library/Managed Installs/logs",
                "errorCount": 1,
                "tails": [{"file": "2026-09-01/1315/run.log", "lines": ["a", "b"], "truncated": False}],
            },
            {
                "tool": "reports",
                "name": "Managed Reports",
                "path": "/Library/Managed Reports/logs",
                "tails": [{"file": "reportmate.log", "lines": ["c"], "truncated": True}],
            },
        ],
    }


def test_strip_removes_every_tail_and_keeps_the_rest():
    original = _module()
    stripped = strip_log_tails(original)
    assert all("tails" not in r for r in stripped["roots"])
    assert stripped["roots"][0]["errorCount"] == 1
    assert stripped["platform"] == "macOS"
    # The stored payload is untouched; the device endpoint reads it again for tails.
    assert "tails" in original["roots"][0]


def test_strip_tolerates_malformed_shapes():
    assert strip_log_tails(None) is None
    assert strip_log_tails({"roots": "broken"}) == {"roots": "broken"}
    assert strip_log_tails({"roots": [1, {"tool": "x", "tails": []}]}) == {
        "roots": [1, {"tool": "x"}]
    }


def test_find_root_by_tool_is_case_insensitive_and_keeps_tail():
    root = find_log_root(_module(), "Reports")
    assert root is not None
    assert root["tails"][0]["lines"] == ["c"]
    assert find_log_root(_module(), "encryption") is None
    assert find_log_root(None, "installs") is None
