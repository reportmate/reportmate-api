"""The management module's logs section: tails are stripped from summaries and served per tool."""

from log_tails import find_log_root, strip_log_tails


def _management():
    return {
        "moduleId": "management",
        "mdm_enrollment": {"enrolled": True},
        "logs": {
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
        },
    }


def test_strip_removes_every_tail_and_keeps_the_rest():
    original = _management()
    stripped = strip_log_tails(original)
    assert all("tails" not in r for r in stripped["logs"]["roots"])
    assert stripped["logs"]["roots"][0]["errorCount"] == 1
    assert stripped["logs"]["platform"] == "macOS"
    assert stripped["mdm_enrollment"] == {"enrolled": True}
    # The stored payload is untouched; the tool endpoint reads it again for tails.
    assert "tails" in original["logs"]["roots"][0]


def test_strip_tolerates_management_without_logs_and_malformed_shapes():
    assert strip_log_tails(None) is None
    assert strip_log_tails({"mdm_enrollment": {}}) == {"mdm_enrollment": {}}
    assert strip_log_tails({"logs": "broken"}) == {"logs": "broken"}
    assert strip_log_tails({"logs": {"roots": [1, {"tool": "x", "tails": []}]}}) == {
        "logs": {"roots": [1, {"tool": "x"}]}
    }


def test_find_root_by_tool_is_case_insensitive_and_keeps_tails():
    root = find_log_root(_management(), "Reports")
    assert root is not None
    assert root["tails"][0]["lines"] == ["c"]
    assert find_log_root(_management(), "encryption") is None
    assert find_log_root({"mdm_enrollment": {}}, "installs") is None
    assert find_log_root(None, "installs") is None
