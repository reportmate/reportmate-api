"""Log configuration: the Azure SDK must not narrate every HTTP header.

`logging.basicConfig(level=logging.INFO)` sets the root logger, which switches
on azure.core's http_logging_policy. That policy prints the request URL, the
request method, one line per request header, the response status and one line
per response header -- for every SDK call, and every ingest broadcasts to Web
PubSub. It accounted for 1,596,439 lines in 2 days: 61% of this service's log
volume and the bulk of the Log Analytics bill, entirely envelope.
"""

import importlib
import logging


def _reload_dependencies():
    import dependencies

    return importlib.reload(dependencies)


def test_azure_sdk_http_logging_is_silenced_by_default(monkeypatch):
    monkeypatch.delenv("AZURE_SDK_LOG_LEVEL", raising=False)
    _reload_dependencies()

    policy = logging.getLogger("azure.core.pipeline.policies.http_logging_policy")
    assert policy.level == logging.WARNING
    assert logging.getLogger("azure").level == logging.WARNING


def test_azure_sdk_logging_can_be_raised_deliberately(monkeypatch):
    monkeypatch.setenv("AZURE_SDK_LOG_LEVEL", "DEBUG")
    _reload_dependencies()

    assert logging.getLogger("azure").level == logging.DEBUG

    monkeypatch.delenv("AZURE_SDK_LOG_LEVEL", raising=False)
    _reload_dependencies()


def test_app_log_level_defaults_to_info_and_honours_the_env(monkeypatch):
    """Asserted on the level the module resolves, not on the live root logger:
    pytest's logging plugin owns root's level during a run."""
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    deps = _reload_dependencies()
    assert deps._LOG_LEVEL_NUM == logging.INFO

    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    deps = _reload_dependencies()
    assert deps._LOG_LEVEL_NUM == logging.WARNING

    monkeypatch.setenv("LOG_LEVEL", "nonsense")
    deps = _reload_dependencies()
    assert deps._LOG_LEVEL_NUM == logging.INFO, "an unparseable level must fall back, not crash"

    monkeypatch.delenv("LOG_LEVEL", raising=False)
    _reload_dependencies()


def test_per_request_ingest_lines_are_debug():
    """These fire on every check-in -- roughly 50,000 a day fleet-wide. At INFO
    they were the largest application-side contributor to log volume."""
    import inspect

    from routers import events

    source = inspect.getsource(events._process_submission)
    for phrase in (
        "Collection type:",
        "Skipped system event creation",
        "[SUCCESS] Successfully processed device",
        "Processing unified payload for device",
    ):
        line = next(l for l in source.splitlines() if phrase in l)
        assert "logger.debug(" in line, f"{phrase!r} is not at DEBUG: {line.strip()}"
