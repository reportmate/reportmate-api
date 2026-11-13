"""LOG_LEVEL handling in dependencies: a bad value must never block import,
and the SDK loggers stay pinned to WARNING whatever LOG_LEVEL says."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

PROBE = (
    "import logging, dependencies;"
    "print(logging.getLevelName(logging.getLogger().level));"
    "print(logging.getLevelName(logging.getLogger('azure.core').level))"
)


def _import_with(level):
    env = dict(os.environ)
    env.pop("LOG_LEVEL", None)
    if level is not None:
        env["LOG_LEVEL"] = level
    result = subprocess.run(
        [sys.executable, "-c", PROBE],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.split()


@pytest.mark.parametrize(
    "level, expected",
    [
        (None, "INFO"),
        ("", "INFO"),
        ("  ", "INFO"),
        ("verbose", "INFO"),
        ("debug", "DEBUG"),
        ("WARNING", "WARNING"),
    ],
)
def test_log_level_resolves_and_never_crashes(level, expected):
    root, sdk = _import_with(level)
    assert root == expected
    assert sdk == "WARNING"
