"""Shared test setup.

The API module reads several settings from the environment at import time
into module-level globals, so deterministic test values must be set before
``dependencies``/``main`` are imported. conftest is imported by pytest ahead
of any test module, which makes this the right place for it.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Deterministic, non-secret values so import-time globals never pick up a
# developer's real configuration. Auth tests monkeypatch these directly.
os.environ.setdefault(
    "DATABASE_URL", "postgresql://reportmate:password@localhost:5432/reportmate"
)
os.environ["REPORTMATE_PASSPHRASE"] = "test-passphrase"
os.environ["API_INTERNAL_SECRET"] = "test-internal-secret"


import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Isolate the global rate-limit bucket between tests.

    TestClient requests all share one remote address, so without a reset the
    mounted default limit would leak 429s across unrelated tests.
    """
    from rate_limit import GlobalRateLimitMiddleware

    GlobalRateLimitMiddleware.reset()
