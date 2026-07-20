"""Alembic migration tests.

The offline-render test always runs (no database). The apply tests need a real
Postgres and run only when TEST_DATABASE_URL is set; otherwise they skip.
"""

import os

import pytest


def test_baseline_renders_offline():
    # `alembic upgrade --sql` renders the migration to SQL without a database,
    # which proves the revision imports and its DDL is syntactically emit-able.
    import io
    from contextlib import redirect_stdout

    from alembic import command
    from alembic.config import Config

    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg = Config(os.path.join(here, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(here, "alembic"))

    buf = io.StringIO()
    with redirect_stdout(buf):
        command.upgrade(cfg, "head", sql=True)
    sql = buf.getvalue()
    assert "usage_history" in sql
    assert "api_keys" in sql
    assert "idempotency_keys" in sql


_TEST_DB = os.getenv("TEST_DATABASE_URL")
integration = pytest.mark.skipif(
    not _TEST_DB, reason="TEST_DATABASE_URL not set; skipping live-DB migration tests"
)


@pytest.fixture
def migrated(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", _TEST_DB)
    monkeypatch.setenv("DB_SSL", "false")
    yield


@integration
def test_upgrade_creates_app_tables_and_stamps_version(migrated):
    import pg8000

    from migrations import run_migrations

    run_migrations()
    run_migrations()  # idempotent — must not raise

    # Connect and assert the expected objects exist.
    from urllib.parse import urlparse

    u = urlparse(_TEST_DB)
    conn = pg8000.connect(
        host=u.hostname,
        port=u.port or 5432,
        database=u.path.lstrip("/"),
        user=u.username,
        password=u.password,
    )
    cur = conn.cursor()
    cur.execute("SELECT version_num FROM alembic_version")
    assert cur.fetchone()[0] == "0001"
    cur.execute(
        "SELECT count(*) FROM information_schema.tables "
        "WHERE table_name IN ('usage_history','api_keys','api_key_audit',"
        "'app_settings','idempotency_keys')"
    )
    assert cur.fetchone()[0] == 5
    cur.close()
    conn.close()
