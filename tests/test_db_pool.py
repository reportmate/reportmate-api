"""Connection-pool tests.

The URL-parsing tests always run. The pool behaviour tests need a real
Postgres and run only when TEST_DATABASE_URL is set (the CI/local integration
path); otherwise they skip.
"""

import os

import pytest

import dependencies


class TestParseDatabaseUrl:
    def test_postgresql_scheme_with_port(self):
        k = dependencies._parse_database_url(
            "postgresql://u:p@db.example.com:5433/mydb"
        )
        assert (k["host"], k["port"], k["database"], k["user"], k["password"]) == (
            "db.example.com",
            5433,
            "mydb",
            "u",
            "p",
        )

    def test_postgres_scheme_defaults_port(self):
        k = dependencies._parse_database_url("postgres://u:p@db.example.com/mydb")
        assert k["port"] == 5432

    def test_query_string_is_ignored(self):
        k = dependencies._parse_database_url(
            "postgresql://u:p@h:5432/mydb?sslmode=require"
        )
        assert k["database"] == "mydb"

    def test_bad_scheme_raises(self):
        with pytest.raises(ValueError):
            dependencies._parse_database_url("mysql://u:p@h/db")

    def test_ssl_toggle(self, monkeypatch):
        monkeypatch.setenv("DB_SSL", "false")
        k = dependencies._parse_database_url("postgresql://u:p@h/db")
        assert k["ssl_context"] is None
        monkeypatch.setenv("DB_SSL", "true")
        k = dependencies._parse_database_url("postgresql://u:p@h/db")
        assert k["ssl_context"] is True


_TEST_DB = os.getenv("TEST_DATABASE_URL")
integration = pytest.mark.skipif(
    not _TEST_DB, reason="TEST_DATABASE_URL not set; skipping live-DB pool tests"
)


@pytest.fixture
def pooled(monkeypatch):
    """Point dependencies at the test DB and give each test a fresh pool."""
    monkeypatch.setenv("DB_SSL", "false")
    monkeypatch.setattr(dependencies, "DATABASE_URL", _TEST_DB)
    monkeypatch.setattr(dependencies, "_DB_POOL_MIN", 1)
    monkeypatch.setattr(dependencies, "_DB_POOL_MAX", 3)
    dependencies.close_db_pool()
    yield dependencies
    dependencies.close_db_pool()


@integration
def test_borrow_query_and_return(pooled):
    conn = pooled.get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1")
    assert cur.fetchone()[0] == 1
    cur.close()
    conn.close()  # returns to pool


@integration
def test_statement_timeout_is_applied(pooled):
    conn = pooled.get_db_connection()
    cur = conn.cursor()
    cur.execute("SHOW statement_timeout")
    assert cur.fetchone()[0] == "2min"
    cur.close()
    conn.close()


@integration
def test_connection_is_reused_after_close(pooled):
    # With max=3 and serial borrow/return, the same physical connection should
    # come back — proving close() returns to the pool rather than tearing down.
    seen = set()
    for _ in range(5):
        conn = pooled.get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT pg_backend_pid()")
        seen.add(cur.fetchone()[0])
        cur.close()
        conn.close()
    assert len(seen) == 1


@integration
def test_open_transaction_is_reset_on_return(pooled):
    # A borrower that leaves a transaction open (reset=True) must not leak that
    # state to the next borrower.
    conn = pooled.get_db_connection()
    cur = conn.cursor()
    cur.execute("CREATE TEMP TABLE t_reset (x int)")  # opens a transaction
    cur.close()
    conn.close()  # PooledDB rolls back on return

    conn2 = pooled.get_db_connection()
    cur2 = conn2.cursor()
    # The temp table from the rolled-back transaction must be gone.
    cur2.execute("SELECT to_regclass('t_reset')")
    assert cur2.fetchone()[0] is None
    cur2.close()
    conn2.close()
