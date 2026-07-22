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


@pytest.fixture
def fake_pg8000(monkeypatch):
    """Drive the pool with fake connections so failover can be tested without a
    live database. Yields the list of physical connections the pool created."""
    created = []

    class _FakeCursor:
        def __init__(self, conn):
            self._c = conn

        def execute(self, sql, *args, **kwargs):
            # A "dropped" connection fails every query until a fresh physical
            # connection is made — the same shape as an Azure NAT idle-drop.
            if self._c.dead:
                raise OSError("cannot read from timed out object")
            self._c.last = sql

        def fetchone(self):
            return (1,)

        def close(self):
            pass

    class _FakeConn:
        def __init__(self):
            self.dead = False
            self.autocommit = False
            self._usock = None  # keepalive helper no-ops on this
            self.last = None

        def cursor(self):
            return _FakeCursor(self)

        def close(self):
            pass

        def commit(self):
            pass

        def rollback(self):
            if self.dead:
                raise OSError("cannot read from timed out object")

    def _connect(**kwargs):
        conn = _FakeConn()
        created.append(conn)
        return conn

    monkeypatch.setattr(dependencies.pg8000, "connect", _connect)
    monkeypatch.setenv("DB_SSL", "false")
    monkeypatch.setattr(dependencies, "DATABASE_URL", "postgresql://u:p@h:5432/db")
    monkeypatch.setattr(dependencies, "_DB_POOL_MIN", 1)
    monkeypatch.setattr(dependencies, "_DB_POOL_MAX", 3)
    dependencies.close_db_pool()
    yield created
    dependencies.close_db_pool()


def test_stale_pooled_connection_reconnects_transparently(fake_pg8000):
    # Regression for the recurring "database unavailable" outage: a pooled
    # connection whose TCP flow was silently dropped (NAT idle timeout) must be
    # transparently reconnected on borrow rather than surfacing the raw
    # "cannot read from timed out object" OSError. The guard is OSError being in
    # the pool's `failures` set; `ping=1` alone does not help because pg8000 has
    # no ping() for DBUtils to call.
    created = fake_pg8000
    conn = dependencies.get_db_connection()
    created[0].dead = True  # simulate the idle-dropped socket

    cur = conn.cursor()
    cur.execute("SELECT 1")  # must reconnect + retry, not raise
    assert cur.fetchone()[0] == 1
    assert len(created) > 1, "pool did not create a fresh connection"
    assert created[-1].dead is False
    cur.close()
    conn.close()


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
