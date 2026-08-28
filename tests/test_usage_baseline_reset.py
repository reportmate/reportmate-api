"""
usage_history baseline reset.

usage_history accumulates client-sent window deltas, so a client-side counting
defect is written into the table permanently and cannot be recomputed from
anything the server holds. Correcting one means removing the affected rows,
and the guarantees that make that safe are what these pin:

  - a preview by default, so the destructive path cannot be reached by
    forgetting a flag;
  - archive before delete, in one transaction, so no row is removed without a
    surviving copy;
  - a refusal to commit if those two counts disagree.
"""

import io
import os
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import main
from dependencies import verify_authentication


@pytest.fixture
def client():
    # These routes sit behind verify_authentication; the behaviour under test
    # is the reset itself, and auth enforcement is covered by test_route_auth.
    main.app.dependency_overrides[verify_authentication] = lambda: None
    try:
        yield TestClient(main.app)
    finally:
        main.app.dependency_overrides.pop(verify_authentication, None)


class FakeCursor:
    """Records executed SQL and replays canned results in order."""

    def __init__(self, results, rowcounts=None):
        self._results = list(results)
        self._rowcounts = list(rowcounts or [])
        self.executed = []
        self.rowcount = 0

    def execute(self, sql, params=None):
        self.executed.append((" ".join(sql.split()), params))
        if self._rowcounts:
            self.rowcount = self._rowcounts.pop(0)

    def fetchone(self):
        return self._results.pop(0) if self._results else None

    def close(self):
        pass


class FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def _patch_db(cursor):
    conn = FakeConn(cursor)
    return conn, patch("routers.admin.get_db_connection", return_value=conn)


COUNTS = (1200, 300, 440, "2026-07-01", "2026-08-31")
KEPT = (50, "2026-09-01", "2026-09-01")


class TestPreviewIsTheDefault:
    def test_without_confirm_nothing_is_written(self, client):
        cursor = FakeCursor([COUNTS, KEPT])
        conn, p = _patch_db(cursor)
        with p:
            r = client.post("/api/v1/admin/usage-history/reset-baseline?before=2026-09-01")

        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "preview"
        assert body["executed"] is False
        assert body["wouldArchiveAndDelete"]["rows"] == 1200
        assert body["wouldRemain"]["rows"] == 50
        assert not conn.committed
        # The destructive statements must never have been reached.
        assert not any("INSERT INTO usage_history_archive" in s for s, _ in cursor.executed)
        assert not any(s.startswith("DELETE FROM usage_history") for s, _ in cursor.executed)

    def test_preview_reports_what_survives(self, client):
        cursor = FakeCursor([COUNTS, KEPT])
        _, p = _patch_db(cursor)
        with p:
            body = client.post(
                "/api/v1/admin/usage-history/reset-baseline?before=2026-09-01"
            ).json()

        # The resulting baseline is stated, not left to be inferred.
        assert body["wouldRemain"]["earliestDate"] == "2026-09-01"


class TestExecution:
    def test_confirm_archives_before_deleting(self, client):
        cursor = FakeCursor([COUNTS, KEPT], rowcounts=[0, 0, 1200, 1200])
        conn, p = _patch_db(cursor)
        with p, patch("routers.admin.invalidate_caches") as inval:
            r = client.post(
                "/api/v1/admin/usage-history/reset-baseline"
                "?before=2026-09-01&confirm=true&reason=pre-term"
            )

        assert r.status_code == 200
        body = r.json()
        assert body["executed"] is True
        assert body["archived"] == 1200
        assert body["deleted"] == 1200
        assert conn.committed

        statements = [s for s, _ in cursor.executed]
        insert_at = next(i for i, s in enumerate(statements) if "INSERT INTO usage_history_archive" in s)
        delete_at = next(i for i, s in enumerate(statements) if s.startswith("DELETE FROM usage_history WHERE"))
        # Order is the whole safety property: a copy must exist first.
        assert insert_at < delete_at

        # The reason is recorded on the archived batch.
        insert_params = cursor.executed[insert_at][1]
        assert "pre-term" in insert_params

        # Fleet usage responses are cached; stale ones would still show the
        # pre-reset numbers.
        inval.assert_called_once()

    def test_a_mismatch_rolls_back_rather_than_losing_rows(self, client):
        # Archive copied fewer rows than the delete would remove.
        cursor = FakeCursor([COUNTS, KEPT], rowcounts=[0, 0, 1199, 1200])
        conn, p = _patch_db(cursor)
        with p, patch("routers.admin.invalidate_caches") as inval:
            r = client.post(
                "/api/v1/admin/usage-history/reset-baseline?before=2026-09-01&confirm=true"
            )

        assert r.status_code == 500
        assert conn.rolled_back
        assert not conn.committed
        inval.assert_not_called()

    def test_nothing_to_do_is_not_an_error(self, client):
        empty = (0, 0, 0, None, None)
        cursor = FakeCursor([empty, KEPT])
        conn, p = _patch_db(cursor)
        with p:
            body = client.post(
                "/api/v1/admin/usage-history/reset-baseline?before=2020-01-01&confirm=true"
            ).json()

        assert body["executed"] is True
        assert body["archived"] == 0
        assert body["deleted"] == 0
        assert not any("INSERT INTO usage_history_archive" in s for s, _ in cursor.executed)


class TestInputValidation:
    @pytest.mark.parametrize("bad", ["2026-13-01", "01-09-2026", "september", "2026/09/01", ""])
    def test_a_malformed_cutoff_is_rejected(self, client, bad):
        cursor = FakeCursor([COUNTS, KEPT])
        _, p = _patch_db(cursor)
        with p:
            r = client.post(f"/api/v1/admin/usage-history/reset-baseline?before={bad}")
        assert r.status_code in (400, 422)

    def test_the_cutoff_is_required(self, client):
        r = client.post("/api/v1/admin/usage-history/reset-baseline")
        assert r.status_code == 422


class TestSeparateFromRoutineCleanup:
    def test_reset_is_its_own_route_and_cleanup_is_untouched(self, client):
        # The reset takes an explicit cutoff; the ageing-out endpoint keeps its
        # own contract (minimum one month retention) and is not repurposed.
        cursor = FakeCursor([COUNTS, KEPT])
        _, p = _patch_db(cursor)
        with p:
            assert client.post(
                "/api/v1/admin/usage-history/reset-baseline?before=2026-09-01"
            ).status_code == 200

        # A one-week retention is out of range for routine cleanup, which is
        # exactly why the reset needed its own endpoint.
        assert client.request(
            "DELETE", "/api/v1/admin/usage-history/cleanup?months=0"
        ).status_code == 422


class TestMigration:
    def test_archive_table_renders_offline(self):
        from alembic import command
        from alembic.config import Config

        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cfg = Config(os.path.join(here, "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(here, "alembic"))

        buf = io.StringIO()
        with redirect_stdout(buf):
            command.upgrade(cfg, "head", sql=True)
        sql = buf.getvalue()

        assert "usage_history_archive" in sql
        assert "idx_usage_history_archive_device_date" in sql
