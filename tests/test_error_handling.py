"""5xx responses must not leak internal detail to callers.

The real handler functions from main.py are mounted on a throwaway app so the
behaviour is exercised in isolation (without mutating main.app's route table).
"""

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException as StarletteHTTPException

from main import http_exception_handler, unhandled_exception_handler

SECRET = "postgres://user:s3cr3t@db:5432/reportmate"


def _client():
    app = FastAPI()
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    @app.get("/boom")
    def boom():
        raise RuntimeError(f"connection failed: {SECRET}")

    @app.get("/explicit-500")
    def explicit_500():
        raise HTTPException(status_code=500, detail=f"db error: {SECRET}")

    @app.get("/not-found")
    def not_found():
        raise HTTPException(status_code=404, detail="Device 0F33V9G2 not found")

    @app.get("/bad-request")
    def bad_request():
        raise HTTPException(status_code=400, detail="serialNumber is required")

    # raise_server_exceptions=False so the Exception handler produces a
    # response instead of the error propagating into the test.
    return TestClient(app, raise_server_exceptions=False)


def test_unhandled_exception_is_masked():
    resp = _client().get("/boom")
    assert resp.status_code == 500
    body = resp.json()
    assert SECRET not in str(body)
    assert "RuntimeError" not in str(body)
    assert body["error"] == "Internal server error"
    assert len(body["reference"]) == 12


def test_explicit_500_detail_is_masked():
    resp = _client().get("/explicit-500")
    assert resp.status_code == 500
    body = resp.json()
    assert SECRET not in str(body)
    assert "reference" in body
    assert body["detail"].endswith(body["reference"])


def test_404_detail_is_preserved():
    resp = _client().get("/not-found")
    assert resp.status_code == 404
    # Client-error detail is intended for the caller.
    assert "0F33V9G2" in resp.json()["detail"]
    assert "reference" not in resp.json()


def test_400_detail_is_preserved():
    resp = _client().get("/bad-request")
    assert resp.status_code == 400
    assert resp.json()["detail"] == "serialNumber is required"
