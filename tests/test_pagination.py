"""Pagination header tests.

Covers the pagination helper's header/Link math directly, the wiring on
GET /api/v1/devices (fresh and cached paths) with a stubbed database, and
the CORS exposure of the new headers.
"""

from fastapi import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient
from starlette.requests import Request

from pagination import PAGINATION_HEADERS, add_pagination_headers


def make_request(query_string: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "server": ("testserver", 80),
            "root_path": "",
            "path": "/api/v1/devices",
            "query_string": query_string.encode(),
            "headers": [],
        }
    )


class TestAddPaginationHeaders:
    def test_middle_page_has_next_and_prev(self):
        response = Response()
        add_pagination_headers(
            response, make_request("limit=10&offset=20"), total=100, limit=10, offset=20
        )
        assert response.headers["X-Total-Count"] == "100"
        assert response.headers["X-Limit"] == "10"
        assert response.headers["X-Offset"] == "20"
        link = response.headers["Link"]
        assert (
            '<http://testserver/api/v1/devices?limit=10&offset=30>; rel="next"' in link
        )
        assert (
            '<http://testserver/api/v1/devices?limit=10&offset=10>; rel="prev"' in link
        )

    def test_first_page_has_no_prev(self):
        response = Response()
        add_pagination_headers(
            response, make_request("limit=10"), total=100, limit=10, offset=0
        )
        assert 'rel="next"' in response.headers["Link"]
        assert 'rel="prev"' not in response.headers["Link"]

    def test_last_page_has_no_next(self):
        response = Response()
        add_pagination_headers(
            response, make_request("limit=10&offset=90"), total=100, limit=10, offset=90
        )
        assert 'rel="next"' not in response.headers["Link"]
        assert 'rel="prev"' in response.headers["Link"]

    def test_single_page_has_no_link(self):
        response = Response()
        add_pagination_headers(
            response, make_request("limit=10"), total=5, limit=10, offset=0
        )
        assert "Link" not in response.headers
        assert response.headers["X-Total-Count"] == "5"

    def test_prev_offset_clamps_to_zero(self):
        response = Response()
        add_pagination_headers(
            response, make_request("limit=10&offset=5"), total=100, limit=10, offset=5
        )
        assert 'offset=0>; rel="prev"' in response.headers["Link"]

    def test_no_limit_emits_totals_only(self):
        response = Response()
        add_pagination_headers(
            response, make_request(""), total=42, limit=None, offset=0
        )
        assert response.headers["X-Total-Count"] == "42"
        assert response.headers["X-Offset"] == "0"
        assert "X-Limit" not in response.headers
        assert "Link" not in response.headers

    def test_link_preserves_other_query_params(self):
        response = Response()
        add_pagination_headers(
            response,
            make_request("includeArchived=true&limit=10&offset=10"),
            total=100,
            limit=10,
            offset=10,
        )
        assert "includeArchived=true" in response.headers["Link"]


class FakeCursor:
    def __init__(self, total: int):
        self._total = total

    def execute(self, query, params=None):
        pass

    def fetchone(self):
        return (self._total,)

    def fetchall(self):
        return []


class FakeConnection:
    def __init__(self, total: int):
        self._total = total

    def cursor(self):
        return FakeCursor(self._total)

    def close(self):
        pass


class TestDevicesEndpointHeaders:
    def _client(self, monkeypatch, total: int) -> TestClient:
        import routers.devices as devices_router

        monkeypatch.setattr(
            devices_router, "get_db_connection", lambda: FakeConnection(total)
        )
        from main import app

        return TestClient(app)

    def test_devices_list_carries_pagination_headers(self, monkeypatch):
        client = self._client(monkeypatch, total=7)
        r = client.get(
            "/api/v1/devices?limit=2&offset=2",
            headers={"X-Client-Passphrase": "test-passphrase"},
        )
        assert r.status_code == 200
        assert r.headers["X-Total-Count"] == "7"
        assert r.headers["X-Limit"] == "2"
        assert r.headers["X-Offset"] == "2"
        assert 'rel="next"' in r.headers["Link"]
        assert 'rel="prev"' in r.headers["Link"]

    def test_cached_response_still_carries_headers(self, monkeypatch):
        client = self._client(monkeypatch, total=9)
        url = "/api/v1/devices?limit=3&offset=3&includeArchived=true"
        auth = {"X-Client-Passphrase": "test-passphrase"}
        first = client.get(url, headers=auth)
        second = client.get(url, headers=auth)
        assert first.status_code == second.status_code == 200
        assert second.headers["X-Total-Count"] == first.headers["X-Total-Count"]
        assert second.headers["X-Offset"] == "3"
        assert 'rel="prev"' in second.headers["Link"]


def test_cors_exposes_pagination_headers():
    from main import app

    cors = next(m for m in app.user_middleware if m.cls is CORSMiddleware)
    exposed = cors.kwargs["expose_headers"]
    for header in PAGINATION_HEADERS:
        assert header in exposed
