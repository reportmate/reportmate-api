"""OIDC bearer authentication (provider-agnostic federated identity).

Exercised through a real FastAPI app + TestClient (like test_auth.py) so the
``Header(None)`` defaults resolve as they do in production. Tokens are signed
with a throwaway local RSA keypair and the JWKS lookup is monkeypatched, so
these tests never touch the network or a real IdP.
"""

from datetime import datetime, timedelta, timezone

import dependencies
import jwt
import oidc_auth
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from dependencies import verify_authentication

ISSUER = "https://login.microsoftonline.com/tenant-id/v2.0"
AUDIENCE = "api://reportmate"


@pytest.fixture(scope="module")
def rsa_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


@pytest.fixture
def make_token(rsa_keys):
    private_key, _ = rsa_keys

    def _make(
        *,
        iss=ISSUER,
        aud=AUDIENCE,
        roles=None,
        scp=None,
        exp_delta=3600,
        alg="RS256",
        signing_key=None,
        **extra,
    ):
        now = datetime.now(timezone.utc)
        payload = {
            "iss": iss,
            "aud": aud,
            "sub": "subject-123",
            "oid": "object-id-abc",
            "preferred_username": "rod@ecuad.ca",
            "iat": now,
            "exp": now + timedelta(seconds=exp_delta),
        }
        if roles is not None:
            payload["roles"] = roles
        if scp is not None:
            payload["scp"] = scp
        payload.update(extra)
        return jwt.encode(payload, signing_key or private_key, algorithm=alg)

    return _make


@pytest.fixture
def oidc_client(monkeypatch, rsa_keys):
    """FastAPI TestClient with OIDC enabled and the signing key stubbed.

    Routes cover each scope bucket so ``_enforce_scope`` is exercised:
    GET /read -> read, POST /ingest -> ingest, GET /admin/ping -> admin.
    """
    _, public_key = rsa_keys
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", False)
    monkeypatch.setattr(oidc_auth, "ENABLE_OIDC_AUTH", True)
    monkeypatch.setattr(oidc_auth, "OIDC_ISSUERS", (ISSUER,))
    monkeypatch.setattr(oidc_auth, "OIDC_AUDIENCES", (AUDIENCE,))
    monkeypatch.setattr(oidc_auth, "OIDC_ALGORITHMS", ("RS256",))
    monkeypatch.setattr(
        oidc_auth, "_signing_key_for_token", lambda token, issuer: public_key
    )

    app = FastAPI()

    @app.get("/read")
    def read(auth=Depends(verify_authentication)):
        return auth

    @app.post("/ingest")
    def ingest(auth=Depends(verify_authentication)):
        return auth

    @app.get("/admin/ping")
    def admin(auth=Depends(verify_authentication)):
        return auth

    return TestClient(app)


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_admin_token_can_read(oidc_client, make_token):
    resp = oidc_client.get(
        "/read", headers=_bearer(make_token(roles=["ReportMate.Admin"]))
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["method"] == "oidc"
    assert body["issuer"] == ISSUER
    assert body["principal"] == "object-id-abc"
    assert body["username"] == "rod@ecuad.ca"
    assert set(body["scopes"]) == {"read", "ingest", "admin"}


def test_read_token_can_read(oidc_client, make_token):
    resp = oidc_client.get(
        "/read", headers=_bearer(make_token(roles=["ReportMate.Read"]))
    )
    assert resp.status_code == 200
    assert resp.json()["scopes"] == ["read"]


def test_read_token_cannot_ingest(oidc_client, make_token):
    resp = oidc_client.post(
        "/ingest", headers=_bearer(make_token(roles=["ReportMate.Read"]))
    )
    assert resp.status_code == 403


def test_read_token_cannot_admin(oidc_client, make_token):
    resp = oidc_client.get(
        "/admin/ping", headers=_bearer(make_token(roles=["ReportMate.Read"]))
    )
    assert resp.status_code == 403


def test_ingest_token_can_post(oidc_client, make_token):
    resp = oidc_client.post(
        "/ingest", headers=_bearer(make_token(roles=["ReportMate.Ingest"]))
    )
    assert resp.status_code == 200
    assert resp.json()["scopes"] == ["ingest"]


def test_admin_token_can_admin(oidc_client, make_token):
    resp = oidc_client.get(
        "/admin/ping", headers=_bearer(make_token(roles=["ReportMate.Admin"]))
    )
    assert resp.status_code == 200


def test_delegated_scope_claim_accepted(oidc_client, make_token):
    # Delegated tokens carry scopes in `scp` (space-delimited), not `roles`.
    resp = oidc_client.get(
        "/read", headers=_bearer(make_token(scp="read openid profile"))
    )
    assert resp.status_code == 200
    assert resp.json()["scopes"] == ["read"]


def test_expired_token_rejected(oidc_client, make_token):
    resp = oidc_client.get(
        "/read", headers=_bearer(make_token(roles=["ReportMate.Read"], exp_delta=-120))
    )
    assert resp.status_code == 401


def test_wrong_audience_rejected(oidc_client, make_token):
    resp = oidc_client.get(
        "/read",
        headers=_bearer(
            make_token(roles=["ReportMate.Read"], aud="api://someone-else")
        ),
    )
    assert resp.status_code == 401


def test_untrusted_issuer_rejected(oidc_client, make_token):
    resp = oidc_client.get(
        "/read",
        headers=_bearer(
            make_token(roles=["ReportMate.Read"], iss="https://evil.example/v2.0")
        ),
    )
    assert resp.status_code == 401


def test_hs256_algorithm_rejected(oidc_client, make_token):
    # Algorithm-confusion guard: a token signed with a symmetric alg must be
    # rejected because only asymmetric algs are accepted.
    token = make_token(
        roles=["ReportMate.Admin"], alg="HS256", signing_key="a-shared-secret"
    )
    resp = oidc_client.get("/read", headers=_bearer(token))
    assert resp.status_code == 401


def test_token_without_reportmate_role_rejected(oidc_client, make_token):
    # A valid token from the right tenant but with no ReportMate role maps to no
    # scopes, so it must not authenticate anything (least privilege).
    resp = oidc_client.get("/read", headers=_bearer(make_token()))
    assert resp.status_code == 401


def test_malformed_bearer_rejected(oidc_client):
    resp = oidc_client.get("/read", headers=_bearer("not-a-jwt"))
    assert resp.status_code == 401


def test_disabled_ignores_bearer(oidc_client, make_token, monkeypatch):
    monkeypatch.setattr(oidc_auth, "ENABLE_OIDC_AUTH", False)
    resp = oidc_client.get(
        "/read", headers=_bearer(make_token(roles=["ReportMate.Admin"]))
    )
    assert resp.status_code == 401


def test_invalid_bearer_falls_through_to_passphrase(oidc_client):
    # conftest sets REPORTMATE_PASSPHRASE=test-passphrase. A rejected bearer must
    # not lock out a caller that also presents a valid passphrase.
    resp = oidc_client.get(
        "/read",
        headers={
            "Authorization": "Bearer garbage",
            "X-Client-Passphrase": "test-passphrase",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["method"] == "passphrase"
