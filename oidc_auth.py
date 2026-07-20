"""
ReportMate API - Federated identity (provider-agnostic OIDC bearer auth).

This module implements ``verify_oidc_bearer`` -- the extension point reserved in
``dependencies.verify_authentication`` for validating an ``Authorization: Bearer``
JWT issued by an external OpenID Connect provider (Microsoft Entra, Okta, Auth0,
Keycloak, Google, ...). It is deliberately **IdP-agnostic**:

  * one or more trusted issuers      -- env ``OIDC_ISSUERS`` (comma-separated)
  * one or more accepted audiences   -- env ``OIDC_AUDIENCE`` (comma-separated)
  * signing keys via each issuer's   -- OIDC discovery, or an explicit
    JWKS document                       ``OIDC_JWKS_URI`` override
  * IdP roles/scopes -> ReportMate scopes -- env ``OIDC_ROLE_SCOPE_MAP`` (JSON)

The point of this path, versus the shared passphrase and per-client API keys, is
that **ReportMate stores no secret for it**. Identity is proven by the provider's
signature over a short-lived token; there is nothing to rotate and nothing to
leak. An operator's own SSO session (e.g. ``az account get-access-token
--resource api://reportmate``) becomes their ReportMate API credential, scoped to
the roles their IdP grants them -- the same trust model as the Azure CLI.

The verifier returns an ``auth`` principal carrying a ``scopes`` list so it flows
through the existing ``_enforce_scope`` gate unchanged. It is **inert until
configured** (``ENABLE_OIDC_AUTH`` + issuers + audience), so wiring it in is
purely additive and breaks nothing in the deployed fleet.
"""

import json
import logging
import os
import urllib.request
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration (read once at import, mirroring dependencies.py)
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("true", "1", "yes")


def _env_list(name: str) -> Tuple[str, ...]:
    """Parse a comma-separated env var into a tuple of non-empty items."""
    raw = os.getenv(name, "")
    return tuple(item.strip() for item in raw.split(",") if item.strip())


# Least-privilege scope buckets, identical to the API-key model in
# dependencies.py: read (GETs), ingest (POST telemetry), admin (mutations,
# deletes, admin endpoints). ``admin`` is a superset so an admin token can also
# read and ingest -- otherwise an admin-only token would 403 on a plain GET.
_DEFAULT_ROLE_SCOPE_MAP: Dict[str, Tuple[str, ...]] = {
    "admin": ("read", "ingest", "admin"),
    "reportmate.admin": ("read", "ingest", "admin"),
    "ingest": ("ingest",),
    "reportmate.ingest": ("ingest",),
    "read": ("read",),
    "reader": ("read",),
    "reportmate.read": ("read",),
}


def _load_role_scope_map() -> Dict[str, Tuple[str, ...]]:
    """Default role->scope map, overlaid with the ``OIDC_ROLE_SCOPE_MAP`` JSON.

    Keys are matched case-insensitively against the token's role/scope claim
    values; values are lists of ReportMate scopes. The override is merged over
    the defaults so an operator can add their own IdP role names (e.g. an Entra
    group id) without losing the built-ins.
    """
    mapping = {key: tuple(val) for key, val in _DEFAULT_ROLE_SCOPE_MAP.items()}
    raw = os.getenv("OIDC_ROLE_SCOPE_MAP", "").strip()
    if raw:
        try:
            override = json.loads(raw)
            for key, scopes in override.items():
                mapping[str(key).strip().lower()] = tuple(scopes)
        except (ValueError, TypeError) as exc:
            logger.error(
                "[OIDC] Ignoring malformed OIDC_ROLE_SCOPE_MAP (%s); using defaults",
                exc,
            )
    return mapping


ENABLE_OIDC_AUTH: bool = _env_bool("ENABLE_OIDC_AUTH", False)
OIDC_ISSUERS: Tuple[str, ...] = _env_list("OIDC_ISSUERS")
OIDC_AUDIENCES: Tuple[str, ...] = _env_list("OIDC_AUDIENCE")
OIDC_JWKS_URI: Optional[str] = os.getenv("OIDC_JWKS_URI") or None
OIDC_ALGORITHMS: Tuple[str, ...] = _env_list("OIDC_ALGORITHMS") or (
    # Asymmetric only. ``none``/HS* are intentionally excluded to prevent
    # algorithm-confusion attacks (an attacker signing HS256 with the public key).
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
)
OIDC_DEFAULT_SCOPES: Tuple[str, ...] = _env_list("OIDC_DEFAULT_SCOPES")
OIDC_ROLE_SCOPE_MAP: Dict[str, Tuple[str, ...]] = _load_role_scope_map()
try:
    OIDC_LEEWAY: int = int(os.getenv("OIDC_LEEWAY", "60"))
except ValueError:
    OIDC_LEEWAY = 60


def oidc_enabled() -> bool:
    """True only when OIDC is switched on AND minimally configured."""
    return bool(ENABLE_OIDC_AUTH and OIDC_ISSUERS and OIDC_AUDIENCES)


# ---------------------------------------------------------------------------
# JWKS / signing-key resolution (isolated so tests can monkeypatch it)
# ---------------------------------------------------------------------------

_JWKS_URI_CACHE: Dict[str, str] = {}
_JWK_CLIENTS: Dict = {}


def _discover_jwks_uri(issuer: str) -> str:
    """Resolve an issuer's JWKS URI via OIDC discovery, cached per issuer.

    An explicit ``OIDC_JWKS_URI`` short-circuits discovery (useful for providers
    without a standard discovery document, or to pin the endpoint).
    """
    if OIDC_JWKS_URI:
        return OIDC_JWKS_URI
    if issuer in _JWKS_URI_CACHE:
        return _JWKS_URI_CACHE[issuer]
    well_known = issuer.rstrip("/") + "/.well-known/openid-configuration"
    with urllib.request.urlopen(
        well_known, timeout=5
    ) as resp:  # nosec B310 - https issuer
        doc = json.loads(resp.read().decode("utf-8"))
    jwks_uri = doc.get("jwks_uri")
    if not jwks_uri:
        raise ValueError(f"No jwks_uri in discovery document for issuer {issuer}")
    _JWKS_URI_CACHE[issuer] = jwks_uri
    return jwks_uri


def _signing_key_for_token(token: str, issuer: str):
    """Return the public signing key for ``token`` from ``issuer``'s JWKS.

    Uses PyJWT's ``PyJWKClient``, which fetches and caches the JWKS and selects
    the key matching the token's ``kid``. Isolated in its own function so tests
    can monkeypatch it with a local key and never touch the network.
    """
    from jwt import PyJWKClient

    jwks_uri = _discover_jwks_uri(issuer)
    client = _JWK_CLIENTS.get(jwks_uri)
    if client is None:
        client = PyJWKClient(jwks_uri, cache_keys=True)
        _JWK_CLIENTS[jwks_uri] = client
    return client.get_signing_key_from_jwt(token).key


# ---------------------------------------------------------------------------
# Claim -> scope mapping
# ---------------------------------------------------------------------------


def _scopes_from_claims(claims: dict) -> List[str]:
    """Map a validated token's role/scope claims to ReportMate scopes.

    Reads Entra-style app roles (``roles``: array), delegated scopes
    (``scp``/``scope``: space- or comma-delimited string), and group ids
    (``groups``: array, for operators who map group -> scope). Each value is
    looked up case-insensitively in ``OIDC_ROLE_SCOPE_MAP`` and the results are
    unioned. Falls back to ``OIDC_DEFAULT_SCOPES`` when nothing maps.
    """
    tokens: List[str] = []

    roles = claims.get("roles")
    if isinstance(roles, list):
        tokens.extend(str(r) for r in roles)

    groups = claims.get("groups")
    if isinstance(groups, list):
        tokens.extend(str(g) for g in groups)

    for scope_claim in ("scp", "scope"):
        value = claims.get(scope_claim)
        if isinstance(value, str):
            tokens.extend(part for part in value.replace(",", " ").split() if part)

    granted: set = set()
    for tok in tokens:
        granted.update(OIDC_ROLE_SCOPE_MAP.get(tok.strip().lower(), ()))

    if not granted and OIDC_DEFAULT_SCOPES:
        granted.update(OIDC_DEFAULT_SCOPES)

    # Return in the canonical read/ingest/admin order for stable logging/tests.
    order = {"read": 0, "ingest": 1, "admin": 2}
    return sorted(granted, key=lambda s: order.get(s, 99))


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def verify_oidc_bearer(authorization: str, client_host: Optional[str] = None):
    """Validate an ``Authorization: Bearer <jwt>`` header against a trusted OIDC
    provider and resolve a scoped principal.

    Returns an ``auth`` dict on success or ``None`` on any failure (disabled,
    malformed, untrusted issuer, bad signature/audience/expiry, or a token that
    maps to no scopes). Returning ``None`` -- rather than raising -- lets the
    caller apply the same "fall through to an accompanying credential" behaviour
    the API-key branch uses, and keeps validation failures from leaking a reason
    to the client (details are logged server-side only).
    """
    if not oidc_enabled():
        return None
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        return None

    import jwt

    # Read the (unverified) issuer first so we can (a) reject issuers we don't
    # trust before doing any crypto, and (b) select the right JWKS for a
    # multi-issuer deployment. Signature is still fully verified below.
    try:
        unverified = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except jwt.InvalidTokenError:
        logger.warning("[OIDC] Rejected bearer token: not a decodable JWT")
        return None

    issuer = unverified.get("iss")
    if not issuer or issuer not in OIDC_ISSUERS:
        logger.warning("[OIDC] Rejected bearer token from untrusted issuer: %r", issuer)
        return None

    try:
        key = _signing_key_for_token(token, issuer)
        claims = jwt.decode(
            token,
            key,
            algorithms=list(OIDC_ALGORITHMS),
            audience=list(OIDC_AUDIENCES),
            issuer=issuer,
            leeway=OIDC_LEEWAY,
            options={"require": ["exp"]},
        )
    except jwt.InvalidTokenError as exc:
        logger.warning("[OIDC] Rejected bearer token (%s): %s", type(exc).__name__, exc)
        return None
    except Exception as exc:  # JWKS fetch / network / key errors
        logger.error("[OIDC] Bearer validation error resolving signing key: %s", exc)
        return None

    scopes = _scopes_from_claims(claims)
    if not scopes:
        principal = claims.get("preferred_username") or claims.get("sub")
        logger.warning(
            "[OIDC] Valid token for %r carries no ReportMate scopes; rejecting",
            principal,
        )
        return None

    return {
        "method": "oidc",
        "issuer": issuer,
        "principal": claims.get("oid") or claims.get("sub"),
        "username": (
            claims.get("preferred_username") or claims.get("upn") or claims.get("email")
        ),
        "client_id": claims.get("azp") or claims.get("appid"),
        "scopes": scopes,
        "client_ip": client_host,
    }
