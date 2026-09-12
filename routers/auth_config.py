"""Public description of how to authenticate to this API.

Nothing here is secret: the OIDC issuer and audience are the same values a
token carries in its claims, and the header names are in every 401 body.
Clients use it to configure themselves. reportmateutil reads the audience,
mints a token with ``az account get-access-token --resource <audience>`` and
presents it as ``Authorization: Bearer`` with no stored secret on the machine.
"""

from fastapi import APIRouter

import oidc_auth

router = APIRouter(tags=["auth"])


@router.get("/auth/config")
def auth_config():
    """Which credentials this deployment accepts, and the OIDC details a
    client needs to mint a bearer token for it."""
    enabled = oidc_auth.oidc_enabled()
    credentials = ["X-API-Key", "X-Client-Passphrase"]
    if enabled:
        credentials.insert(0, "Authorization: Bearer")
    return {
        "credentials": credentials,
        "oidc": {
            "enabled": enabled,
            "issuers": list(oidc_auth.OIDC_ISSUERS) if enabled else [],
            # The first audience is the one to request a token for.
            "audience": oidc_auth.OIDC_AUDIENCES[0] if enabled and oidc_auth.OIDC_AUDIENCES else None,
            "audiences": list(oidc_auth.OIDC_AUDIENCES) if enabled else [],
        },
    }
