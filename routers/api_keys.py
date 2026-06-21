"""
Admin endpoints for managing per-client API keys.

All routes live under ``/admin`` so the central scope gate in
``verify_authentication`` requires the ``admin`` scope. A holder of the legacy
shared passphrase (full access) can mint the first keys, avoiding any
chicken-and-egg bootstrap problem.
"""

import json
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from dependencies import (
    ALL_SCOPES,
    audit_api_key,
    generate_api_key,
    get_db_connection,
    logger,
    verify_authentication,
    _hash_secret,
)

router = APIRouter(tags=["admin"])


class CreateApiKey(BaseModel):
    client_id: str = Field(
        ..., min_length=1, description="Human label / owner of the key"
    )
    scopes: List[str] = Field(
        default_factory=lambda: ["read"],
        description="Subset of read/ingest/admin",
    )


def _actor(auth: dict) -> str:
    """Identify who performed an admin action, for the audit log."""
    return auth.get("client_id") or auth.get("method") or "unknown"


@router.post("/admin/api-keys", tags=["admin"])
async def create_api_key(
    body: CreateApiKey,
    auth: dict = Depends(verify_authentication),
):
    """Mint a new API key. The full key is returned once and never stored."""
    invalid = [s for s in body.scopes if s not in ALL_SCOPES]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scopes {invalid}; allowed: {sorted(ALL_SCOPES)}",
        )
    if not body.scopes:
        raise HTTPException(status_code=400, detail="At least one scope is required")

    key_id, secret, full_key = generate_api_key()
    actor = _actor(auth)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO api_keys (id, client_id, key_hash, scopes, created_by) "
        "VALUES (%s, %s, %s, %s, %s)",
        (
            key_id,
            body.client_id,
            _hash_secret(secret),
            json.dumps(body.scopes),
            actor,
        ),
    )
    conn.commit()
    conn.close()

    audit_api_key(
        key_id,
        "created",
        actor=actor,
        detail={"client_id": body.client_id, "scopes": body.scopes},
    )
    logger.info(f"API key {key_id} created for '{body.client_id}' by {actor}")

    return {
        "id": key_id,
        "client_id": body.client_id,
        "scopes": body.scopes,
        "key": full_key,
        "warning": "Store this key now -- it cannot be retrieved again.",
    }


@router.get("/admin/api-keys", tags=["admin"])
async def list_api_keys(auth: dict = Depends(verify_authentication)):
    """List API keys (metadata only; secrets are never returned)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, client_id, scopes, active, created_at, created_by, last_used "
        "FROM api_keys ORDER BY created_at DESC"
    )
    rows = cursor.fetchall()
    conn.close()

    keys = []
    for row in rows:
        kid, client_id, scopes, active, created_at, created_by, last_used = row
        if isinstance(scopes, str):
            try:
                scopes = json.loads(scopes)
            except Exception:
                scopes = []
        keys.append(
            {
                "id": kid,
                "client_id": client_id,
                "scopes": scopes or [],
                "active": bool(active),
                "created_at": created_at.isoformat() if created_at else None,
                "created_by": created_by,
                "last_used": last_used.isoformat() if last_used else None,
            }
        )
    return {"keys": keys, "count": len(keys)}


@router.delete("/admin/api-keys/{key_id}", tags=["admin"])
async def revoke_api_key(
    key_id: str,
    auth: dict = Depends(verify_authentication),
):
    """Revoke a key (soft delete -- sets active=false; the audit row remains)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE api_keys SET active = FALSE WHERE id = %s", (key_id,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()

    if not affected:
        raise HTTPException(status_code=404, detail="API key not found")

    actor = _actor(auth)
    audit_api_key(key_id, "revoked", actor=actor)
    logger.info(f"API key {key_id} revoked by {actor}")
    return {"id": key_id, "status": "revoked"}
