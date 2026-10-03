"""Inventory state: what an asset inventory system says each device is doing.

ReportMate only sees check-ins, so a device stored on a shelf and a device
that has gone missing look the same: both stopped reporting. The inventory
side knows which is which. It writes one state per serial number here --
``checked_out`` (in someone's hands), ``storage`` (checked in to a storage
room) or ``decommissioning`` (on its way out) -- and the read side uses it to
keep stored devices out of the stale and missing counts and the install
error and warning tiles, while still listing and finding them.

The write is a bulk snapshot. With ``replace`` set, a serial left out of the
payload loses its state, so the table always matches the inventory's last
full answer rather than accumulating rows for devices it no longer mentions.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from dependencies import (
    get_db_connection,
    invalidate_caches,
    logger,
    verify_authentication,
)

router = APIRouter(tags=["inventory-state"])

STATES = ("checked_out", "storage", "decommissioning")
MAX_DEVICES_PER_WRITE = 20000


class InventoryStateEntry(BaseModel):
    serialNumber: str = Field(min_length=1, max_length=128)
    state: Literal["checked_out", "storage", "decommissioning"]
    storageLocation: Optional[str] = Field(default=None, max_length=255)
    leaseNumber: Optional[str] = Field(default=None, max_length=128)
    assetTag: Optional[str] = Field(default=None, max_length=128)


class InventoryStateWrite(BaseModel):
    devices: List[InventoryStateEntry]
    replace: bool = False


def normalize_serial(serial: Optional[str]) -> str:
    return (serial or "").strip().upper()


def _row_to_state(row) -> Dict[str, Any]:
    _serial, state, storage_location, lease_number, asset_tag, updated_at = row
    return {
        "state": state,
        "storageLocation": storage_location,
        "leaseNumber": lease_number,
        "assetTag": asset_tag,
        "updatedAt": updated_at.isoformat() if updated_at else None,
    }


def fetch_inventory_states(
    conn, serials: Optional[List[str]] = None
) -> Dict[str, Dict[str, Any]]:
    """Inventory state per upper-cased serial number.

    Read paths call this alongside their own queries. A failure -- the table
    not migrated yet, say -- returns no states rather than failing the page,
    and rolls back so the caller's connection is still usable.
    """
    cursor = conn.cursor()
    try:
        if serials is None:
            cursor.execute(
                "SELECT serial_number, state, storage_location, lease_number, asset_tag, updated_at "
                "FROM device_inventory_state"
            )
        else:
            cursor.execute(
                "SELECT serial_number, state, storage_location, lease_number, asset_tag, updated_at "
                "FROM device_inventory_state WHERE serial_number = ANY(%s)",
                ([normalize_serial(s) for s in serials],),
            )
        return {row[0]: _row_to_state(row) for row in cursor.fetchall()}
    except Exception as e:  # noqa: BLE001 -- state is an overlay, never fatal
        logger.warning(f"Inventory state unavailable: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return {}


def is_stored(state: Optional[Dict[str, Any]]) -> bool:
    return bool(state) and state.get("state") == "storage"


@router.get("/inventory-state", dependencies=[Depends(verify_authentication)])
def get_inventory_state():
    """Every device's inventory state, keyed by upper-cased serial number."""
    conn = get_db_connection()
    try:
        states = fetch_inventory_states(conn)
        counts = {s: 0 for s in STATES}
        for value in states.values():
            counts[value["state"]] = counts.get(value["state"], 0) + 1
        return {"devices": states, "total": len(states), "counts": counts}
    finally:
        conn.close()


@router.put("/inventory-state", dependencies=[Depends(verify_authentication)])
def put_inventory_state(body: InventoryStateWrite):
    """Write inventory states in bulk; ``replace`` makes the payload the whole truth."""
    if len(body.devices) > MAX_DEVICES_PER_WRITE:
        raise HTTPException(
            status_code=413,
            detail=f"At most {MAX_DEVICES_PER_WRITE} devices per write",
        )

    # An empty snapshot with replace would clear every state. That is never
    # a real answer from an inventory, and nearly always a failed read on
    # the other side, so it is refused rather than obeyed.
    if body.replace and not body.devices:
        raise HTTPException(status_code=400, detail="replace needs at least one device")

    # One row per serial: the last entry for a serial wins, the same way a
    # second write would overwrite the first.
    rows: Dict[str, InventoryStateEntry] = {}
    for entry in body.devices:
        serial = normalize_serial(entry.serialNumber)
        if serial:
            rows[serial] = entry

    now = datetime.now(timezone.utc)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if rows:
            cursor.executemany(
                """
                INSERT INTO device_inventory_state
                    (serial_number, state, storage_location, lease_number, asset_tag, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (serial_number) DO UPDATE SET
                    state = EXCLUDED.state,
                    storage_location = EXCLUDED.storage_location,
                    lease_number = EXCLUDED.lease_number,
                    asset_tag = EXCLUDED.asset_tag,
                    updated_at = EXCLUDED.updated_at
                """,
                [
                    (serial, e.state, e.storageLocation, e.leaseNumber, e.assetTag, now)
                    for serial, e in rows.items()
                ],
            )
        cleared = 0
        if body.replace:
            cursor.execute(
                "DELETE FROM device_inventory_state WHERE NOT (serial_number = ANY(%s))",
                (list(rows.keys()),),
            )
            cleared = cursor.rowcount or 0
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Inventory state write failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to write inventory state")
    finally:
        conn.close()

    invalidate_caches()
    logger.info(
        f"[INVENTORY STATE] wrote {len(rows)} devices, cleared {cleared} (replace={body.replace})"
    )
    return {"written": len(rows), "cleared": cleared, "replace": body.replace}
