"""Extensions: data an outside system attaches to a device by serial number.

Modules are what the client collects on the device and posts through
/events. Some data about a device never touches the device at all -- an MDM
compliance audit, a vendor's risk score, a lease record -- and is known only
to a server that can name the device by serial. That is an extension: a named
JSONB document per device, written by whichever integration owns it, kept in
one generic ``extension_data`` table keyed by (device_id, extension_name), so
adding an extension needs no migration.

A name that collides with a core module is refused. Core data has its own
table and its own ingest path, and letting an extension shadow it would leave
two sources for the same module.

Auth is the same ``verify_authentication`` gate as the device routes, so the
usual scope mapping applies: GET needs ``read``, POST needs ``ingest`` and
DELETE needs ``admin``.

The device read model does not merge extensions yet. Whether they surface as
``device.extensions`` or alongside ``device.modules`` is still open; until then
they are read through these routes.
"""

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from dependencies import (
    VALID_MODULE_NAMES,
    get_db_connection,
    logger,
    verify_authentication,
)

router = APIRouter(tags=["extensions"])

# A lowercase slug: a letter or digit, then up to 63 of letters, digits, _ or -.
EXTENSION_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
MAX_DEVICES_PER_WRITE = 20000

EXTENSION_UPSERT_SQL = """
    INSERT INTO extension_data
        (device_id, extension_name, data, source, collected_at, created_at, updated_at)
    VALUES (%s, %s, %s::jsonb, %s, %s, %s, %s)
    ON CONFLICT (device_id, extension_name) DO UPDATE SET
        data = EXCLUDED.data,
        source = EXCLUDED.source,
        collected_at = EXCLUDED.collected_at,
        updated_at = EXCLUDED.updated_at
"""


class ExtensionWrite(BaseModel):
    data: Any
    source: Optional[str] = Field(default=None, max_length=64)
    collectedAt: Optional[datetime] = None


class BulkExtensionEntry(BaseModel):
    serialNumber: str = Field(min_length=1, max_length=255)
    data: Any
    source: Optional[str] = Field(default=None, max_length=64)
    collectedAt: Optional[datetime] = None


class BulkExtensionWrite(BaseModel):
    source: Optional[str] = Field(default=None, max_length=64)
    collectedAt: Optional[datetime] = None
    devices: List[BulkExtensionEntry]


def validate_extension_name(name: str) -> str:
    name = (name or "").strip().lower()
    if not EXTENSION_NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid extension name")
    if name in VALID_MODULE_NAMES:
        raise HTTPException(
            status_code=400,
            detail=f"'{name}' is a core module; core data is ingested through /events",
        )
    return name


def _iso(value) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _upsert_params(device_id, name, data, source, collected_at, now):
    return (device_id, name, json.dumps(data), source, collected_at or now, now, now)


def _resolve_device_id(cursor, serial_number: str) -> Optional[str]:
    """The devices.id for a serial, matching the device routes' lookup."""
    cursor.execute(
        "SELECT id FROM devices WHERE serial_number = %s OR id = %s",
        (serial_number, serial_number),
    )
    row = cursor.fetchone()
    return row[0] if row else None


# ── per device ──────────────────────────────────────────────────


@router.post(
    "/device/{serial_number}/extension/{extension_name}",
    dependencies=[Depends(verify_authentication)],
)
def upsert_device_extension(
    serial_number: str, extension_name: str, body: ExtensionWrite
):
    """Attach one extension's data to a device, replacing what was there."""
    name = validate_extension_name(extension_name)
    if body.data is None:
        raise HTTPException(status_code=400, detail="Missing extension data")

    now = datetime.now(timezone.utc)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        device_id = _resolve_device_id(cursor, serial_number)
        if device_id is None:
            raise HTTPException(
                status_code=404, detail=f"Device {serial_number} not found"
            )
        cursor.execute(
            EXTENSION_UPSERT_SQL,
            _upsert_params(
                device_id, name, body.data, body.source, body.collectedAt, now
            ),
        )
        conn.commit()
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        logger.error(f"Extension {name} write failed for {serial_number}: {e}")
        raise HTTPException(status_code=500, detail="Failed to store extension data")
    finally:
        conn.close()

    return {"success": True, "serialNumber": serial_number, "extension": name}


@router.get(
    "/device/{serial_number}/extension/{extension_name}",
    dependencies=[Depends(verify_authentication)],
)
def get_device_extension(serial_number: str, extension_name: str):
    """One extension's data for a device."""
    name = validate_extension_name(extension_name)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT e.data, e.source, e.collected_at, e.updated_at "
            "FROM extension_data e JOIN devices d ON d.id = e.device_id "
            "WHERE (d.serial_number = %s OR d.id = %s) AND e.extension_name = %s",
            (serial_number, serial_number, name),
        )
        row = cursor.fetchone()
    except Exception as e:
        logger.error(f"Extension {name} read failed for {serial_number}: {e}")
        raise HTTPException(status_code=500, detail="Failed to read extension data")
    finally:
        conn.close()

    if not row:
        raise HTTPException(
            status_code=404, detail="Extension data not found for device"
        )
    data, source, collected_at, updated_at = row
    return {
        "serialNumber": serial_number,
        "extension": name,
        "data": json.loads(data) if isinstance(data, str) else data,
        "source": source,
        "collectedAt": _iso(collected_at),
        "updatedAt": _iso(updated_at),
    }


@router.delete(
    "/device/{serial_number}/extension/{extension_name}",
    dependencies=[Depends(verify_authentication)],
)
def delete_device_extension(serial_number: str, extension_name: str):
    """Remove one extension's data from a device, e.g. when it leaves that system's scope."""
    name = validate_extension_name(extension_name)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM extension_data WHERE extension_name = %s AND device_id IN "
            "(SELECT id FROM devices WHERE serial_number = %s OR id = %s)",
            (name, serial_number, serial_number),
        )
        deleted = cursor.rowcount or 0
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Extension {name} delete failed for {serial_number}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete extension data")
    finally:
        conn.close()

    return {
        "success": True,
        "serialNumber": serial_number,
        "extension": name,
        "deleted": deleted,
    }


# ── fleet ───────────────────────────────────────────────────────


@router.post(
    "/extension/{extension_name}/bulk", dependencies=[Depends(verify_authentication)]
)
def bulk_upsert_extension(extension_name: str, body: BulkExtensionWrite):
    """Write one extension for many devices in a single call.

    This is the fleet poller's path: it computes the whole fleet in one pass
    and posts it here. Serials ReportMate has never seen are skipped and
    returned, not treated as an error, because the other system routinely
    knows devices that have not checked in yet.
    """
    name = validate_extension_name(extension_name)
    if len(body.devices) > MAX_DEVICES_PER_WRITE:
        raise HTTPException(
            status_code=413,
            detail=f"At most {MAX_DEVICES_PER_WRITE} devices per write",
        )

    # The last entry for a serial wins, the same way a second write would.
    entries: Dict[str, BulkExtensionEntry] = {}
    skipped_bad = 0
    for entry in body.devices:
        serial = entry.serialNumber.strip()
        if not serial or entry.data is None:
            skipped_bad += 1
            continue
        entries[serial] = entry

    now = datetime.now(timezone.utc)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        device_ids: Dict[str, str] = {}
        if entries:
            serials = list(entries.keys())
            cursor.execute(
                "SELECT id, serial_number FROM devices "
                "WHERE serial_number = ANY(%s) OR id = ANY(%s)",
                (serials, serials),
            )
            for device_id, serial_number in cursor.fetchall():
                for key in (serial_number, device_id):
                    if key in entries:
                        device_ids.setdefault(key, device_id)

        rows = [
            _upsert_params(
                device_ids[serial],
                name,
                e.data,
                e.source or body.source,
                e.collectedAt or body.collectedAt,
                now,
            )
            for serial, e in entries.items()
            if serial in device_ids
        ]
        if rows:
            cursor.executemany(EXTENSION_UPSERT_SQL, rows)
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Extension {name} bulk write failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to store extension data")
    finally:
        conn.close()

    unknown = [s for s in entries if s not in device_ids]
    logger.info(
        f"[EXTENSION] {name}: wrote {len(rows)} devices, "
        f"{len(unknown)} unknown, {skipped_bad} malformed"
    )
    return {
        "success": True,
        "extension": name,
        "written": len(rows),
        "unknownSerials": unknown,
        "skippedBad": skipped_bad,
    }
