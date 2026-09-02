"""Administrative operations: archive, unarchive, delete devices, diagnostics."""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from routers.events import _install_issue_counts
from dependencies import (
    get_db_connection, get_maintenance_db_connection, invalidate_caches,
    load_sql, logger,
    verify_authentication,
)

router = APIRouter(tags=["admin"])

@router.patch("/device/{serial_number}/archive", dependencies=[Depends(verify_authentication)], tags=["devices"])
def archive_device(serial_number: str):
    """
    Archive a device (soft delete).
    
    Archived devices:
    - Are hidden from all bulk endpoints by default
    - Still exist in database with all module data intact
    - Can be unarchived later
    - Do NOT receive new data submissions (rejected at ingestion)
    
    This is useful for:
    - Decommissioned devices
    - Devices being retired/replaced
    - Test devices no longer needed
    - Keeping historical data while hiding from active reports
    
    **Authentication Required:**
    - Windows clients: X-API-PASSPHRASE header
    - Azure resources: X-MS-CLIENT-PRINCIPAL-ID header (Managed Identity)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if device exists
        check_query = load_sql("admin/check_device_archived")
        cursor.execute(check_query, {"serial_number": serial_number})
        
        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            raise HTTPException(status_code=404, detail=f"Device {serial_number} not found")
        
        device_id, currently_archived = device_row
        
        # Check if already archived
        if currently_archived:
            conn.close()
            return {
                "success": True,
                "message": f"Device {serial_number} is already archived",
                "serialNumber": serial_number,
                "archived": True,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        # Archive the device
        archive_query = load_sql("admin/archive_device")
        now = datetime.now(timezone.utc)
        cursor.execute(archive_query, {
            "serial_number": serial_number,
            "archived_at": now,
            "updated_at": now
        })
        
        conn.commit()
        conn.close()
        invalidate_caches()
        
        logger.info(f"[SUCCESS] Archived device: {serial_number}")
        
        return {
            "success": True,
            "message": f"Device {serial_number} has been archived",
            "serialNumber": serial_number,
            "archived": True,
            "archivedAt": now.isoformat(),
            "timestamp": now.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to archive device {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to archive device: {str(e)}")

@router.patch("/device/{serial_number}/unarchive", dependencies=[Depends(verify_authentication)], tags=["devices"])
def unarchive_device(serial_number: str):
    """
    Unarchive a device (restore from soft delete).
    
    Unarchived devices:
    - Become visible in all bulk endpoints again
    - Can receive new data submissions
    - Restore to 'active' status
    - Retain all historical data
    
    **Authentication Required:**
    - Windows clients: X-API-PASSPHRASE header
    - Azure resources: X-MS-CLIENT-PRINCIPAL-ID header (Managed Identity)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if device exists
        check_query = load_sql("admin/check_device_archived")
        cursor.execute(check_query, {"serial_number": serial_number})
        
        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            raise HTTPException(status_code=404, detail=f"Device {serial_number} not found")
        
        device_id, currently_archived = device_row
        
        # Check if not archived
        if not currently_archived:
            conn.close()
            return {
                "success": True,
                "message": f"Device {serial_number} is not archived",
                "serialNumber": serial_number,
                "archived": False,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        # Unarchive the device
        unarchive_query = load_sql("admin/unarchive_device")
        now = datetime.now(timezone.utc)
        cursor.execute(unarchive_query, {
            "serial_number": serial_number,
            "updated_at": now
        })
        
        conn.commit()
        conn.close()
        invalidate_caches()
        
        logger.info(f"[SUCCESS] Unarchived device: {serial_number}")
        
        return {
            "success": True,
            "message": f"Device {serial_number} has been unarchived",
            "serialNumber": serial_number,
            "archived": False,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to unarchive device {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to unarchive device: {str(e)}")

@router.delete("/device/{serial_number}", dependencies=[Depends(verify_authentication)], tags=["devices"])
def delete_device(serial_number: str, confirm: bool = Query(False)):
    """
    Permanently delete a device and all its data.
    
    **WARNING: This is a DESTRUCTIVE operation!**
    
    Deletion removes:
    - Device record from devices table
    - All module data (cascading delete via foreign keys)
    - All events history
    - ALL historical data - cannot be recovered
    
    This should only be used for:
    - Test devices that should not exist
    - Duplicate records
    - Data cleanup/GDPR compliance
    
    **RECOMMENDATION:** Use archive instead of delete to preserve historical data!
    
    Query Parameters:
    - confirm: Must be set to true to confirm deletion (safety check)
    
    **Authentication Required:**
    - Windows clients: X-API-PASSPHRASE header
    - Azure resources: X-MS-CLIENT-PRINCIPAL-ID header (Managed Identity)
    """
    try:
        # Safety check: require explicit confirmation
        if not confirm:
            raise HTTPException(
                status_code=400,
                detail="Deletion requires confirmation. Add ?confirm=true to the request. WARNING: This permanently deletes all device data!"
            )
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if device exists and get details for logging
        check_query = load_sql("admin/get_device_for_delete")
        cursor.execute(check_query, {"serial_number": serial_number})
        
        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            raise HTTPException(status_code=404, detail=f"Device {serial_number} not found")
        
        device_id, device_uuid, device_name, is_archived = device_row
        
        # Get module counts for logging
        module_tables = ["system", "hardware", "applications", "installs", "network", "security",
                        "inventory", "management", "peripherals", "identity"]
        module_counts = {}
        
        for table in module_tables:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE device_id = %s", (device_id,))
                count_result = cursor.fetchone()
                module_counts[table] = count_result[0] if count_result else 0
            except Exception:
                module_counts[table] = 0
        
        # Get event count
        cursor.execute("SELECT COUNT(*) FROM events WHERE device_id = %s", (device_id,))
        event_count_result = cursor.fetchone()
        event_count = event_count_result[0] if event_count_result else 0

        # usage_history has no FK to devices, so it must be cleaned up explicitly
        # to avoid orphan rows after a hard delete.
        cursor.execute("DELETE FROM usage_history WHERE device_id = %s", (device_id,))
        usage_history_deleted = cursor.rowcount

        # Delete the device (CASCADE will delete all related module data and events)
        cursor.execute("""
            DELETE FROM devices
            WHERE serial_number = %s OR id = %s
        """, (serial_number, serial_number))

        deleted_count = cursor.rowcount

        conn.commit()
        conn.close()
        invalidate_caches()
        
        if deleted_count == 0:
            raise HTTPException(status_code=404, detail=f"Device {serial_number} not found")
        
        logger.warning(f"DELETED device: {serial_number} (UUID: {device_uuid}, Name: {device_name})")
        logger.warning(f"   - Archived status: {is_archived}")
        logger.warning(f"   - Events deleted: {event_count}")
        logger.warning(f"   - Usage history rows deleted: {usage_history_deleted}")
        logger.warning(f"   - Modules deleted: {sum(module_counts.values())} records across {len([k for k, v in module_counts.items() if v > 0])} tables")

        return {
            "success": True,
            "message": f"Device {serial_number} and all associated data has been permanently deleted",
            "serialNumber": serial_number,
            "deviceId": device_uuid,
            "deviceName": device_name,
            "wasArchived": is_archived,
            "deletedData": {
                "events": event_count,
                "usageHistory": usage_history_deleted,
                "modules": module_counts,
                "totalModuleRecords": sum(module_counts.values())
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "warning": "This data cannot be recovered"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete device {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete device: {str(e)}")

@router.get("/admin/usage-history/date-anomalies", dependencies=[Depends(verify_authentication)], tags=["admin"])
def usage_history_date_anomalies(
    floor: Optional[str] = Query(None, description="Rows dated before this YYYY-MM-DD are implausible (default: 548 days ago, the API's own lookback ceiling)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum sample rows returned per bucket"),
):
    """
    Rows in usage_history whose `date` could not have been produced by a
    healthy client.

    Read-only. Exists because neither the fleet nor the per-device usage
    endpoint can see these rows: both clamp their lookback to 548 days, so a
    row dated 1976 is invisible to every normal query while still being
    counted by aggregates that scan the whole table.

    Two buckets, each a different defect:

    - **tooOld** - a date below the floor. A client cannot have observed usage
      before it existed, so this is a parsing or conversion fault.
    - **inFuture** - a date after today. Usually a device clock, but it also
      lands rows in windows that have not happened yet, where they will be
      silently included the moment the window arrives.

    `updated_at` is the field that matters when reading the result: it is when
    the row was last written, so it separates a historical mess that a baseline
    reset will clear from a fault that is still occurring and will simply
    repopulate.
    """
    conn = None
    try:
        if floor:
            try:
                floor_date = datetime.strptime(floor, "%Y-%m-%d").date()
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid 'floor' date {floor!r}; expected YYYY-MM-DD",
                )
        else:
            floor_date = (datetime.now(timezone.utc) - timedelta(days=548)).date()

        today = datetime.now(timezone.utc).date()

        conn = get_db_connection()
        cursor = conn.cursor()

        def bucket(where: str, param) -> Dict[str, Any]:
            cursor.execute(
                f"""
                SELECT COUNT(*), COUNT(DISTINCT device_id), COUNT(DISTINCT app_name),
                       MIN(date)::text, MAX(date)::text,
                       MIN(updated_at)::text, MAX(updated_at)::text
                FROM usage_history WHERE {where}
                """,
                (param,),
            )
            c = cursor.fetchone() or (0, 0, 0, None, None, None, None)

            cursor.execute(
                f"""
                SELECT device_id, date::text, app_name, launches,
                       total_seconds, active_seconds, updated_at::text
                FROM usage_history WHERE {where}
                ORDER BY date, device_id, app_name
                LIMIT %s
                """,
                (param, limit),
            )
            rows = [
                {
                    "deviceId": r[0],
                    "date": r[1],
                    "appName": r[2],
                    "launches": int(r[3] or 0),
                    "totalSeconds": float(r[4] or 0),
                    "activeSeconds": float(r[5] or 0),
                    "updatedAt": r[6],
                }
                for r in cursor.fetchall()
            ]

            return {
                "rows": int(c[0] or 0),
                "devices": int(c[1] or 0),
                "applications": int(c[2] or 0),
                "earliestDate": c[3],
                "latestDate": c[4],
                "firstWritten": c[5],
                "lastWritten": c[6],
                "sample": rows,
            }

        too_old = bucket("date < %s", floor_date)
        in_future = bucket("date > %s", today)

        conn.close()
        conn = None

        return {
            "status": "ok",
            "floorDate": str(floor_date),
            "today": str(today),
            "tooOld": too_old,
            "inFuture": in_future,
        }

    except HTTPException:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        raise
    except Exception as e:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        logger.error(f"usage_history date anomaly probe failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


PLATFORM_CASE = """CASE
                WHEN LOWER(COALESCE(d.platform, '')) LIKE '%%mac%%'
                  OR LOWER(COALESCE(d.platform, '')) LIKE '%%darwin%%' THEN 'macOS'
                WHEN LOWER(COALESCE(d.platform, '')) LIKE '%%win%%' THEN 'Windows'
                ELSE 'Other'
            END"""

# One second of slack on the ordering checks: the clients round each counter
# independently, so a session can legitimately carry foreground one second
# above total after rounding. Anything past that is a defect.
ORDERING_SLACK_SECONDS = 1
DAY_SECONDS = 86400


@router.get("/admin/usage-history/integrity", dependencies=[Depends(verify_authentication)], tags=["admin"])
def usage_history_integrity(
    days: int = Query(7, ge=1, le=90, description="Lookback window in days, by row date"),
    sample: int = Query(20, ge=1, le=200, description="Maximum offending device-days returned"),
):
    """
    Physical-plausibility check over recent usage_history rows, per platform.

    The accuracy checks that gated September collection were run by hand
    against the fleet endpoints and per-device histories. This is the same
    check as one query so a timer can run it every day through the term and
    say out loud when a client regression starts inflating the record again.

    Everything here is a hard physical bound, not a heuristic:

    - a duration cannot be negative;
    - foreground cannot exceed total, and active cannot exceed foreground,
      beyond one second of rounding slack;
    - a device cannot accumulate more than 24 hours of foreground or active
      time in one calendar day, summed across its applications.

    The per-platform block for the last complete day gives the day's shape
    (devices with rows, foreground and active hours per device, launches) so
    a check that passes the bounds still shows whether the fleet moved.
    total_seconds is process lifetime with no wall-clock ceiling and is not
    checked against the day; see the usage endpoint for why it is not a
    reportable figure.
    """
    conn = None
    try:
        today = datetime.now(timezone.utc).date()
        cutoff = today - timedelta(days=days)
        # Clients date rows on their local calendar day, so the newest
        # complete day is the one before today everywhere the fleet lives.
        last_complete = today - timedelta(days=1)
        floor_date = today - timedelta(days=548)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            f"""
            SELECT {PLATFORM_CASE} AS platform,
                   COUNT(*)                                                    AS rows,
                   COUNT(DISTINCT uh.device_id)                                AS devices,
                   COUNT(*) FILTER (WHERE uh.total_seconds < 0
                                       OR uh.active_seconds < 0
                                       OR uh.foreground_seconds < 0)           AS negative_rows,
                   COUNT(*) FILTER (WHERE uh.foreground_seconds
                                          > uh.total_seconds + %s)             AS foreground_over_total,
                   COUNT(*) FILTER (WHERE uh.active_seconds
                                          > uh.foreground_seconds + %s)        AS active_over_foreground,
                   COUNT(*) FILTER (WHERE uh.foreground_seconds > %s
                                       OR uh.active_seconds > %s)              AS rows_over_day
            FROM usage_history uh
            JOIN devices d ON d.serial_number = uh.device_id
            WHERE uh.date >= %s
            GROUP BY 1
            """,
            (ORDERING_SLACK_SECONDS, ORDERING_SLACK_SECONDS, DAY_SECONDS, DAY_SECONDS, cutoff),
        )
        platforms: Dict[str, Dict[str, Any]] = {}
        for row in cursor.fetchall():
            platforms[row[0]] = {
                "rows": int(row[1] or 0),
                "devices": int(row[2] or 0),
                "negativeRows": int(row[3] or 0),
                "foregroundOverTotal": int(row[4] or 0),
                "activeOverForeground": int(row[5] or 0),
                "rowsOverDay": int(row[6] or 0),
            }

        cursor.execute(
            f"""
            SELECT {PLATFORM_CASE} AS platform,
                   uh.device_id, uh.date::text,
                   SUM(uh.foreground_seconds) AS fg, SUM(uh.active_seconds) AS act
            FROM usage_history uh
            JOIN devices d ON d.serial_number = uh.device_id
            WHERE uh.date >= %s
            GROUP BY 1, uh.device_id, uh.date
            HAVING SUM(uh.foreground_seconds) > %s OR SUM(uh.active_seconds) > %s
            ORDER BY GREATEST(SUM(uh.foreground_seconds), SUM(uh.active_seconds)) DESC
            LIMIT %s
            """,
            (cutoff, DAY_SECONDS, DAY_SECONDS, sample),
        )
        over = [
            {
                "platform": r[0],
                "deviceId": r[1],
                "date": r[2],
                "foregroundHours": round(float(r[3] or 0) / 3600, 2),
                "activeHours": round(float(r[4] or 0) / 3600, 2),
            }
            for r in cursor.fetchall()
        ]
        for entry in over:
            platforms.setdefault(entry["platform"], {})
            platforms[entry["platform"]]["deviceDaysOverCeiling"] = (
                platforms[entry["platform"]].get("deviceDaysOverCeiling", 0) + 1
            )
        for stats in platforms.values():
            stats.setdefault("deviceDaysOverCeiling", 0)

        cursor.execute(
            f"""
            SELECT {PLATFORM_CASE} AS platform,
                   COUNT(DISTINCT uh.device_id)          AS devices,
                   SUM(uh.foreground_seconds)            AS fg,
                   SUM(uh.active_seconds)                AS act,
                   SUM(uh.launches)                      AS launches
            FROM usage_history uh
            JOIN devices d ON d.serial_number = uh.device_id
            WHERE uh.date = %s
            GROUP BY 1
            """,
            (last_complete,),
        )
        for row in cursor.fetchall():
            devices = int(row[1] or 0)
            fg_hours = float(row[2] or 0) / 3600
            act_hours = float(row[3] or 0) / 3600
            platforms.setdefault(row[0], {})["lastCompleteDay"] = {
                "date": str(last_complete),
                "devices": devices,
                "foregroundHours": round(fg_hours, 1),
                "activeHours": round(act_hours, 1),
                "foregroundHoursPerDevice": round(fg_hours / devices, 2) if devices else 0.0,
                "activeHoursPerDevice": round(act_hours / devices, 2) if devices else 0.0,
                "launches": int(row[4] or 0),
            }

        cursor.execute(
            """
            SELECT COUNT(*) FILTER (WHERE date < %s) AS too_old,
                   COUNT(*) FILTER (WHERE date > %s) AS in_future
            FROM usage_history
            """,
            (floor_date, today),
        )
        anomalies = cursor.fetchone() or (0, 0)

        conn.close()
        conn = None

        breaches = sum(
            p.get("negativeRows", 0) + p.get("foregroundOverTotal", 0)
            + p.get("activeOverForeground", 0) + p.get("deviceDaysOverCeiling", 0)
            for p in platforms.values()
        ) + int(anomalies[0] or 0) + int(anomalies[1] or 0)

        return {
            "status": "ok",
            "days": days,
            "cutoffDate": str(cutoff),
            "lastCompleteDay": str(last_complete),
            "clean": breaches == 0,
            "platforms": platforms,
            "deviceDaysOverCeiling": over,
            "dateAnomalies": {"tooOld": int(anomalies[0] or 0), "inFuture": int(anomalies[1] or 0)},
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"usage_history integrity probe failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            conn.close()


EXPORT_COLUMNS = [
    "device_id", "date", "app_name", "publisher", "launches",
    "total_seconds", "active_seconds", "foreground_seconds", "users", "updated_at",
]
EXPORT_BATCH = 5000


@router.get("/admin/usage-history/export", dependencies=[Depends(verify_authentication)], tags=["admin"])
def usage_history_export(
    start: str = Query(..., alias="from", description="First row date to include, YYYY-MM-DD"),
    end: str = Query(..., alias="to", description="First row date to exclude, YYYY-MM-DD"),
):
    """
    Stream usage_history rows for a date range as CSV.

    usage_history is the one table a device cannot re-report: every other
    module row is a current-state snapshot that self-heals on the next
    check-in. This is the read side of its archive -- the alerts app pulls
    each closed month through here and writes it to blob storage, so the
    record outlives the database's backup window.

    Half-open range ``[from, to)`` on the row date, ordered by date, device
    and application so two exports of the same range are byte-identical.
    Rows stream from a server-side cursor in batches; a month of the current
    fleet is a few hundred thousand rows and never sits in memory at once.
    """
    try:
        start_date = datetime.strptime(start, "%Y-%m-%d").date()
        end_date = datetime.strptime(end, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(status_code=400, detail="from/to must be YYYY-MM-DD")
    if end_date <= start_date:
        raise HTTPException(status_code=400, detail="'to' must be after 'from'")

    def rows():
        import csv
        import io

        conn = get_db_connection()
        try:
            cursor = conn.cursor(name="usage_history_export")
            cursor.itersize = EXPORT_BATCH
            cursor.execute(
                """
                SELECT device_id, date::text, app_name, publisher, launches,
                       total_seconds, active_seconds, foreground_seconds,
                       COALESCE(users::text, '[]'), updated_at::text
                FROM usage_history
                WHERE date >= %s AND date < %s
                ORDER BY date, device_id, app_name
                """,
                (start_date, end_date),
            )
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(EXPORT_COLUMNS)
            yield buf.getvalue()
            while True:
                batch = cursor.fetchmany(EXPORT_BATCH)
                if not batch:
                    break
                buf = io.StringIO()
                writer = csv.writer(buf)
                writer.writerows(batch)
                yield buf.getvalue()
        finally:
            conn.close()

    filename = f"usage_history-{start_date}-{end_date}.csv"
    return StreamingResponse(
        rows(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/admin/usage-history/reset-baseline", dependencies=[Depends(verify_authentication)], tags=["admin"])
def reset_usage_history_baseline(
    before: str = Query(..., description="Archive and remove rows dated before this YYYY-MM-DD (exclusive)"),
    confirm: bool = Query(False, description="Must be true to execute; otherwise a preview is returned"),
    reason: str = Query("", description="Recorded on the archived rows so a batch can be identified later"),
):
    """
    Archive and remove usage_history rows before a cutoff date.

    **This is a DESTRUCTIVE operation on the live reporting table.**

    Why it exists: usage_history accumulates client-sent window deltas, so a
    client-side counting defect is written into the table permanently and
    cannot be recomputed from anything the server still holds. Correcting one
    means removing the affected rows. Every row is copied verbatim into
    usage_history_archive first, so the reset is recoverable and "what did we
    report before" stays answerable.

    Not the same as /admin/usage-history/cleanup, which enforces a minimum
    retention of one month and exists for routine ageing-out. This takes an
    explicit cutoff so a term baseline can start clean, and it archives rather
    than discards.

    Without ``confirm=true`` this returns a preview of exactly what would be
    affected and changes nothing. Run the preview first.
    """
    conn = None
    try:
        try:
            cutoff = datetime.strptime(before, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid 'before' date {before!r}; expected YYYY-MM-DD",
            )

        # A pooled connection's 120s statement_timeout is too short for the
        # table-wide aggregates and the archive copy; use a dedicated one.
        conn = get_maintenance_db_connection()
        cursor = conn.cursor()

        # Preview and execute report the same shape, so what the caller
        # approved is what they can compare the result against.
        cursor.execute(
            """
            SELECT COUNT(*), COUNT(DISTINCT device_id), COUNT(DISTINCT app_name),
                   MIN(date)::text, MAX(date)::text
            FROM usage_history
            WHERE date < %s
            """,
            (cutoff,),
        )
        row = cursor.fetchone() or (0, 0, 0, None, None)
        affected = {
            "rows": int(row[0] or 0),
            "devices": int(row[1] or 0),
            "applications": int(row[2] or 0),
            "earliestDate": row[3],
            "latestDate": row[4],
        }

        # What survives the reset, so the caller can see the resulting baseline
        # rather than inferring it.
        cursor.execute(
            "SELECT COUNT(*), MIN(date)::text, MAX(date)::text FROM usage_history WHERE date >= %s",
            (cutoff,),
        )
        kept = cursor.fetchone() or (0, None, None)
        remaining = {
            "rows": int(kept[0] or 0),
            "earliestDate": kept[1],
            "latestDate": kept[2],
        }

        if not confirm:
            conn.close()
            return {
                "status": "preview",
                "executed": False,
                "cutoffDate": str(cutoff),
                "wouldArchiveAndDelete": affected,
                "wouldRemain": remaining,
                "detail": "Nothing was changed. Re-send with confirm=true to execute.",
            }

        if affected["rows"] == 0:
            conn.close()
            return {
                "status": "ok",
                "executed": True,
                "cutoffDate": str(cutoff),
                "archived": 0,
                "deleted": 0,
                "remaining": remaining,
                "detail": "No rows before the cutoff; nothing to do.",
            }

        # Copy first, then delete, in one transaction: a failure between the
        # two would otherwise destroy rows with no archived copy.
        cursor.execute(
            """
            INSERT INTO usage_history_archive (
                id, device_id, date, app_name, publisher, launches,
                total_seconds, active_seconds, foreground_seconds, users,
                updated_at, reason
            )
            SELECT id, device_id, date, app_name, publisher, launches,
                   total_seconds, active_seconds, foreground_seconds, users,
                   updated_at, %s
            FROM usage_history
            WHERE date < %s
            """,
            (reason, cutoff),
        )
        archived = cursor.rowcount

        cursor.execute("DELETE FROM usage_history WHERE date < %s", (cutoff,))
        deleted = cursor.rowcount

        # Refuse to commit a partial copy rather than leave rows unrecoverable.
        if archived != deleted:
            conn.rollback()
            conn.close()
            raise HTTPException(
                status_code=500,
                detail=(
                    f"Archived {archived} rows but would delete {deleted}; "
                    "rolled back without changing anything."
                ),
            )

        conn.commit()
        conn.close()
        conn = None

        # The fleet usage endpoints cache their results; without this the
        # report keeps serving the pre-reset numbers.
        invalidate_caches()

        logger.warning(
            "usage_history baseline reset: archived and deleted %s rows before %s (reason=%r)",
            deleted, cutoff, reason,
        )

        return {
            "status": "ok",
            "executed": True,
            "cutoffDate": str(cutoff),
            "archived": archived,
            "deleted": deleted,
            "remaining": remaining,
        }

    except HTTPException:
        if conn is not None:
            try:
                conn.rollback()
                conn.close()
            except Exception:
                pass
        raise
    except Exception as e:
        if conn is not None:
            try:
                conn.rollback()
                conn.close()
            except Exception:
                pass
        logger.error(f"usage_history baseline reset failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/admin/usage-history/cleanup", dependencies=[Depends(verify_authentication)], tags=["admin"])
def cleanup_usage_history(
    months: int = Query(default=18, ge=1, le=36, description="Retain data for this many months")
):
    """
    Delete usage_history rows older than the specified retention period.
    Default retention: 18 months. Call via scheduled task or manually.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cutoff = datetime.now(timezone.utc) - timedelta(days=months * 30)
        cursor.execute("DELETE FROM usage_history WHERE date < %s", (cutoff.date(),))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        logger.info(f"Usage history cleanup: deleted {deleted} rows older than {cutoff.date()}")
        return {"deleted": deleted, "cutoffDate": str(cutoff.date()), "retentionMonths": months}
    except Exception as e:
        logger.error(f"Usage history cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def _clear_install_issue_fields(data) -> bool:
    """Blank the error/warning fields of one installs payload in place.

    Returns True when anything changed. Kept as a function so the cleanup
    endpoint and its tests exercise the same rules - a test that restates these
    conditions drifts from them silently, which is how the currentStatus half of
    this cleanup stayed broken once already.
    """
    if not isinstance(data, dict):
        return False

    modified = False

    error_statuses = {"error", "failed", "problem", "needs_reinstall", "install_failed"}
    # The fleet warning count keys on currentStatus, not on lastWarning, so a
    # cleared item left at "Warning" still counts. Reset it with the text.
    warning_statuses = {"warning"}

    for item in (data.get("cimian", {}) or {}).get("items", []) or []:
        if not isinstance(item, dict):
            continue
        has_error = bool((item.get("lastError") or "").strip())
        has_warning = bool((item.get("lastWarning") or "").strip())
        has_failure = (item.get("failureCount", 0) or 0) > 0
        has_warn_count = (item.get("warningCount", 0) or 0) > 0
        has_loop = item.get("installLoopDetected", False) or item.get("hasInstallLoop", False)
        status = (item.get("currentStatus") or "").lower()
        has_error_status = status in error_statuses
        has_warning_status = status in warning_statuses

        if (has_error or has_warning or has_failure or has_warn_count
                or has_loop or has_error_status or has_warning_status):
            item["lastError"] = ""
            item["lastWarning"] = ""
            item["failureCount"] = 0
            item["warningCount"] = 0
            item["installLoopDetected"] = False
            item["hasInstallLoop"] = False
            if has_error_status or has_warning_status:
                item["currentStatus"] = "Installed"
                if item.get("mappedStatus"):
                    item["mappedStatus"] = "Installed"
            modified = True

    munki = data.get("munki", {}) or {}
    if munki:
        for key in ("errors", "warnings", "problemInstalls"):
            value = munki.get(key)
            if isinstance(value, str) and value.strip():
                munki[key] = ""
                modified = True
            elif isinstance(value, list) and value:
                munki[key] = []
                modified = True
        for item in munki.get("items", []) or []:
            if not isinstance(item, dict):
                continue
            status = (item.get("status") or "").lower()
            cur = (item.get("currentStatus") or "").lower()
            if ((item.get("lastError") or "").strip() or (item.get("lastWarning") or "").strip()
                    or "fail" in status or "error" in status or "warning" in status
                    or cur in ("error", "warning")):
                item["lastError"] = ""
                item["lastWarning"] = ""
                if "fail" in status or "error" in status or "warning" in status:
                    item["status"] = "installed"
                if cur in ("error", "warning"):
                    item["currentStatus"] = "Installed"
                modified = True

    return modified


@router.delete("/admin/installs/clear-errors", dependencies=[Depends(verify_authentication)], tags=["admin"])
def clear_stale_installs_errors(
    days: int = Query(default=10, ge=0, le=365, description="Clear errors/warnings from devices that have not reported in this many days; 0 clears every device (they re-report their true state on the next check-in)")
):
    """
    Clear error and warning fields from installs data for stale devices.

    Targets devices that have not checked in (devices.last_seen) for the
    specified number of days. Clears per-item error/warning fields in Cimian data and
    error/warning strings in Munki data.

    This is a manual maintenance operation - not automated.

    **Authentication Required:**
    - Windows clients: X-API-PASSPHRASE header
    - Azure resources: X-MS-CLIENT-PRINCIPAL-ID header (Managed Identity)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # Stale means the device itself has not checked in. installs.updated_at
        # is touched on every ingest for every device, so keying on it matched
        # nothing in practice (0 of 300+ devices with dozens idle for weeks);
        # devices.last_seen is the check-in watermark the rest of the API uses.
        cursor.execute(
            """
            SELECT i.device_id, i.data
            FROM installs i
            JOIN devices d ON d.id = i.device_id
            WHERE COALESCE(d.last_seen, i.updated_at) < %s
            """,
            (cutoff,)
        )
        rows = cursor.fetchall()

        cleared_devices = []

        for device_id, data in rows:
            if not isinstance(data, dict):
                continue

            modified = False

            # Error/failed status values that the frontend flags as "Devices with Install Errors"
            modified = _clear_install_issue_fields(data)
            if modified:
                # The dashboard does not read this JSONB. It sums the
                # precomputed cimian_errors/cimian_warnings/munki_errors/
                # munki_warnings columns that ingest maintains, so rewriting
                # data alone cleared the record everywhere except the place
                # people actually look: /installs/full went clean while the
                # dashboard cards did not move at all. Recompute the counters
                # from the cleared payload with the same helper ingest uses, in
                # the same statement, so the two can never disagree.
                ce, cw, me, mw = _install_issue_counts(data)
                cursor.execute(
                    """
                    UPDATE installs
                    SET data = %s::jsonb,
                        cimian_errors = %s, cimian_warnings = %s,
                        munki_errors = %s, munki_warnings = %s
                    WHERE device_id = %s
                    """,
                    (json.dumps(data), ce, cw, me, mw, device_id)
                )
                cleared_devices.append(device_id)

        conn.commit()
        conn.close()

        if cleared_devices:
            invalidate_caches()

        logger.info(
            f"Installs error cleanup: cleared {len(cleared_devices)} devices "
            f"(checked {len(rows)} stale, cutoff {days} days)"
        )

        return {
            "success": True,
            "cleared": len(cleared_devices),
            "totalStale": len(rows),
            "days": days,
            "cutoffDate": cutoff.isoformat(),
            "clearedDevices": cleared_devices,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        logger.error(f"Installs error cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Installs error cleanup failed: {str(e)}")

@router.get("/debug/database", dependencies=[Depends(verify_authentication)], tags=["admin"])
def debug_database():
    """
    Database diagnostic endpoint - analyze storage usage and data cleanup opportunities.
    
    This endpoint helps identify:
    1. Duplicate records per device that should only have 1 row per module
    2. Orphaned records for devices that no longer exist
    3. Historical data retention issues
    4. Table bloat from dead tuples
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        diagnostics = {}
        
        # 1. Check for duplicate records in module tables (MAJOR ISSUE)
        module_tables = ['inventory', 'system', 'hardware', 'applications', 'network', 
                        'security', 'profiles', 'installs', 'management', 'displays', 'printers', 'peripherals', 'identity']
        duplicates = {}
        total_duplicate_rows = 0
        
        for table in module_tables:
            try:
                # Each device should have ONLY ONE record per module table
                cursor.execute(f"""
                    SELECT device_id, COUNT(*) as cnt 
                    FROM {table} 
                    GROUP BY device_id 
                    HAVING COUNT(*) > 1
                """)
                dups = cursor.fetchall()
                if dups:
                    device_count = len(dups)
                    total_rows = sum(d[1] for d in dups)
                    excess_rows = total_rows - device_count  # Should only be 1 per device
                    duplicates[table] = {
                        "devicesWithDuplicates": device_count,
                        "totalRows": total_rows,
                        "excessRows": excess_rows,
                        "topOffenders": [{"deviceId": d[0], "count": d[1]} for d in dups[:5]]
                    }
                    total_duplicate_rows += excess_rows
                else:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    total = cursor.fetchone()[0]
                    duplicates[table] = {
                        "devicesWithDuplicates": 0,
                        "totalRows": total,
                        "excessRows": 0
                    }
            except Exception as e:
                duplicates[table] = {"error": str(e)}
        
        diagnostics["duplicates"] = duplicates
        diagnostics["totalExcessRows"] = total_duplicate_rows
        
        # 2. Check for orphaned module records (device doesn't exist)
        orphaned = {}
        total_orphaned = 0
        for table in module_tables:
            try:
                cursor.execute(f"""
                    SELECT COUNT(*) 
                    FROM {table} m
                    LEFT JOIN devices d ON m.device_id = d.serial_number
                    WHERE d.serial_number IS NULL
                """)
                orphan_count = cursor.fetchone()[0]
                if orphan_count > 0:
                    orphaned[table] = orphan_count
                    total_orphaned += orphan_count
            except Exception:
                pass
        
        diagnostics["orphanedRecords"] = orphaned
        diagnostics["totalOrphanedRecords"] = total_orphaned
        
        # 3. Check events table - should we have retention policy?
        # Guarded like the per-table stages above: a slow scan degrades this
        # section instead of failing the whole diagnostic with a 500.
        try:
            cursor.execute("SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM events")
            event_row = cursor.fetchone()
            diagnostics["events"] = {
                "totalEvents": event_row[0],
                "oldestEvent": event_row[1].isoformat() if event_row[1] else None,
                "newestEvent": event_row[2].isoformat() if event_row[2] else None
            }
        except Exception as e:
            diagnostics["events"] = {"error": str(e)}
        
        # 4. Table sizes (guarded: degrade instead of 500 on slow stats)
        try:
            cursor.execute("""
            SELECT 
                relname,
                n_live_tup,
                n_dead_tup,
                pg_size_pretty(pg_total_relation_size(relid)) as total_size
            FROM pg_stat_user_tables 
            WHERE relname IN ('devices', 'events', 'inventory', 'system', 'hardware',
                             'applications', 'profiles', 'network', 'security',
                             'usage_history', 'usage_history_archive', 'installs',
                             'management', 'peripherals', 'identity')
            ORDER BY pg_total_relation_size(relid) DESC
        """)
            table_sizes = []
            for row in cursor.fetchall():
                table_sizes.append({
                    "table": row[0],
                    "liveRows": row[1],
                    "deadRows": row[2],
                    "totalSize": row[3]
                })
            diagnostics["tableSizes"] = table_sizes
        except Exception as e:
            diagnostics["tableSizes"] = {"error": str(e)}
        
        # 5. Cleanup recommendations
        recommendations = []
        if total_duplicate_rows > 0:
            recommendations.append(f"DELETE {total_duplicate_rows} duplicate rows from module tables (each device should have 1 record per module)")
        if total_orphaned > 0:
            recommendations.append(f"DELETE {total_orphaned} orphaned records (devices no longer exist)")
        
        diagnostics["recommendations"] = recommendations
        diagnostics["potentialStorageSavings"] = f"~{total_duplicate_rows + total_orphaned} records can be safely removed"
        
        conn.close()
        
        return {
            "database": "connected",
            "diagnostics": diagnostics,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Database diagnostic failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database diagnostic failed: {str(e)}")
