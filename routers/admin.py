"""Administrative operations: archive, unarchive, delete devices, diagnostics."""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from dependencies import (
    get_db_connection, invalidate_caches, load_sql, logger,
    verify_authentication,
)

router = APIRouter(tags=["admin"])

@router.patch("/device/{serial_number}/archive", dependencies=[Depends(verify_authentication)], tags=["devices"])
async def archive_device(serial_number: str):
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
async def unarchive_device(serial_number: str):
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
async def delete_device(serial_number: str, confirm: bool = Query(False)):
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
        
        logger.warning(f"🗑️ DELETED device: {serial_number} (UUID: {device_uuid}, Name: {device_name})")
        logger.warning(f"   - Archived status: {is_archived}")
        logger.warning(f"   - Events deleted: {event_count}")
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

@router.delete("/admin/usage-history/cleanup", dependencies=[Depends(verify_authentication)], tags=["admin"])
async def cleanup_usage_history(
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

@router.get("/debug/database", dependencies=[Depends(verify_authentication)], tags=["admin"])
async def debug_database():
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
        cursor.execute("SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM events")
        event_row = cursor.fetchone()
        diagnostics["events"] = {
            "totalEvents": event_row[0],
            "oldestEvent": event_row[1].isoformat() if event_row[1] else None,
            "newestEvent": event_row[2].isoformat() if event_row[2] else None
        }
        
        # 4. Table sizes
        cursor.execute("""
            SELECT 
                relname,
                n_live_tup,
                n_dead_tup,
                pg_size_pretty(pg_total_relation_size(relid)) as total_size
            FROM pg_stat_user_tables 
            WHERE relname IN ('devices', 'events', 'inventory', 'system', 'hardware', 
                             'applications', 'profiles', 'network', 'security')
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
