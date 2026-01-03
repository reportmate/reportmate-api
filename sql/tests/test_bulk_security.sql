-- Test wrapper for bulk_security.sql
-- Run in pgAdmin or any SQL client to test the query

-- Method 1: PREPARE/EXECUTE (closest to real parameterization)
PREPARE bulk_security_query(boolean) AS
SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    sec.data as security_data,
    sec.collected_at,
    inv.data->>'deviceName' as device_name,
    inv.data->>'computerName' as computer_name,
    inv.data->>'usage' as usage,
    inv.data->>'catalog' as catalog,
    inv.data->>'location' as location,
    inv.data->>'assetTag' as asset_tag
FROM devices d
LEFT JOIN security sec ON d.id = sec.device_id
LEFT JOIN inventory inv ON d.id = inv.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%'
    AND d.serial_number != 'localhost'
    AND sec.data IS NOT NULL
    AND ($1 OR d.archived = FALSE)
ORDER BY d.serial_number, sec.updated_at DESC;

-- Test: Exclude archived devices (default behavior)
EXECUTE bulk_security_query(false);

-- Test: Include archived devices
-- EXECUTE bulk_security_query(true);

-- Cleanup
DEALLOCATE bulk_security_query;
