-- Test wrapper for bulk_management.sql
-- Run in pgAdmin or any SQL client to test the query

-- Method 1: PREPARE/EXECUTE (closest to real parameterization)
PREPARE bulk_management_query(boolean) AS
SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    m.data as management_data,
    m.collected_at,
    inv.data->>'deviceName' as device_name,
    inv.data->>'computerName' as computer_name,
    inv.data->>'usage' as usage,
    inv.data->>'catalog' as catalog,
    inv.data->>'location' as location,
    inv.data->>'assetTag' as asset_tag,
    inv.data->>'department' as department
FROM devices d
LEFT JOIN management m ON d.id = m.device_id
LEFT JOIN inventory inv ON d.id = inv.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%'
    AND d.serial_number != 'localhost'
    AND m.data IS NOT NULL
    AND ($1 OR d.archived = FALSE)
ORDER BY d.serial_number, m.updated_at DESC;

-- Test: Exclude archived devices (default behavior)
EXECUTE bulk_management_query(false);

-- Test: Include archived devices
-- EXECUTE bulk_management_query(true);

-- Cleanup
DEALLOCATE bulk_management_query;
