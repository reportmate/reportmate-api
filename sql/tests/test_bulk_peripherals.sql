-- Test wrapper for bulk_peripherals.sql
-- Run in pgAdmin or any SQL client to test the query

-- Method 1: PREPARE/EXECUTE (closest to real parameterization)
PREPARE bulk_peripherals_query(boolean) AS
SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    disp.data as displays_data,
    print.data as printers_data,
    GREATEST(disp.collected_at, print.collected_at) as collected_at,
    inv.data->>'deviceName' as device_name,
    inv.data->>'computerName' as computer_name,
    inv.data->>'usage' as usage,
    inv.data->>'catalog' as catalog,
    inv.data->>'location' as location,
    inv.data->>'assetTag' as asset_tag
FROM devices d
LEFT JOIN displays disp ON d.id = disp.device_id
LEFT JOIN printers print ON d.id = print.device_id
LEFT JOIN inventory inv ON d.id = inv.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%'
    AND d.serial_number != 'localhost'
    AND (disp.data IS NOT NULL OR print.data IS NOT NULL)
    AND ($1 OR d.archived = FALSE)
ORDER BY d.serial_number, GREATEST(disp.updated_at, print.updated_at) DESC;

-- Test: Exclude archived devices (default behavior)
EXECUTE bulk_peripherals_query(false);

-- Test: Include archived devices
-- EXECUTE bulk_peripherals_query(true);

-- Cleanup
DEALLOCATE bulk_peripherals_query;
