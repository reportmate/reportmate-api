-- Test wrapper for bulk_hardware.sql
-- Run in pgAdmin or any SQL client to test the query
-- 
-- Usage:
--   1. PREPARE + EXECUTE (recommended for testing parameterization)
--   2. Or use the raw query with substituted values below

-- Method 1: PREPARE/EXECUTE (closest to real parameterization)
PREPARE bulk_hardware_query(boolean) AS
SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    h.data as hardware_data,
    h.collected_at,
    s.data as system_data,
    COALESCE(inv.data->>'device_name', inv.data->>'deviceName') as device_name,
    COALESCE(inv.data->>'computer_name', inv.data->>'computerName') as computer_name
FROM devices d
LEFT JOIN hardware h ON d.id = h.device_id
LEFT JOIN system s ON d.id = s.device_id
LEFT JOIN inventory inv ON d.id = inv.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%'
    AND h.data IS NOT NULL
    AND ($1 OR d.archived = FALSE)
ORDER BY d.serial_number, h.updated_at DESC;

-- Test: Exclude archived devices (default behavior)
EXECUTE bulk_hardware_query(false);

-- Test: Include archived devices
-- EXECUTE bulk_hardware_query(true);

-- Cleanup
DEALLOCATE bulk_hardware_query;


-- Method 2: Raw query with hardcoded values (for quick testing)
-- Uncomment and run directly:
/*
SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    h.data as hardware_data,
    h.collected_at,
    s.data as system_data,
    COALESCE(inv.data->>'device_name', inv.data->>'deviceName') as device_name,
    COALESCE(inv.data->>'computer_name', inv.data->>'computerName') as computer_name
FROM devices d
LEFT JOIN hardware h ON d.id = h.device_id
LEFT JOIN system s ON d.id = s.device_id
LEFT JOIN inventory inv ON d.id = inv.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%'
    AND h.data IS NOT NULL
    AND d.archived = FALSE  -- Change to TRUE to include archived
ORDER BY d.serial_number, h.updated_at DESC;
*/
