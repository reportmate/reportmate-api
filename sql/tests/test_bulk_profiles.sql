-- Test wrapper for bulk_profiles.sql
-- Run in pgAdmin or any SQL client to test the query

-- Method 1: PREPARE/EXECUTE (closest to real parameterization)
PREPARE bulk_profiles_query(boolean) AS
SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    p.metadata as profiles_metadata,
    p.intune_policy_hashes,
    p.security_policy_hashes,
    p.mdm_policy_hashes,
    p.updated_at as profiles_updated_at,
    inv.data->>'deviceName' as device_name,
    inv.data->>'computerName' as computer_name,
    inv.data->>'usage' as usage,
    inv.data->>'catalog' as catalog,
    inv.data->>'location' as location,
    inv.data->>'assetTag' as asset_tag
FROM devices d
LEFT JOIN profiles p ON d.serial_number = p.device_id
LEFT JOIN inventory inv ON d.serial_number = inv.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%'
    AND d.serial_number != 'localhost'
    AND p.device_id IS NOT NULL
    AND ($1 OR d.archived = FALSE)
ORDER BY d.serial_number, p.updated_at DESC;

-- Test: Exclude archived devices (default behavior)
EXECUTE bulk_profiles_query(false);

-- Test: Include archived devices
-- EXECUTE bulk_profiles_query(true);

-- Cleanup
DEALLOCATE bulk_profiles_query;
