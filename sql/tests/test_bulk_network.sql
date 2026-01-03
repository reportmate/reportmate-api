-- Test wrapper for bulk_network.sql
-- Run in pgAdmin or any SQL client to test the query

-- Method 1: PREPARE/EXECUTE (closest to real parameterization)
PREPARE bulk_network_query(boolean) AS
SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    n.data as network_data,
    n.collected_at,
    inv.data->>'deviceName' as device_name,
    inv.data->>'computerName' as computer_name,
    inv.data->>'usage' as usage,
    inv.data->>'catalog' as catalog,
    inv.data->>'location' as location,
    inv.data->>'assetTag' as asset_tag,
    sys.data->'operatingSystem'->>'name' as os_name,
    sys.data->'operatingSystem'->>'version' as os_version,
    sys.data->'operatingSystem'->>'buildNumber' as build_number,
    sys.data->>'uptime' as uptime,
    sys.data->>'bootTime' as boot_time
FROM devices d
LEFT JOIN network n ON d.id = n.device_id
LEFT JOIN inventory inv ON d.id = inv.device_id
LEFT JOIN system sys ON d.id = sys.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%'
    AND d.serial_number != 'localhost'
    AND n.data IS NOT NULL
    AND ($1 OR d.archived = FALSE)
ORDER BY d.serial_number, n.updated_at DESC;

-- Test: Exclude archived devices (default behavior)
EXECUTE bulk_network_query(false);

-- Test: Include archived devices
-- EXECUTE bulk_network_query(true);

-- Cleanup
DEALLOCATE bulk_network_query;
