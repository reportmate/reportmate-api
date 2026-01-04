-- Bulk installs endpoint: /api/devices/installs
-- Returns flattened list of managed installs across all devices
-- Parameters: include_archived (boolean)

SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    i.data as installs_data,
    i.collected_at,
    COALESCE(inv.data->>'device_name', inv.data->>'deviceName') as device_name,
    COALESCE(inv.data->>'computer_name', inv.data->>'computerName') as computer_name,
    inv.data->>'usage' as usage,
    inv.data->>'catalog' as catalog,
    inv.data->>'location' as location,
    COALESCE(inv.data->>'asset_tag', inv.data->>'assetTag') as asset_tag,
    inv.data->>'fleet' as fleet,
    inv.data->>'platform' as platform
FROM devices d
LEFT JOIN installs i ON d.id = i.device_id
LEFT JOIN inventory inv ON d.id = inv.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND i.data IS NOT NULL
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY d.serial_number, i.updated_at DESC;
