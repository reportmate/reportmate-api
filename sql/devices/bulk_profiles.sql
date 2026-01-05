-- Bulk profiles endpoint: /api/devices/profiles
-- Returns devices with MDM profiles and configuration data
-- Parameters: include_archived (boolean)

SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    p.data as profiles_data,
    p.collected_at as profiles_collected_at,
    p.updated_at as profiles_updated_at,
    COALESCE(inv.data->>'device_name', inv.data->>'deviceName') as device_name,
    COALESCE(inv.data->>'computer_name', inv.data->>'computerName') as computer_name,
    inv.data->>'usage' as usage,
    inv.data->>'catalog' as catalog,
    inv.data->>'location' as location,
    COALESCE(inv.data->>'asset_tag', inv.data->>'assetTag') as asset_tag
FROM devices d
LEFT JOIN profiles p ON d.id = p.device_id
LEFT JOIN inventory inv ON d.id = inv.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND p.data IS NOT NULL
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY d.serial_number, p.updated_at DESC;
