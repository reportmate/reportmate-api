-- Bulk identity endpoint: /api/devices/identity
-- Returns devices with identity data (users, groups, sessions, BTMDB health, directory services)
-- Parameters: include_archived (boolean)

SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    d.platform,
    ident.data as identity_data,
    ident.collected_at,
    COALESCE(inv.data->>'device_name', inv.data->>'deviceName') as device_name,
    COALESCE(inv.data->>'computer_name', inv.data->>'computerName') as computer_name,
    inv.data->>'usage' as usage,
    inv.data->>'catalog' as catalog,
    inv.data->>'location' as location,
    COALESCE(inv.data->>'asset_tag', inv.data->>'assetTag') as asset_tag,
    inv.data->>'department' as department
FROM devices d
LEFT JOIN identity ident ON d.serial_number = ident.device_id
LEFT JOIN inventory inv ON d.serial_number = inv.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND ident.data IS NOT NULL
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY d.serial_number, ident.updated_at DESC;
