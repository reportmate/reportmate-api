-- Bulk system endpoint: /api/devices/system
-- Returns devices with OS details, uptime, updates, services, etc.
-- Parameters: include_archived (boolean)
-- Note: Returns every matching device. limit/offset are applied to the cached
-- result in the handler, the same way the other bulk endpoints do it. Applying
-- LIMIT here as well truncated the row set before the handler's offset could
-- reach past it, so any page after the first came back empty.

SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    s.data as system_data,
    s.collected_at,
    COALESCE(inv.data->>'device_name', inv.data->>'deviceName') as device_name,
    COALESCE(inv.data->>'computer_name', inv.data->>'computerName') as computer_name,
    inv.data->>'usage' as usage,
    inv.data->>'catalog' as catalog,
    inv.data->>'location' as location,
    COALESCE(inv.data->>'asset_tag', inv.data->>'assetTag') as asset_tag,
    inv.data->>'department' as department,
    inv.data->>'fleet' as fleet
FROM devices d
LEFT JOIN system s ON d.serial_number = s.device_id
LEFT JOIN inventory inv ON d.serial_number = inv.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND s.data IS NOT NULL
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY d.serial_number, s.updated_at DESC;
