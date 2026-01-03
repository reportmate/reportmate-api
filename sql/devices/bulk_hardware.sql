-- Bulk hardware endpoint: /api/devices/hardware
-- Returns flattened list of hardware details across all devices
-- Parameters: include_archived (boolean)

SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    h.data as hardware_data,
    h.collected_at,
    s.data as system_data,
    inv.data->>'deviceName' as device_name,
    inv.data->>'computerName' as computer_name
FROM devices d
LEFT JOIN hardware h ON d.id = h.device_id
LEFT JOIN system s ON d.id = s.device_id
LEFT JOIN inventory inv ON d.id = inv.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND h.data IS NOT NULL
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY d.serial_number, h.updated_at DESC;
