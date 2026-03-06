-- Lightweight device list for applications filters endpoint
-- Returns only device metadata (no application data) for "missing" report mode
-- Parameters: include_archived (boolean)

SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    COALESCE(inv.data->>'device_name', inv.data->>'deviceName', d.serial_number) as device_name,
    inv.data->>'usage' as usage,
    inv.data->>'catalog' as catalog,
    inv.data->>'location' as location
FROM devices d
LEFT JOIN inventory inv ON d.id = inv.device_id
JOIN applications a ON d.id = a.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND a.data IS NOT NULL
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY d.serial_number;
