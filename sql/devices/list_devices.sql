-- List all devices with lightweight module payloads
-- Parameters:
--   %(include_archived)s: boolean - whether to include archived devices
--   %(limit)s: integer or NULL - maximum devices to return
--   %(offset)s: integer - pagination offset

SELECT 
    d.id,
    d.device_id,
    d.serial_number,
    d.name,
    d.os,
    d.os_name,
    d.os_version,
    d.last_seen,
    d.archived,
    d.created_at,
    i.data as inventory_data,
    s.data as system_data
FROM devices d
LEFT JOIN inventory i ON d.serial_number = i.device_id
LEFT JOIN system s ON d.serial_number = s.device_id
WHERE (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY d.last_seen DESC NULLS LAST
LIMIT %(limit)s
OFFSET %(offset)s
