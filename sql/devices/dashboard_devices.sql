-- Dashboard devices query
-- Fetches all devices with inventory data for dashboard display
-- Parameters:
--   %(include_archived)s: boolean - whether to include archived devices

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
    i.data as inventory_data
FROM devices d
LEFT JOIN inventory i ON d.serial_number = i.device_id
WHERE (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY d.last_seen DESC NULLS LAST
