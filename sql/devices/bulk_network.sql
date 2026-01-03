-- Bulk network endpoint: /api/devices/network
-- Returns devices with network configuration data (interfaces, IPs, MACs, DNS, etc.)
-- Parameters: include_archived (boolean)

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
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND n.data IS NOT NULL
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY d.serial_number, n.updated_at DESC;
