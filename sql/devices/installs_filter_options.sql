-- Extract unique install item names, inventory values, and config metadata
-- Used by /api/devices/installs/filters to avoid downloading all records
-- Parameters: include_archived (boolean)
--
-- Returns one row per device with:
--   - serial_number, device_name, usage, catalog, location, fleet, platform
--   - installs_data JSONB (needed to extract item names and config in Python)

SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    COALESCE(inv.data->>'device_name', inv.data->>'deviceName', d.serial_number) as device_name,
    inv.data->>'usage' as usage,
    inv.data->>'catalog' as catalog,
    inv.data->>'location' as location,
    COALESCE(inv.data->>'asset_tag', inv.data->>'assetTag') as asset_tag,
    inv.data->>'fleet' as fleet,
    COALESCE(sys.data->'operatingSystem'->>'platform', inv.data->>'platform') as platform,
    i.data as installs_data,
    d.last_seen
FROM devices d
LEFT JOIN installs i ON d.id = i.device_id
LEFT JOIN inventory inv ON d.id = inv.device_id
LEFT JOIN system sys ON d.id = sys.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND i.data IS NOT NULL
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY d.serial_number, i.updated_at DESC;
