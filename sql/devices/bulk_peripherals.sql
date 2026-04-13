-- Bulk peripherals endpoint: /api/devices/peripherals
-- Returns devices with connected peripherals (USB, input devices, audio, Bluetooth, cameras, etc.)
-- Parameters: include_archived (boolean)
--
-- JOIN note: peripherals.device_id holds the device serial_number (per ingestion in events.py).
-- Earlier versions of this query joined on d.id = p.device_id, which silently missed every
-- Mac row because d.id on Mac records is the UUID while p.device_id is the serial. Always
-- join via d.serial_number so the match is consistent across both platforms.

SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    p.data as peripherals_data,
    p.collected_at,
    COALESCE(inv.data->>'device_name', inv.data->>'deviceName') as device_name,
    COALESCE(inv.data->>'computer_name', inv.data->>'computerName') as computer_name,
    inv.data->>'usage' as usage,
    inv.data->>'catalog' as catalog,
    inv.data->>'location' as location,
    COALESCE(inv.data->>'asset_tag', inv.data->>'assetTag') as asset_tag,
    COALESCE(
        sys.data->'operating_system'->>'name',
        sys.data->'operatingSystem'->>'name',
        inv.data->>'platform'
    ) as platform
FROM devices d
LEFT JOIN peripherals p ON p.device_id = d.serial_number
LEFT JOIN inventory inv ON inv.device_id = d.serial_number
LEFT JOIN system sys ON sys.device_id = d.serial_number
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND p.data IS NOT NULL
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY d.serial_number, p.updated_at DESC;
