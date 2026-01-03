-- Bulk peripherals endpoint: /api/devices/peripherals
-- Returns devices with connected peripherals (displays, printers, USB devices, etc.)
-- Parameters: include_archived (boolean)
-- Note: Combines displays and printers data into unified peripherals view

SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    disp.data as displays_data,
    print.data as printers_data,
    -- Use COALESCE to handle NULL values from LEFT JOINs
    GREATEST(
        COALESCE(disp.collected_at, '1970-01-01'::timestamp),
        COALESCE(print.collected_at, '1970-01-01'::timestamp)
    ) as collected_at,
    inv.data->>'deviceName' as device_name,
    inv.data->>'computerName' as computer_name,
    inv.data->>'usage' as usage,
    inv.data->>'catalog' as catalog,
    inv.data->>'location' as location,
    inv.data->>'assetTag' as asset_tag
FROM devices d
LEFT JOIN displays disp ON d.id = disp.device_id
LEFT JOIN printers print ON d.id = print.device_id
LEFT JOIN inventory inv ON d.id = inv.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND (disp.data IS NOT NULL OR print.data IS NOT NULL)
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
-- Use COALESCE to handle NULL values in ORDER BY
ORDER BY d.serial_number, GREATEST(
    COALESCE(disp.updated_at, '1970-01-01'::timestamp),
    COALESCE(print.updated_at, '1970-01-01'::timestamp)
) DESC;
