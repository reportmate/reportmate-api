-- Fleet threat detection rows: /api/v1/security/detections
-- One row per device that matches the scope, with its collected detections
-- array as reported (Windows clients send Defender detections; macOS clients
-- send none). A device without the array still returns a row so coverage can
-- be counted.
-- Parameters: include_archived (boolean), platform ('' | 'windows' | 'macos').

SELECT jsonb_build_object(
    'serialNumber', d.serial_number,
    'deviceName', COALESCE(inv.data->>'deviceName', inv.data->>'device_name', d.name, d.serial_number),
    'platform', COALESCE(sys.data->'operatingSystem'->>'name', d.platform),
    'assetTag', COALESCE(inv.data->>'assetTag', inv.data->>'asset_tag'),
    'usage', inv.data->>'usage',
    'catalog', inv.data->>'catalog',
    'area', inv.data->>'department',
    'fleet', inv.data->>'fleet',
    'location', inv.data->>'location',
    'room', COALESCE(inv.data->>'room', inv.data->>'location'),
    'archived', d.archived,
    'inventoryState', ist.state,
    'lastSeen', d.last_seen,
    'collectedAt', COALESCE(sec.data->>'collectedAt', sec.data->>'collected_at', sec.collected_at::text),
    'hasSecurity', sec.device_id IS NOT NULL,
    'detections', CASE WHEN jsonb_typeof(sec.data->'detections') = 'array' THEN sec.data->'detections' END
)
FROM devices d
LEFT JOIN security sec ON sec.device_id = d.serial_number
LEFT JOIN system sys ON sys.device_id = d.serial_number
LEFT JOIN inventory inv ON inv.device_id = d.serial_number
LEFT JOIN device_inventory_state ist ON ist.serial_number = upper(trim(d.serial_number))
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
    AND (
        %(platform)s = ''
        OR CASE
            WHEN lower(COALESCE(sys.data->'operatingSystem'->>'name', d.platform, '')) LIKE '%%windows%%' THEN 'windows'
            WHEN lower(COALESCE(sys.data->'operatingSystem'->>'name', d.platform, '')) LIKE '%%mac%%'
                OR lower(COALESCE(sys.data->'operatingSystem'->>'name', d.platform, '')) LIKE '%%darwin%%' THEN 'macos'
            ELSE lower(COALESCE(sys.data->'operatingSystem'->>'name', d.platform, ''))
        END = %(platform)s
    )
ORDER BY d.serial_number;
