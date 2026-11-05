SELECT jsonb_build_object(
    'serialNumber', d.serial_number,
    'deviceName', COALESCE(inv.data->>'deviceName', inv.data->>'device_name', d.name, d.serial_number),
    'hostname', COALESCE(sys.data->'operatingSystem'->>'computerName', sys.data->'operatingSystem'->>'hostname', net.data->>'hostname', inv.data->>'computerName', inv.data->>'computer_name'),
    'platform', COALESCE(sys.data->'operatingSystem'->>'name', d.platform),
    'osVersion', COALESCE(sys.data->'operatingSystem'->>'displayVersion', sys.data->'operatingSystem'->>'version'),
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
    'collectedAt', COALESCE(sys.data->>'collectedAt', sys.data->>'collected_at', sys.collected_at::text),
    'pendingWindowsUpdates', COALESCE(sys.data->'pendingWindowsUpdates', sys.data->'pending_windows_updates'),
    'pendingWindowsUpdatesCount', COALESCE(sys.data->'pendingWindowsUpdatesCount', sys.data->'pending_windows_updates_count'),
    'installedUpdates', sys.data->'updates',
    'pendingAppleUpdates', COALESCE(sys.data->'pendingAppleUpdates', sys.data->'pending_apple_updates'),
    'updateSearch', COALESCE(sys.data->'updateSearch', sys.data->'update_search')
)
FROM devices d
LEFT JOIN system sys ON sys.device_id = d.serial_number
LEFT JOIN inventory inv ON inv.device_id = d.serial_number
LEFT JOIN network net ON net.device_id = d.serial_number
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
ORDER BY lower(COALESCE(inv.data->>'deviceName', inv.data->>'device_name', d.name, d.serial_number)), d.serial_number;
