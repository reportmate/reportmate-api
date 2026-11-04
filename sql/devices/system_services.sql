SELECT jsonb_build_object(
    'serialNumber', d.serial_number,
    'deviceName', COALESCE(inv.data->>'deviceName', inv.data->>'device_name', d.name, d.serial_number),
    'hostname', COALESCE(sys.data->'operatingSystem'->>'computerName', sys.data->'operatingSystem'->>'hostname', net.data->>'hostname', inv.data->>'computerName', inv.data->>'computer_name'),
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
    'collectedAt', COALESCE(sys.data->>'collectedAt', sys.data->>'collected_at', sys.collected_at::text),
    'applicationsCollectedAt', COALESCE(app.data->>'collectedAt', app.data->>'collected_at', app.collected_at::text),
    'serviceInventoryCount', CASE WHEN jsonb_typeof(sys.data->'services') = 'array'
        THEN jsonb_array_length(sys.data->'services') ELSE 0 END,
    'serviceInventoryAvailable', jsonb_typeof(sys.data->'services') = 'array'
        AND jsonb_array_length(CASE WHEN jsonb_typeof(sys.data->'services') = 'array'
            THEN sys.data->'services' ELSE '[]'::jsonb END) > 0
        AND NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(sys.data->'services') = 'array'
                THEN sys.data->'services' ELSE '[]'::jsonb END) entry
            WHERE jsonb_typeof(entry) != 'object'
                OR COALESCE(NULLIF(entry->>'name', ''), NULLIF(entry->>'label', ''), NULLIF(entry->>'displayName', '')) IS NULL
        ),
    'services', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
            'name', COALESCE(s->>'name', s->>'label'),
            'displayName', COALESCE(s->>'displayName', s->>'display_name', s->>'label'),
            'status', s->>'status',
            'startType', COALESCE(s->>'startType', s->>'start_type'),
            'path', COALESCE(s->>'path', s->>'program'),
            'type', s->>'type',
            'onDemand', COALESCE(s->'onDemand', s->'on_demand'),
            'disabled', s->'disabled'
        ) ORDER BY COALESCE(s->>'name', s->>'label'))
        FROM jsonb_array_elements(CASE WHEN jsonb_typeof(sys.data->'services') = 'array'
            THEN sys.data->'services' ELSE '[]'::jsonb END) s
        WHERE %(service)s != '' AND (
            strpos(lower(COALESCE(s->>'name', s->>'label', '')), %(service)s) > 0
            OR strpos(lower(COALESCE(s->>'displayName', s->>'display_name', '')), %(service)s) > 0
            OR strpos(lower(COALESCE(s->>'path', s->>'program', '')), %(service)s) > 0
        )
    ), '[]'::jsonb),
    'applications', COALESCE((
        SELECT jsonb_agg(DISTINCT jsonb_build_object(
            'name', COALESCE(a->>'name', a->>'displayName'),
            'version', COALESCE(a->>'version', a->>'bundle_version'),
            'path', a->>'path'
        ))
        FROM jsonb_array_elements(CASE
            WHEN jsonb_typeof(app.data) = 'array' THEN app.data
            WHEN jsonb_typeof(app.data->'installedApplications') = 'array' THEN app.data->'installedApplications'
            WHEN jsonb_typeof(app.data->'InstalledApplications') = 'array' THEN app.data->'InstalledApplications'
            WHEN jsonb_typeof(app.data->'installed_applications') = 'array' THEN app.data->'installed_applications'
            ELSE '[]'::jsonb END) a
        WHERE %(application)s != ''
            AND strpos(lower(COALESCE(a->>'name', a->>'displayName', '')), %(application)s) > 0
    ), '[]'::jsonb)
)
FROM devices d
LEFT JOIN system sys ON sys.device_id = d.serial_number
LEFT JOIN applications app ON app.device_id = d.serial_number
LEFT JOIN inventory inv ON inv.device_id = d.serial_number
LEFT JOIN network net ON net.device_id = d.serial_number
LEFT JOIN device_inventory_state ist ON ist.serial_number = upper(trim(d.serial_number))
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY lower(COALESCE(inv.data->>'deviceName', inv.data->>'device_name', d.name, d.serial_number)), d.serial_number;
