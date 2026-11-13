SELECT jsonb_build_object(
    'serialNumber', serial_number, 'deviceName', device_name, 'hostname', hostname,
    'platform', platform, 'assetTag', asset_tag, 'usage', usage, 'catalog', catalog,
    'area', area, 'fleet', fleet, 'location', location, 'room', room,
    'archived', archived, 'inventoryState', inventory_state, 'lastSeen', last_seen,
    'collectedAt', collected_at, 'platformKey', platform_key,
    'inventoryAvailable', COALESCE(jsonb_typeof(system_data->'binaries') = 'array', FALSE),
    'items', COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'kind', 'binary', 'key', lower(b->>'name'), 'name', lower(b->>'name'),
            'category', NULLIF(b->>'category', ''), 'path', NULLIF(b->>'path', ''),
            'resolvedPath', NULLIF(b->>'resolvedPath', ''),
            'version', NULLIF(b->>'version', ''), 'versionString', NULLIF(b->>'versionString', ''),
            'versionSource', NULLIF(b->>'versionSource', ''),
            'source', NULLIF(b->>'source', ''), 'package', NULLIF(b->>'package', ''),
            'packageVersion', NULLIF(b->>'packageVersion', ''), 'publisher', NULLIF(b->>'publisher', ''),
            'running', b->'running', 'processCount', b->'processCount',
            'serviceName', NULLIF(b->>'serviceName', '')))
        FROM jsonb_array_elements(CASE WHEN jsonb_typeof(system_data->'binaries') = 'array'
            THEN system_data->'binaries' ELSE '[]'::jsonb END) b
        WHERE jsonb_typeof(b) = 'object' AND COALESCE(b->>'name', '') != '' AND (
            lower(b->>'name') = ANY(%(binary_keys)s::text[])
            OR lower(COALESCE(b->>'category', '')) = ANY(%(categories)s::text[])
            OR (%(running_only)s AND b->>'running' = 'true'))
    ), '[]'::jsonb)
)
FROM scoped
ORDER BY lower(device_name), serial_number;
