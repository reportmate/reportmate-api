SELECT jsonb_build_object(
    'serialNumber', serial_number, 'deviceName', device_name, 'hostname', hostname,
    'platform', platform, 'assetTag', asset_tag, 'usage', usage, 'catalog', catalog,
    'area', area, 'fleet', fleet, 'location', location, 'room', room,
    'archived', archived, 'inventoryState', inventory_state, 'lastSeen', last_seen,
    'collectedAt', collected_at, 'platformKey', platform_key,
    'inventoryAvailable', jsonb_typeof(system_data->'systemExtensions') = 'array'
        OR jsonb_typeof(system_data->'privilegedHelperTools') = 'array',
    'items', COALESCE((SELECT jsonb_agg(item) FROM (
        SELECT jsonb_build_object(
            'kind', 'systemExtension', 'key', e->>'identifier', 'name', e->>'identifier',
            'version', NULLIF(e->>'version', ''), 'state', NULLIF(e->>'state', ''),
            'teamId', NULLIF(e->>'teamId', ''), 'type', NULLIF(e->>'type', ''),
            'category', NULLIF(COALESCE(e->>'extensionCategory', e->>'category'), ''),
            'appName', NULLIF(e->>'appName', ''), 'path', NULLIF(e->>'bundlePath', ''),
            'managedByProfile', COALESCE(e->'managedByProfile', e->'managed_by_profile')
        ) AS item
        FROM jsonb_array_elements(CASE WHEN platform_key = 'macos' AND jsonb_typeof(system_data->'systemExtensions') = 'array'
            THEN system_data->'systemExtensions' ELSE '[]'::jsonb END) e
        WHERE jsonb_typeof(e) = 'object' AND (
            lower(COALESCE(e->>'identifier', '')) = ANY(%(system_keys)s::text[])
            OR lower(COALESCE(e->>'teamId', '')) = ANY(%(team_ids)s::text[])
            OR (%(not_activated)s AND COALESCE(e->>'state', '') NOT IN ('', 'activated_enabled', 'enabled')))
        UNION ALL
        SELECT jsonb_build_object(
            'kind', 'kernelExtension', 'key', k->>'name', 'name', k->>'name',
            'version', NULLIF(k->>'version', ''), 'loaded', k->'loaded', 'path', NULLIF(k->>'path', '')
        )
        FROM jsonb_array_elements(CASE WHEN platform_key = 'macos' AND jsonb_typeof(system_data->'kernelExtensions') = 'array'
            THEN system_data->'kernelExtensions' ELSE '[]'::jsonb END) k
        WHERE jsonb_typeof(k) = 'object' AND lower(COALESCE(k->>'name', '')) = ANY(%(kernel_keys)s::text[])
        UNION ALL
        SELECT jsonb_build_object(
            'kind', 'helper', 'key', h->>'name', 'name', h->>'name',
            'bundleId', NULLIF(split_part(COALESCE(h->>'bundleIdentifier', h->>'bundleId', ''), E'\n', 1), ''),
            'teamId', NULLIF(h->>'teamId', ''), 'signed', h->'signed', 'path', NULLIF(h->>'path', ''),
            'modifiedDate', NULLIF(h->>'modifiedDate', '')
        )
        FROM jsonb_array_elements(CASE WHEN platform_key = 'macos' AND jsonb_typeof(system_data->'privilegedHelperTools') = 'array'
            THEN system_data->'privilegedHelperTools' ELSE '[]'::jsonb END) h
        WHERE jsonb_typeof(h) = 'object' AND (
            lower(COALESCE(h->>'name', '')) = ANY(%(helper_keys)s::text[])
            OR lower(COALESCE(h->>'teamId', '')) = ANY(%(team_ids)s::text[])
            OR (%(unsigned)s AND h->'signed' IS NOT NULL AND h->>'signed' IN ('0', 'false')))
    ) matched), '[]'::jsonb)
)
FROM scoped
WHERE platform_key = 'macos'
ORDER BY lower(device_name), serial_number;
