SELECT jsonb_build_object(
    'serialNumber', serial_number, 'deviceName', device_name, 'hostname', hostname,
    'platform', platform, 'assetTag', asset_tag, 'usage', usage, 'catalog', catalog,
    'area', area, 'fleet', fleet, 'location', location, 'room', room,
    'archived', archived, 'inventoryState', inventory_state, 'lastSeen', last_seen,
    'collectedAt', collected_at, 'platformKey', platform_key,
    'inventoryAvailable', jsonb_typeof(system_data->'scheduledTasks') = 'array',
    'items', COALESCE((SELECT jsonb_agg(item) FROM (
        SELECT jsonb_build_object(
            'kind', 'task', 'key', t->>'path', 'name', t->>'name', 'path', t->>'path',
            'enabled', t->'enabled', 'state', COALESCE(t->>'state', t->>'status'),
            'hidden', t->'hidden', 'action', t->>'action',
            'lastRunTime', COALESCE(t->>'lastRunTime', t->>'last_run_time'),
            'nextRunTime', COALESCE(t->>'nextRunTime', t->>'next_run_time'),
            'lastRunCode', COALESCE(t->>'lastRunCode', t->>'last_run_code'),
            'lastRunMessage', COALESCE(t->>'lastRunMessage', t->>'last_run_message')
        ) AS item
        FROM jsonb_array_elements(CASE WHEN platform_key = 'windows' AND jsonb_typeof(system_data->'scheduledTasks') = 'array'
            THEN system_data->'scheduledTasks' ELSE '[]'::jsonb END) t
        WHERE jsonb_typeof(t) = 'object' AND (
            lower(COALESCE(t->>'path', '')) = ANY(%(task_keys)s::text[])
            OR (%(failed_tasks)s AND COALESCE(t->>'lastRunCode', t->>'last_run_code', '') != ''
                AND COALESCE(t->>'lastRunCode', t->>'last_run_code') != ALL(%(ok_codes)s::text[])))
        UNION ALL
        SELECT jsonb_build_object(
            'kind', 'launchd', 'key', t->>'name', 'name', t->>'name', 'program', t->>'path',
            'arguments', t->'arguments', 'type', t->>'type', 'source', t->>'source',
            'state', t->>'status', 'runAtLoad', t->'runAtLoad', 'username', NULLIF(t->>'username', ''),
            'keepAlive', (SELECT s->'keepAlive' FROM jsonb_array_elements(CASE WHEN jsonb_typeof(system_data->'services') = 'array'
                THEN system_data->'services' ELSE '[]'::jsonb END) s
                WHERE jsonb_typeof(s) = 'object' AND s->>'label' = t->>'name' LIMIT 1)
        )
        FROM jsonb_array_elements(CASE WHEN platform_key = 'macos' AND jsonb_typeof(system_data->'scheduledTasks') = 'array'
            THEN system_data->'scheduledTasks' ELSE '[]'::jsonb END) t
        WHERE jsonb_typeof(t) = 'object' AND lower(COALESCE(t->>'name', '')) = ANY(%(launchd_keys)s::text[])
        UNION ALL
        SELECT jsonb_build_object(
            'kind', 'loginItem', 'key', l->>'name', 'name', l->>'name', 'path', NULLIF(l->>'path', ''),
            'type', l->>'type', 'source', l->>'source', 'enabled', l->'enabled',
            'bundleId', NULLIF(COALESCE(l->>'bundleId', l->>'bundle_id'), ''),
            'username', NULLIF(COALESCE(l->>'username', l->>'user'), '')
        )
        FROM jsonb_array_elements(CASE
            WHEN jsonb_typeof(system_data->'loginItems') = 'array' THEN system_data->'loginItems'
            WHEN jsonb_typeof(system_data->'login_items') = 'array' THEN system_data->'login_items'
            ELSE '[]'::jsonb END) l
        WHERE jsonb_typeof(l) = 'object' AND lower(COALESCE(l->>'name', '')) = ANY(%(login_keys)s::text[])
    ) matched), '[]'::jsonb)
)
FROM scoped
ORDER BY lower(device_name), serial_number;
