SELECT 'systemExtension' AS kind, e->>'identifier' AS value, max(COALESCE(NULLIF(e->>'appName', ''), e->>'type')) AS label,
    count(DISTINCT serial_number) AS devices
FROM scoped CROSS JOIN LATERAL jsonb_array_elements(CASE
    WHEN platform_key = 'macos' AND jsonb_typeof(system_data->'systemExtensions') = 'array'
    THEN system_data->'systemExtensions' ELSE '[]'::jsonb END) e
WHERE jsonb_typeof(e) = 'object' AND COALESCE(e->>'identifier', '') != ''
GROUP BY e->>'identifier'
UNION ALL
SELECT 'kernelExtension', k->>'name', max(k->>'version'), count(DISTINCT serial_number)
FROM scoped CROSS JOIN LATERAL jsonb_array_elements(CASE
    WHEN platform_key = 'macos' AND jsonb_typeof(system_data->'kernelExtensions') = 'array'
    THEN system_data->'kernelExtensions' ELSE '[]'::jsonb END) k
WHERE jsonb_typeof(k) = 'object' AND COALESCE(k->>'name', '') != ''
GROUP BY k->>'name'
UNION ALL
SELECT 'helper', h->>'name', max(split_part(COALESCE(h->>'bundleIdentifier', h->>'bundleId', ''), E'\n', 1)), count(DISTINCT serial_number)
FROM scoped CROSS JOIN LATERAL jsonb_array_elements(CASE
    WHEN platform_key = 'macos' AND jsonb_typeof(system_data->'privilegedHelperTools') = 'array'
    THEN system_data->'privilegedHelperTools' ELSE '[]'::jsonb END) h
WHERE jsonb_typeof(h) = 'object' AND COALESCE(h->>'name', '') != ''
GROUP BY h->>'name'
UNION ALL
SELECT 'team', team, NULL, count(DISTINCT serial_number)
FROM scoped CROSS JOIN LATERAL (
    SELECT NULLIF(e->>'teamId', '') AS team FROM jsonb_array_elements(CASE
        WHEN platform_key = 'macos' AND jsonb_typeof(system_data->'systemExtensions') = 'array'
        THEN system_data->'systemExtensions' ELSE '[]'::jsonb END) e WHERE jsonb_typeof(e) = 'object'
    UNION ALL
    SELECT NULLIF(h->>'teamId', '') FROM jsonb_array_elements(CASE
        WHEN platform_key = 'macos' AND jsonb_typeof(system_data->'privilegedHelperTools') = 'array'
        THEN system_data->'privilegedHelperTools' ELSE '[]'::jsonb END) h WHERE jsonb_typeof(h) = 'object'
) teams
WHERE team IS NOT NULL
GROUP BY team
UNION ALL
SELECT 'scope', field.key, field.value, count(DISTINCT serial_number)
FROM base CROSS JOIN LATERAL jsonb_each_text(jsonb_build_object(
    'usages', usage, 'catalogs', catalog, 'areas', area, 'fleets', fleet,
    'locations', location, 'rooms', room, 'inventoryStates', inventory_state)) field
WHERE COALESCE(field.value, '') != ''
GROUP BY field.key, field.value;
