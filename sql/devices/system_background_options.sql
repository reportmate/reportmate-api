SELECT 'task' AS kind, t->>'path' AS value, max(t->>'name') AS label, count(DISTINCT serial_number) AS devices
FROM scoped CROSS JOIN LATERAL jsonb_array_elements(CASE
    WHEN platform_key = 'windows' AND jsonb_typeof(system_data->'scheduledTasks') = 'array'
    THEN system_data->'scheduledTasks' ELSE '[]'::jsonb END) t
WHERE jsonb_typeof(t) = 'object' AND COALESCE(t->>'path', '') != ''
GROUP BY t->>'path'
UNION ALL
SELECT 'launchd', t->>'name', max(t->>'source'), count(DISTINCT serial_number)
FROM scoped CROSS JOIN LATERAL jsonb_array_elements(CASE
    WHEN platform_key = 'macos' AND jsonb_typeof(system_data->'scheduledTasks') = 'array'
    THEN system_data->'scheduledTasks' ELSE '[]'::jsonb END) t
WHERE jsonb_typeof(t) = 'object' AND COALESCE(t->>'name', '') != ''
GROUP BY t->>'name'
UNION ALL
SELECT 'loginItem', l->>'name', max(COALESCE(l->>'bundleId', l->>'bundle_id')), count(DISTINCT serial_number)
FROM scoped CROSS JOIN LATERAL jsonb_array_elements(CASE
    WHEN jsonb_typeof(system_data->'loginItems') = 'array' THEN system_data->'loginItems'
    WHEN jsonb_typeof(system_data->'login_items') = 'array' THEN system_data->'login_items'
    ELSE '[]'::jsonb END) l
WHERE jsonb_typeof(l) = 'object' AND COALESCE(l->>'name', '') != ''
GROUP BY l->>'name'
UNION ALL
SELECT 'scope', field.key, field.value, count(DISTINCT serial_number)
FROM base CROSS JOIN LATERAL jsonb_each_text(jsonb_build_object(
    'usages', usage, 'catalogs', catalog, 'areas', area, 'fleets', fleet,
    'locations', location, 'rooms', room, 'inventoryStates', inventory_state)) field
WHERE COALESCE(field.value, '') != ''
GROUP BY field.key, field.value;
