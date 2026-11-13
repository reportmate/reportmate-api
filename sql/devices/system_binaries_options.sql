SELECT 'binary' AS kind, lower(b->>'name') AS value, max(b->>'category') AS label,
    count(DISTINCT serial_number) AS devices
FROM scoped CROSS JOIN LATERAL jsonb_array_elements(CASE
    WHEN jsonb_typeof(system_data->'binaries') = 'array' THEN system_data->'binaries' ELSE '[]'::jsonb END) b
WHERE jsonb_typeof(b) = 'object' AND COALESCE(b->>'name', '') != ''
GROUP BY lower(b->>'name')
UNION ALL
SELECT 'scope', field.key, field.value, count(DISTINCT serial_number)
FROM base CROSS JOIN LATERAL jsonb_each_text(jsonb_build_object(
    'usages', usage, 'catalogs', catalog, 'areas', area, 'fleets', fleet,
    'locations', location, 'rooms', room, 'inventoryStates', inventory_state)) field
WHERE COALESCE(field.value, '') != ''
GROUP BY field.key, field.value;
