WITH base AS NOT MATERIALIZED (
    SELECT d.serial_number, sys.data AS system_data, app.data AS applications_data,
        inv.data->>'usage' AS usage, inv.data->>'catalog' AS catalog,
        inv.data->>'department' AS area, inv.data->>'fleet' AS fleet,
        inv.data->>'location' AS location,
        COALESCE(inv.data->>'room', inv.data->>'location') AS room,
        COALESCE(ist.state, 'unknown') AS inventory_state
    FROM devices d
    LEFT JOIN system sys ON sys.device_id = d.serial_number
    LEFT JOIN applications app ON app.device_id = d.serial_number
    LEFT JOIN inventory inv ON inv.device_id = d.serial_number
    LEFT JOIN device_inventory_state ist ON ist.serial_number = upper(trim(d.serial_number))
    WHERE d.serial_number IS NOT NULL AND d.serial_number NOT LIKE 'TEST-%%'
        AND d.serial_number != 'localhost'
        AND (%(include_archived)s OR d.archived = FALSE)
        AND (%(platform)s = '' OR CASE
            WHEN lower(COALESCE(sys.data->'operatingSystem'->>'name', d.platform, '')) LIKE '%%windows%%' THEN 'windows'
            WHEN lower(COALESCE(sys.data->'operatingSystem'->>'name', d.platform, '')) LIKE '%%mac%%'
                OR lower(COALESCE(sys.data->'operatingSystem'->>'name', d.platform, '')) LIKE '%%darwin%%' THEN 'macos'
            ELSE lower(COALESCE(sys.data->'operatingSystem'->>'name', d.platform, '')) END = %(platform)s)
), scoped AS NOT MATERIALIZED (
    SELECT * FROM base WHERE
        (%(usages)s::text[] = '{}' OR lower(usage) = ANY(%(usages)s))
        AND (%(catalogs)s::text[] = '{}' OR lower(catalog) = ANY(%(catalogs)s))
        AND (%(areas)s::text[] = '{}' OR lower(area) = ANY(%(areas)s))
        AND (%(fleets)s::text[] = '{}' OR lower(fleet) = ANY(%(fleets)s))
        AND (%(locations)s::text[] = '{}' OR lower(location) = ANY(%(locations)s))
        AND (%(rooms)s::text[] = '{}' OR lower(room) = ANY(%(rooms)s))
        AND (%(inventory_states)s::text[] = '{}' OR lower(inventory_state) = ANY(%(inventory_states)s))
)
SELECT 'service' AS kind, COALESCE(s->>'name', s->>'label') AS value,
    max(COALESCE(s->>'displayName', s->>'display_name')) AS label,
    count(DISTINCT serial_number) AS devices,
    jsonb_agg(DISTINCT COALESCE(s->>'startType', s->>'start_type')) AS versions
FROM scoped CROSS JOIN LATERAL jsonb_array_elements(CASE
    WHEN jsonb_typeof(system_data->'services') = 'array' THEN system_data->'services' ELSE '[]'::jsonb END) s
WHERE COALESCE(s->>'name', s->>'label', '') != ''
GROUP BY COALESCE(s->>'name', s->>'label')
UNION ALL
SELECT 'application', COALESCE(a->>'name', a->>'displayName'), NULL,
    count(DISTINCT serial_number),
    COALESCE(jsonb_agg(DISTINCT COALESCE(a->>'version', a->>'bundle_version'))
        FILTER (WHERE COALESCE(a->>'version', a->>'bundle_version', '') != ''), '[]'::jsonb)
FROM scoped CROSS JOIN LATERAL jsonb_array_elements(CASE
    WHEN jsonb_typeof(applications_data) = 'array' THEN applications_data
    WHEN jsonb_typeof(applications_data->'installedApplications') = 'array' THEN applications_data->'installedApplications'
    WHEN jsonb_typeof(applications_data->'InstalledApplications') = 'array' THEN applications_data->'InstalledApplications'
    WHEN jsonb_typeof(applications_data->'installed_applications') = 'array' THEN applications_data->'installed_applications'
    ELSE '[]'::jsonb END) a
WHERE COALESCE(a->>'name', a->>'displayName', '') != ''
GROUP BY COALESCE(a->>'name', a->>'displayName')
UNION ALL
SELECT 'scope', field.key, field.value, count(DISTINCT serial_number), NULL::jsonb
FROM base CROSS JOIN LATERAL jsonb_each_text(jsonb_build_object(
    'usages', usage, 'catalogs', catalog, 'areas', area, 'fleets', fleet,
    'locations', location, 'rooms', room, 'inventoryStates', inventory_state)) field
WHERE COALESCE(field.value, '') != ''
GROUP BY field.key, field.value;
