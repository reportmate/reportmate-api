-- Collected configuration profiles, managed preference domains and inventory
-- scope values for the fleet profile report picker: /api/v1/management/profiles/filters
-- Parameters: include_archived (boolean)

WITH base AS NOT MATERIALIZED (
    SELECT d.serial_number, d.platform, d.os_name, m.data AS mdata,
        inv.data->>'usage' AS usage, inv.data->>'catalog' AS catalog,
        inv.data->>'department' AS area, inv.data->>'fleet' AS fleet,
        inv.data->>'location' AS location,
        COALESCE(inv.data->>'room', inv.data->>'location') AS room,
        COALESCE(ist.state, 'unknown') AS inventory_state
    FROM devices d
    LEFT JOIN management m ON m.device_id = d.id
    LEFT JOIN inventory inv ON inv.device_id = d.id
    LEFT JOIN device_inventory_state ist ON ist.serial_number = upper(trim(d.serial_number))
    WHERE d.serial_number IS NOT NULL AND d.serial_number NOT LIKE 'TEST-%%'
        AND d.serial_number != 'localhost'
        AND (%(include_archived)s OR d.archived = FALSE)
), profiles AS (
    SELECT serial_number, COALESCE(platform, os_name) AS platform, p
    FROM base CROSS JOIN LATERAL jsonb_array_elements(CASE
        WHEN jsonb_typeof(mdata->'installed_profiles') = 'array' THEN mdata->'installed_profiles'
        WHEN jsonb_typeof(mdata->'installedProfiles') = 'array' THEN mdata->'installedProfiles'
        WHEN jsonb_typeof(mdata->'configurationProfiles') = 'array' THEN mdata->'configurationProfiles'
        WHEN jsonb_typeof(mdata->'configuration_profiles') = 'array' THEN mdata->'configuration_profiles'
        ELSE '[]'::jsonb END) p
    WHERE jsonb_typeof(p) = 'object'
), prefs AS (
    SELECT serial_number, COALESCE(platform, os_name) AS platform, pol->>'domain' AS domain, pol->'settings' AS settings
    FROM base CROSS JOIN LATERAL jsonb_array_elements(CASE
        WHEN jsonb_typeof(mdata->'managed_policies') = 'array' THEN mdata->'managed_policies'
        WHEN jsonb_typeof(mdata->'managedPolicies') = 'array' THEN mdata->'managedPolicies'
        ELSE '[]'::jsonb END) pol
    WHERE jsonb_typeof(pol) = 'object' AND COALESCE(pol->>'domain', '') != ''
), preference_keys AS (
    SELECT DISTINCT domain, s->>'name' AS name
    FROM prefs CROSS JOIN LATERAL jsonb_array_elements(CASE
        WHEN jsonb_typeof(settings) = 'array' THEN settings ELSE '[]'::jsonb END) s
    WHERE jsonb_typeof(s) = 'object' AND COALESCE(s->>'name', '') != ''
)
SELECT 'profile' AS kind,
    COALESCE(NULLIF(p->>'identifier', ''), NULLIF(p->>'uuid', ''), NULLIF(p->>'profile_name', ''), NULLIF(p->>'profileName', ''), p->>'name') AS value,
    max(COALESCE(NULLIF(p->>'name', ''), NULLIF(p->>'profile_name', ''), p->>'profileName')) AS label,
    count(DISTINCT serial_number) AS devices,
    jsonb_agg(DISTINCT platform) FILTER (WHERE platform IS NOT NULL) AS platforms,
    NULL::jsonb AS keys
FROM profiles
WHERE COALESCE(NULLIF(p->>'identifier', ''), NULLIF(p->>'uuid', ''), NULLIF(p->>'profile_name', ''), NULLIF(p->>'profileName', ''), p->>'name', '') != ''
GROUP BY 2
UNION ALL
SELECT 'preference', domain, NULL, count(DISTINCT serial_number),
    jsonb_agg(DISTINCT platform) FILTER (WHERE platform IS NOT NULL),
    (SELECT jsonb_agg(DISTINCT k.name ORDER BY k.name) FROM preference_keys k WHERE k.domain = prefs.domain)
FROM prefs
GROUP BY domain
UNION ALL
SELECT 'scope', field.key, field.value, count(DISTINCT serial_number), NULL::jsonb, NULL::jsonb
FROM base CROSS JOIN LATERAL jsonb_each_text(jsonb_build_object(
    'usages', usage, 'catalogs', catalog, 'areas', area, 'fleets', fleet,
    'locations', location, 'rooms', room, 'inventoryStates', inventory_state)) field
WHERE COALESCE(field.value, '') != ''
GROUP BY field.key, field.value;
