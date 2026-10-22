-- Card 11, step 4: devices with each folded app name installed.
WITH fleet AS (/*FLEET*/),
name_map AS (
    SELECT * FROM unnest(%(raw_names)s::text[], %(folded_names)s::text[]) AS m(raw_name, folded)
),
apps AS (
    SELECT f.serial,
           CASE
               WHEN a.data ? 'installedApplications' THEN a.data->'installedApplications'
               WHEN a.data ? 'InstalledApplications' THEN a.data->'InstalledApplications'
               WHEN a.data ? 'installed_applications' THEN a.data->'installed_applications'
               WHEN jsonb_typeof(a.data) = 'array' THEN a.data
               ELSE '[]'::jsonb
           END AS list
    FROM fleet f
    JOIN applications a ON a.device_id = f.id
    WHERE a.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
)
SELECT m.folded AS app, COUNT(DISTINCT apps.serial) AS installed_devices
FROM apps
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(apps.list) = 'array' THEN apps.list ELSE '[]'::jsonb END) elem
JOIN name_map m ON m.raw_name = COALESCE(elem->>'name', elem->>'displayName', '')
GROUP BY m.folded
