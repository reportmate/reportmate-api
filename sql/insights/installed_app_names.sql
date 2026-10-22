-- Card 11, step 2: the distinct installed application names in the
-- applications inventory, to be folded the same way.
WITH fleet AS (/*FLEET*/),
apps AS (
    SELECT CASE
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
SELECT DISTINCT COALESCE(elem->>'name', elem->>'displayName', '') AS app_name
FROM apps
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(apps.list) = 'array' THEN apps.list ELSE '[]'::jsonb END) elem
WHERE COALESCE(elem->>'name', elem->>'displayName', '') <> ''
