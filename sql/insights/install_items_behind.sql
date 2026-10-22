-- Card 8, Software Risk: managed items with the most devices on an older
-- version than the catalog offers (installedVersion differs from latestVersion,
-- the same comparison as the install rows of GET /installs, where a Munki
-- item carries its latest version as version).
WITH fleet AS (/*FLEET*/),
src AS (
    SELECT f.serial,
           CASE
               WHEN jsonb_array_length(CASE WHEN jsonb_typeof(i.data->'cimian'->'items') = 'array' THEN i.data->'cimian'->'items' ELSE '[]'::jsonb END) > 0 THEN i.data->'cimian'->'items'
               WHEN jsonb_typeof(i.data->'munki'->'items') = 'array' THEN i.data->'munki'->'items'
               ELSE '[]'::jsonb
           END AS items,
           NOT (jsonb_array_length(CASE WHEN jsonb_typeof(i.data->'cimian'->'items') = 'array' THEN i.data->'cimian'->'items' ELSE '[]'::jsonb END) > 0) AS is_munki
    FROM fleet f
    JOIN installs i ON i.device_id = f.id
    WHERE i.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
)
SELECT v.name, COUNT(DISTINCT src.serial) AS devices
FROM src
CROSS JOIN LATERAL jsonb_array_elements(src.items) it
CROSS JOIN LATERAL (
    SELECT NULLIF(TRIM(COALESCE(it->>'itemName', it->>'name')), '') AS name,
           TRIM(COALESCE(it->>'installedVersion', '')) AS have,
           TRIM(COALESCE(it->>'latestVersion', CASE WHEN src.is_munki THEN it->>'version' END, '')) AS want
) v
WHERE jsonb_typeof(it) = 'object'
  AND v.name IS NOT NULL
  AND v.have <> ''
  AND v.want <> ''
  AND v.have <> v.want
GROUP BY v.name
ORDER BY devices DESC, v.name
LIMIT %(limit)s
