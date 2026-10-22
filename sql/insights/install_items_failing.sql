-- Card 5: the managed items failing on the most devices. Aggregated here so
-- the per-item rows (over a hundred thousand fleet-wide) never leave Postgres.
-- A device reports Cimian items, or Munki items when it has none, as the web
-- getDeviceInstallItems reads them. The state is the reportmateStatus ingest
-- stamps on every item; an item stored before stamping falls back to its status text.
WITH fleet AS (/*FLEET*/),
src AS (
    SELECT f.serial,
           CASE
               WHEN jsonb_array_length(CASE WHEN jsonb_typeof(i.data->'cimian'->'items') = 'array' THEN i.data->'cimian'->'items' ELSE '[]'::jsonb END) > 0 THEN i.data->'cimian'->'items'
               WHEN jsonb_typeof(i.data->'munki'->'items') = 'array' THEN i.data->'munki'->'items'
               ELSE '[]'::jsonb
           END AS items
    FROM fleet f
    JOIN installs i ON i.device_id = f.id
    WHERE i.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
)
SELECT n.name, COUNT(DISTINCT src.serial) AS devices
FROM src
CROSS JOIN LATERAL jsonb_array_elements(src.items) it
CROSS JOIN LATERAL (SELECT NULLIF(TRIM(COALESCE(it->>'itemName', it->>'name')), '') AS name) n
WHERE jsonb_typeof(it) = 'object'
  AND n.name IS NOT NULL
  AND (
      it->>'reportmateStatus' = 'error'
      OR (it->>'reportmateStatus' IS NULL
          AND LOWER(COALESCE(it->>'currentStatus', it->>'mappedStatus', it->>'status', '')) ~ '(error|fail|problem|install.loop)')
  )
GROUP BY n.name
ORDER BY devices DESC, n.name COLLATE "C"
LIMIT %(limit)s
