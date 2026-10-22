-- Card: Install Health. Items waiting to install (reportmateStatus pending),
-- and the devices they wait on, per agent.
WITH fleet AS (/*FLEET*/),
src AS (
    SELECT f.serial,
           CASE WHEN jsonb_array_length(CASE WHEN jsonb_typeof(i.data->'cimian'->'items') = 'array' THEN i.data->'cimian'->'items' ELSE '[]'::jsonb END) > 0
                THEN 'cimian' ELSE 'munki' END AS agent,
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
SELECT src.agent,
       COUNT(*) AS items,
       COUNT(DISTINCT src.serial) AS devices
FROM src
CROSS JOIN LATERAL jsonb_array_elements(src.items) it
WHERE jsonb_typeof(it) = 'object'
  AND it->>'reportmateStatus' = 'pending'
GROUP BY src.agent
