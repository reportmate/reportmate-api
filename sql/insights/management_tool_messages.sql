-- Management Tools Logs: error messages seen in the window, grouped by tool
-- and stored message across platforms. Python then strips any prefix older
-- stamps left in the stored message, regroups and keeps the top few.
WITH fleet AS (/*FLEET*/),
roots AS (/*MANAGEMENT_ROOTS*/)
SELECT e->>'m' AS message, r.tool,
       ARRAY_AGG(DISTINCT r.platform) AS platforms,
       COUNT(DISTINCT r.serial) AS devices,
       SUM(CASE WHEN jsonb_typeof(e->'n') = 'number' THEN (e->>'n')::int ELSE 0 END) AS lines,
       MIN(r.serial) AS sample_serial
FROM roots r
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(r.s->'errors') = 'array' THEN r.s->'errors' ELSE '[]'::jsonb END) e
WHERE jsonb_typeof(e) = 'object'
  AND COALESCE(e->>'m', '') <> ''
  AND COALESCE(e->>'last', '') >= %(since_hour)s
GROUP BY 1, 2
ORDER BY devices DESC, lines DESC, message
LIMIT %(limit)s
