-- Card: Management Tools Errors. The normalised error messages seen in the
-- window on the most devices, per tool and platform, with one device to open.
WITH fleet AS (/*FLEET*/),
roots AS (
    SELECT f.serial, f.platform,
           LOWER(COALESCE(root->>'tool', '')) AS tool,
           CASE WHEN LOWER(COALESCE(root->>'tool', '')) = 'mdm' THEN COALESCE(NULLIF(TRIM(root->>'name'), ''), 'MDM') END AS mdm_name,
           root->'levelSummary'->'errors' AS errors
    FROM fleet f
    JOIN management m ON m.device_id = f.id
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(m.data->'logs'->'roots') = 'array' THEN m.data->'logs'->'roots' ELSE '[]'::jsonb END) root
    WHERE m.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
      AND jsonb_typeof(root) = 'object'
      AND jsonb_typeof(root->'levelSummary'->'errors') = 'array'
      AND COALESCE(root->>'tool', '') <> ''
)
SELECT e->>'m' AS message, r.tool, r.platform, r.mdm_name,
       COUNT(DISTINCT r.serial) AS devices,
       SUM(CASE WHEN jsonb_typeof(e->'n') = 'number' THEN (e->>'n')::int ELSE 0 END) AS lines,
       MIN(r.serial) AS sample_serial
FROM roots r
CROSS JOIN LATERAL jsonb_array_elements(r.errors) e
WHERE jsonb_typeof(e) = 'object'
  AND COALESCE(e->>'m', '') <> ''
  AND COALESCE(e->>'last', '') >= %(since_hour)s
GROUP BY 1, 2, 3, 4
ORDER BY devices DESC, lines DESC, message
LIMIT %(limit)s
