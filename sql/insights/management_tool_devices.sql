-- Management Tools Errors, device list: the devices whose log root for one
-- tool has error (or warning) lines in the window, from the levelSummary
-- ingest stamps on each root (log_tails.py). Hour keys are UTC YYYY-MM-DDTHH.
WITH fleet AS (/*FLEET*/),
roots AS (
    SELECT f.serial, f.id, f.platform, f.device_name, root->'levelSummary'->'hours' AS hours
    FROM fleet f
    JOIN management m ON m.device_id = f.id
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(m.data->'logs'->'roots') = 'array' THEN m.data->'logs'->'roots' ELSE '[]'::jsonb END) root
    WHERE m.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
      AND jsonb_typeof(root) = 'object'
      AND LOWER(COALESCE(root->>'tool', '')) = %(tool)s
      AND jsonb_typeof(root->'levelSummary'->'hours') = 'object'
),
counted AS (
    SELECT r.serial, r.id, r.platform, r.device_name,
           SUM(c.n) AS lines,
           MAX(h.key) FILTER (WHERE c.n > 0) AS last_hour
    FROM roots r
    CROSS JOIN LATERAL jsonb_each(r.hours) h
    CROSS JOIN LATERAL (
        SELECT CASE WHEN jsonb_typeof(h.value->(%(slot)s::int)) = 'number' THEN (h.value->>(%(slot)s::int))::int ELSE 0 END AS n
    ) c
    WHERE h.key >= %(since_hour)s
    GROUP BY r.serial, r.id, r.platform, r.device_name
)
SELECT c.serial,
       COALESCE(NULLIF(inv.data->>'device_name', ''), NULLIF(inv.data->>'deviceName', ''),
                NULLIF(c.device_name, ''), c.serial) AS name,
       c.platform, c.lines, c.last_hour
FROM counted c
LEFT JOIN inventory inv ON inv.device_id = c.id
WHERE c.lines > 0
ORDER BY c.lines DESC, c.last_hour DESC, c.serial
LIMIT %(limit)s
