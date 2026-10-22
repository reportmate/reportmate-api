-- Fleet Management Tools Logs report: error and warning lines per tool,
-- platform and UTC hour in the window, for the trend line.
WITH fleet AS (/*FLEET*/),
roots AS (/*MANAGEMENT_ROOTS*/)
SELECT r.tool, r.platform, h.key AS hour,
       SUM(CASE WHEN jsonb_typeof(h.value->0) = 'number' THEN (h.value->>0)::int ELSE 0 END) AS errors,
       SUM(CASE WHEN jsonb_typeof(h.value->1) = 'number' THEN (h.value->>1)::int ELSE 0 END) AS warnings
FROM roots r
CROSS JOIN LATERAL jsonb_each(CASE WHEN jsonb_typeof(r.s->'hours') = 'object' THEN r.s->'hours' ELSE '{}'::jsonb END) h
WHERE h.key >= %(since_hour)s
GROUP BY r.tool, r.platform, h.key
