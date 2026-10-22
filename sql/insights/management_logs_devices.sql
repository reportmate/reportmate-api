-- Fleet Management Tools Logs report, devices: one row per device and tool
-- with error or warning lines in the window. Optional filters: one tool, a
-- level (rows with that level only), and a set of stored error messages (rows
-- whose root logged one of them in the window).
WITH fleet AS (/*FLEET*/),
roots AS (/*MANAGEMENT_ROOTS*/),
counted AS (
    SELECT r.serial, r.id, r.platform, r.device_name, r.tool, w.errors, w.warnings, w.last_hour,
           r.s->'errors' AS messages
    FROM roots r
    CROSS JOIN LATERAL (
        SELECT COALESCE(SUM(c.e), 0) AS errors, COALESCE(SUM(c.w), 0) AS warnings,
               MAX(h.key) FILTER (WHERE c.e + c.w > 0) AS last_hour
        FROM jsonb_each(CASE WHEN jsonb_typeof(r.s->'hours') = 'object' THEN r.s->'hours' ELSE '{}'::jsonb END) h
        CROSS JOIN LATERAL (
            SELECT CASE WHEN jsonb_typeof(h.value->0) = 'number' THEN (h.value->>0)::int ELSE 0 END AS e,
                   CASE WHEN jsonb_typeof(h.value->1) = 'number' THEN (h.value->>1)::int ELSE 0 END AS w
        ) c
        WHERE h.key >= %(since_hour)s
    ) w
    WHERE (%(tool)s::text IS NULL OR r.tool = %(tool)s::text)
)
SELECT c.serial,
       COALESCE(NULLIF(inv.data->>'device_name', ''), NULLIF(inv.data->>'deviceName', ''),
                NULLIF(c.device_name, ''), c.serial) AS name,
       c.platform, c.tool, c.errors, c.warnings, c.last_hour
FROM counted c
LEFT JOIN inventory inv ON inv.device_id = c.id
WHERE c.errors + c.warnings > 0
  AND (%(level)s::text IS NULL OR (%(level)s::text = 'error' AND c.errors > 0)
                               OR (%(level)s::text = 'warning' AND c.warnings > 0))
  AND (CARDINALITY(%(messages)s::text[]) = 0 OR EXISTS (
          SELECT 1 FROM jsonb_array_elements(
              CASE WHEN jsonb_typeof(c.messages) = 'array' THEN c.messages ELSE '[]'::jsonb END) e
          WHERE e->>'m' = ANY(%(messages)s::text[])
            AND COALESCE(e->>'last', '') >= %(since_hour)s))
ORDER BY c.errors DESC, c.warnings DESC, c.last_hour DESC NULLS LAST, c.serial, c.tool
LIMIT %(limit)s
