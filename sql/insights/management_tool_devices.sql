-- Management Tools Logs, device list: the devices whose log root for one
-- tool has error (or warning) lines in the window, from the levelSummary
-- ingest stamps on each root (log_tails.py). MDM agent roots are excluded.
WITH fleet AS (/*FLEET*/),
roots AS (/*MANAGEMENT_ROOTS*/),
counted AS (
    SELECT r.serial, r.id, r.platform, r.device_name,
           SUM(c.n) AS lines,
           MAX(h.key) FILTER (WHERE c.n > 0) AS last_hour
    FROM roots r
    CROSS JOIN LATERAL jsonb_each(CASE WHEN jsonb_typeof(r.s->'hours') = 'object' THEN r.s->'hours' ELSE '{}'::jsonb END) h
    CROSS JOIN LATERAL (
        SELECT CASE WHEN jsonb_typeof(h.value->(%(slot)s::int)) = 'number' THEN (h.value->>(%(slot)s::int))::int ELSE 0 END AS n
    ) c
    WHERE r.tool = %(tool)s
      AND h.key >= %(since_hour)s
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
