-- Card 11, step 3: usage per folded app name. The name map arrives as two
-- parallel arrays (raw name, folded name), so devices that report two aliases
-- of one app are counted once.
WITH fleet AS (/*FLEET*/),
name_map AS (
    SELECT * FROM unnest(%(raw_names)s::text[], %(folded_names)s::text[]) AS m(raw_name, folded)
)
SELECT
    m.folded AS app,
    SUM(uh.total_seconds)::double precision AS total_seconds,
    SUM(COALESCE(uh.active_seconds, 0))::double precision AS active_seconds,
    COUNT(DISTINCT uh.device_id) AS device_count,
    COUNT(DISTINCT uh.device_id) FILTER (WHERE COALESCE(uh.active_seconds, 0) > 0) AS active_device_count
FROM usage_history uh
JOIN fleet f ON f.serial = uh.device_id
JOIN name_map m ON m.raw_name = uh.app_name
WHERE uh.date >= %(cutoff)s
  AND (%(platform)s = 'all' OR f.platform = %(platform)s)
GROUP BY m.folded
