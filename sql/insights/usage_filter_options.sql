-- App Usage: the inventory usage and catalog values in the platform scope,
-- for the filter chips.
WITH fleet AS (/*FLEET*/)
SELECT 'usage' AS kind, inv.data->>'usage' AS value, COUNT(*) AS devices
FROM fleet f JOIN inventory inv ON inv.device_id = f.id
WHERE COALESCE(inv.data->>'usage', '') <> ''
  AND (%(platform)s = 'all' OR f.platform = %(platform)s)
GROUP BY 2
UNION ALL
SELECT 'catalog' AS kind, inv.data->>'catalog' AS value, COUNT(*) AS devices
FROM fleet f JOIN inventory inv ON inv.device_id = f.id
WHERE COALESCE(inv.data->>'catalog', '') <> ''
  AND (%(platform)s = 'all' OR f.platform = %(platform)s)
GROUP BY 2
ORDER BY 1, 3 DESC, 2
