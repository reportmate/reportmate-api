-- App Usage, step 1: the distinct app names with usage in the window, within
-- the inventory scope. canonicalize_app_name folds them in Python (it is a
-- regex alias map) and the folded names go back to Postgres for the totals.
WITH fleet AS (/*FLEET*/)
SELECT DISTINCT uh.app_name
FROM usage_history uh
JOIN fleet f ON f.serial = uh.device_id
LEFT JOIN inventory inv ON inv.device_id = f.id
WHERE uh.date >= %(cutoff)s
  AND uh.app_name IS NOT NULL
  AND (%(platform)s = 'all' OR f.platform = %(platform)s)
  AND (CARDINALITY(%(usages)s::text[]) = 0 OR LOWER(inv.data->>'usage') = ANY(%(usages)s::text[]))
  AND (CARDINALITY(%(catalogs)s::text[]) = 0 OR LOWER(inv.data->>'catalog') = ANY(%(catalogs)s::text[]))
