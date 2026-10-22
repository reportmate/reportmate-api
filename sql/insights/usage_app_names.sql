-- Card 11, Unused Software, step 1: the distinct app names with usage in the
-- window. canonicalize_app_name folds them in Python (it is a regex alias
-- map), and the folded names go back to Postgres for the aggregate.
WITH fleet AS (/*FLEET*/)
SELECT DISTINCT uh.app_name
FROM usage_history uh
JOIN fleet f ON f.serial = uh.device_id
WHERE uh.date >= %(cutoff)s
  AND uh.app_name IS NOT NULL
  AND (%(platform)s = 'all' OR f.platform = %(platform)s)
