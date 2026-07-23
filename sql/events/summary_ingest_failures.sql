-- Per-reason rollup of rejected check-ins (drives the summary chips in the UI)
-- Parameters:
--   %(hours)s: int - look-back window in hours
--   %(serial)s: text - case-insensitive substring filter on serial number (nullable)

SELECT f.reason,
       COUNT(*) AS count,
       COUNT(DISTINCT f.serial_number) AS devices,
       MAX(f.occurred_at) AS last_seen
FROM ingest_failures f
WHERE f.occurred_at >= NOW() - make_interval(hours => %(hours)s)
  AND (%(serial)s::text IS NULL OR f.serial_number ILIKE '%%' || %(serial)s || '%%')
GROUP BY f.reason
ORDER BY count DESC
