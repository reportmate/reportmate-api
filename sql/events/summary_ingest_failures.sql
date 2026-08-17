-- Per-reason rollup of rejected check-ins (drives the summary chips in the UI)
-- Parameters:
--   %(hours)s: int - look-back window in hours
--   %(serial)s: text - case-insensitive substring filter on serial number (nullable)
--   %(outcome)s: text - 'rejected', 'accepted', or NULL for both (nullable)

SELECT f.reason,
       COUNT(*) AS count,
       COUNT(DISTINCT f.serial_number) AS devices,
       MAX(f.occurred_at) AS last_seen
FROM ingest_failures f
WHERE f.occurred_at >= NOW() - make_interval(hours => %(hours)s)
  AND (%(serial)s::text IS NULL OR f.serial_number ILIKE '%%' || %(serial)s || '%%')
  AND (%(outcome)s::text IS NULL
       OR (%(outcome)s = 'rejected' AND (f.status_code IS NULL OR f.status_code >= 400))
       OR (%(outcome)s = 'accepted' AND f.status_code < 400))
GROUP BY f.reason
ORDER BY count DESC
