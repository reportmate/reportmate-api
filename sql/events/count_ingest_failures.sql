-- Count rejected device check-ins matching the same filters as the list query
-- Parameters:
--   %(hours)s: int - look-back window in hours
--   %(serial)s: text - case-insensitive substring filter on serial number (nullable)
--   %(reason)s: text - exact rejection reason code (nullable)

SELECT COUNT(*) AS total
FROM ingest_failures f
WHERE f.occurred_at >= NOW() - make_interval(hours => %(hours)s)
  AND (%(serial)s::text IS NULL OR f.serial_number ILIKE '%%' || %(serial)s || '%%')
  AND (%(reason)s::text IS NULL OR f.reason = %(reason)s)
