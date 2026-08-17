-- Rejected vs accepted-with-repair totals, independent of the outcome filter
-- so the UI can offer the other side without a second round trip.
-- Parameters:
--   %(hours)s: int - look-back window in hours
--   %(serial)s: text - case-insensitive substring filter on serial number (nullable)

SELECT COUNT(*) FILTER (WHERE f.status_code IS NULL OR f.status_code >= 400) AS rejected,
       COUNT(*) FILTER (WHERE f.status_code < 400) AS accepted
FROM ingest_failures f
WHERE f.occurred_at >= NOW() - make_interval(hours => %(hours)s)
  AND (%(serial)s::text IS NULL OR f.serial_number ILIKE '%%' || %(serial)s || '%%')
