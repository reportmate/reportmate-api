-- Rejected device check-ins, newest first
-- Parameters:
--   %(hours)s: int - look-back window in hours
--   %(serial)s: text - case-insensitive substring filter on serial number (nullable)
--   %(reason)s: text - exact rejection reason code (nullable)
--   %(limit)s / %(offset)s: pagination

SELECT f.id,
       f.occurred_at,
       f.failure_type,
       f.reason,
       f.detail,
       f.status_code,
       f.endpoint,
       f.client_ip,
       f.user_agent,
       f.serial_number,
       f.device_uuid,
       f.device_name,
       f.platform,
       f.client_version
FROM ingest_failures f
WHERE f.occurred_at >= NOW() - make_interval(hours => %(hours)s)
  AND (%(serial)s::text IS NULL OR f.serial_number ILIKE '%%' || %(serial)s || '%%')
  AND (%(reason)s::text IS NULL OR f.reason = %(reason)s)
ORDER BY f.occurred_at DESC
LIMIT %(limit)s OFFSET %(offset)s
