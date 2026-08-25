-- Rejected / retried / accepted totals, independent of the outcome filter so
-- the UI can offer the other sides without a second round trip.
-- Parameters:
--   %(hours)s: int - look-back window in hours
--   %(serial)s: text - case-insensitive substring filter on serial number (nullable)

-- outcome derivation, shared by every query on this table
--
--   accepted -- recorded below 400: the check-in got in, and the row exists
--               only to keep a client-side defect visible (nul_in_payload,
--               usage_out_of_bounds).
--   retried  -- turned away, but the payload was never the problem: the
--               upload died in transport and the device has checked in
--               successfully since. The clients retry three times with
--               backoff, so this is the ordinary outcome of a dropped upload
--               rather than a device that failed to report.
--   rejected -- turned away with nothing since. These are the devices whose
--               data genuinely did not arrive.
--
-- Only transport reasons qualify. A malformed body or a bad passphrase is
-- resent identically, so a later success says nothing about that check-in; a
-- dropped upload resends the same bytes down a fresh connection, which is
-- precisely why the retry lands.
WITH scoped AS (
    SELECT f.*,
           (f.status_code IS NOT NULL AND f.status_code < 400) AS accepted,
           (
               (f.status_code IS NULL OR f.status_code >= 400)
               AND f.reason IN ('upload_aborted', 'body_unreadable', 'empty_body')
               AND f.serial_number IS NOT NULL
               AND EXISTS (
                   SELECT 1 FROM devices d
                   WHERE d.serial_number = f.serial_number
                     AND d.last_seen > f.occurred_at
               )
           ) AS retried
    FROM ingest_failures f
    WHERE f.occurred_at >= NOW() - make_interval(hours => %(hours)s)
      AND (%(serial)s::text IS NULL OR f.serial_number ILIKE '%%' || %(serial)s || '%%')
)
SELECT COUNT(*) FILTER (WHERE NOT s.accepted AND NOT s.retried) AS rejected,
       COUNT(*) FILTER (WHERE s.retried) AS retried,
       COUNT(*) FILTER (WHERE s.accepted) AS accepted
FROM scoped s
