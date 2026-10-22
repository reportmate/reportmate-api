-- The device scope every insight card counts over. Not a query on its own:
-- dashboard_insights.py substitutes it for /*FLEET*/ in the WITH of every card query.
-- Same exclusions as the bulk reports (TEST- serials, localhost, archived
-- unless asked), plus stored devices, which the dashboard keeps out of every
-- fleet count. Platform is normalised once here so a card can filter on it.
SELECT d.id,
       d.serial_number AS serial,
       d.last_seen,
       d.name AS device_name,
       CASE
           WHEN LOWER(COALESCE(NULLIF(d.platform, ''), NULLIF(d.os_name, ''), d.os, '')) ~ '(mac|darwin|os x)' THEN 'macOS'
           WHEN LOWER(COALESCE(NULLIF(d.platform, ''), NULLIF(d.os_name, ''), d.os, '')) ~ 'win' THEN 'Windows'
           ELSE 'Unknown'
       END AS platform
FROM devices d
WHERE d.serial_number IS NOT NULL
  AND d.serial_number NOT LIKE 'TEST-%%'
  AND d.serial_number <> 'localhost'
  AND (%(include_archived)s = TRUE OR d.archived = FALSE)
  AND /*NOT_STORED*/
