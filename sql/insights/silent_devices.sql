-- Card 6, Check-in Gaps: devices silent 1 to 7 days (stale) and over 7 days
-- or never (missing), the thresholds the /devices status pills use.
WITH fleet AS (/*FLEET*/)
SELECT
    COUNT(*) AS devices,
    COUNT(*) FILTER (WHERE last_seen < NOW() - INTERVAL '24 hours'
                       AND last_seen >= NOW() - INTERVAL '168 hours') AS stale,
    COUNT(*) FILTER (WHERE last_seen IS NULL OR last_seen < NOW() - INTERVAL '168 hours') AS missing
FROM fleet
WHERE (%(platform)s = 'all' OR platform = %(platform)s)
