-- Card 3, Unmanaged Devices: MDM enrollment per platform, and how recently
-- the unenrolled devices were seen (24 h / 7 day thresholds of /devices).
-- Enrollment reads the same three keys GET /management does.
WITH fleet AS (/*FLEET*/),
m AS (
    SELECT f.platform, f.last_seen,
           COALESCE(NULLIF(NULLIF(mg.data->'mdmEnrollment', 'null'::jsonb), '{}'::jsonb),
                    mg.data->'mdm_enrollment') AS me
    FROM fleet f
    JOIN management mg ON mg.device_id = f.id
    WHERE mg.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
),
e AS (
    SELECT platform, last_seen,
           (LOWER(COALESCE(me->>'isEnrolled', '')) IN {{TRUE}}
            OR LOWER(COALESCE(me->>'is_enrolled', '')) IN {{TRUE}}
            OR LOWER(COALESCE(me->>'enrolled', '')) IN {{TRUE}}) AS enrolled
    FROM m
)
SELECT
    platform,
    COUNT(*) AS devices,
    COUNT(*) FILTER (WHERE NOT enrolled) AS unmanaged,
    COUNT(*) FILTER (WHERE NOT enrolled AND last_seen >= NOW() - INTERVAL '24 hours') AS seen_24h,
    COUNT(*) FILTER (WHERE NOT enrolled AND last_seen < NOW() - INTERVAL '24 hours'
                                        AND last_seen >= NOW() - INTERVAL '168 hours') AS seen_7d,
    COUNT(*) FILTER (WHERE NOT enrolled AND (last_seen IS NULL OR last_seen < NOW() - INTERVAL '168 hours')) AS silent
FROM e
GROUP BY platform
ORDER BY platform
