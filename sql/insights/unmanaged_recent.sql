-- Card 3: the unenrolled devices seen most recently, the ones still in use.
WITH fleet AS (/*FLEET*/)
SELECT f.serial,
       COALESCE(NULLIF(inv.data->>'device_name', ''), NULLIF(inv.data->>'deviceName', ''),
                NULLIF(f.device_name, ''), f.serial) AS name,
       f.platform,
       f.last_seen
FROM fleet f
JOIN management mg ON mg.device_id = f.id
LEFT JOIN inventory inv ON inv.device_id = f.id
CROSS JOIN LATERAL (
    SELECT COALESCE(NULLIF(NULLIF(mg.data->'mdmEnrollment', 'null'::jsonb), '{}'::jsonb),
                    mg.data->'mdm_enrollment') AS me
) x
WHERE mg.data IS NOT NULL
  AND (%(platform)s = 'all' OR f.platform = %(platform)s)
  AND NOT (LOWER(COALESCE(x.me->>'isEnrolled', '')) IN {{TRUE}}
           OR LOWER(COALESCE(x.me->>'is_enrolled', '')) IN {{TRUE}}
           OR LOWER(COALESCE(x.me->>'enrolled', '')) IN {{TRUE}})
ORDER BY f.last_seen DESC NULLS LAST, f.serial
LIMIT %(limit)s
