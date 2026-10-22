-- Card 9: the common names expiring soonest, one row per name.
WITH fleet AS (/*FLEET*/),
expiring AS (
    SELECT NULLIF(TRIM(COALESCE(NULLIF(cert->>'commonName', ''), cert->>'subject', '')), '') AS cn,
           COALESCE(CASE WHEN jsonb_typeof(cert->'daysUntilExpiry') = 'number'
                         THEN (cert->>'daysUntilExpiry')::numeric
                         WHEN cert->>'daysUntilExpiry' ~ '^\s*-?\d+(\.\d+)?\s*$'
                         THEN (cert->>'daysUntilExpiry')::numeric END, 0) AS days,
           f.serial
    FROM fleet f
    JOIN security s ON s.device_id = f.serial
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(s.data->'certificates') = 'array' THEN s.data->'certificates' ELSE '[]'::jsonb END) cert
    WHERE s.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
      AND COALESCE(LOWER(cert->>'isExpiringSoon') IN {{TRUE}}, FALSE)
      AND NOT COALESCE(LOWER(cert->>'isExpired') IN {{TRUE}}, FALSE)
)
SELECT cn, MIN(days) AS days, COUNT(DISTINCT serial) AS devices
FROM expiring
WHERE cn IS NOT NULL AND days BETWEEN 0 AND %(window_days)s
GROUP BY cn
ORDER BY MIN(days), cn
LIMIT %(limit)s
