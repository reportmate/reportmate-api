-- Card 9: the actionable certificates expiring soonest, one row per readable
-- name and issuer (certificate_class.py stamps displayName and issuerName so a
-- GUID-named certificate shows as something a person recognises). Expiry is
-- worked out now from notAfterEpoch, as in certificates.sql.
WITH fleet AS (/*FLEET*/),
expiring AS (
    SELECT NULLIF(TRIM(COALESCE(NULLIF(cert->>'displayName', ''), NULLIF(cert->>'commonName', ''), cert->>'subject', '')), '') AS cn,
           COALESCE(NULLIF(TRIM(cert->>'issuerName'), ''), NULLIF(TRIM(cert->>'issuer'), ''), '') AS issuer,
           CASE WHEN jsonb_typeof(cert->'notAfterEpoch') = 'number'
                THEN ((cert->>'notAfterEpoch')::numeric - EXTRACT(EPOCH FROM NOW())) / 86400.0
                WHEN jsonb_typeof(cert->'daysUntilExpiry') = 'number'
                THEN (cert->>'daysUntilExpiry')::numeric
                WHEN cert->>'daysUntilExpiry' ~ '^\s*-?\d+(\.\d+)?\s*$'
                THEN (cert->>'daysUntilExpiry')::numeric
                ELSE 0 END AS days,
           jsonb_typeof(cert->'notAfterEpoch') = 'number' AS live,
           COALESCE(LOWER(cert->>'isExpiringSoon') IN {{TRUE}}, FALSE) AS flagged_expiring,
           COALESCE(LOWER(cert->>'isExpired') IN {{TRUE}}, FALSE) AS flagged_expired,
           f.serial
    FROM fleet f
    JOIN security s ON s.device_id = f.serial
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(s.data->'certificates') = 'array' THEN s.data->'certificates' ELSE '[]'::jsonb END) cert
    WHERE s.data IS NOT NULL
      AND jsonb_typeof(cert) = 'object'
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
      AND COALESCE(cert->>'class', 'actionable') = 'actionable'
)
SELECT cn, issuer, MIN(days) AS days, COUNT(DISTINCT serial) AS devices
FROM expiring
WHERE cn IS NOT NULL
  AND days BETWEEN 0 AND %(window_days)s
  AND (live OR (flagged_expiring AND NOT flagged_expired))
GROUP BY cn, issuer
ORDER BY MIN(days), cn COLLATE "C", issuer COLLATE "C"
LIMIT %(limit)s
