-- Card 9, Expiring Certificates: certificates expiring within the window
-- (flagged expiring soon, not expired, 0 to N days left), counted as
-- certificates and as devices, plus devices holding expired user certificates.
WITH fleet AS (/*FLEET*/),
sec AS (
    SELECT f.serial, s.data AS d
    FROM fleet f
    JOIN security s ON s.device_id = f.serial
    WHERE s.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
),
expiring AS (
    SELECT sec.serial,
           COALESCE(CASE WHEN jsonb_typeof(cert->'daysUntilExpiry') = 'number'
                         THEN (cert->>'daysUntilExpiry')::numeric
                         WHEN cert->>'daysUntilExpiry' ~ '^\s*-?\d+(\.\d+)?\s*$'
                         THEN (cert->>'daysUntilExpiry')::numeric END, 0) AS days
    FROM sec
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(sec.d->'certificates') = 'array' THEN sec.d->'certificates' ELSE '[]'::jsonb END) cert
    WHERE COALESCE(LOWER(cert->>'isExpiringSoon') IN {{TRUE}}, FALSE)
      AND NOT COALESCE(LOWER(cert->>'isExpired') IN {{TRUE}}, FALSE)
)
SELECT
    (SELECT COUNT(*) FROM expiring WHERE days BETWEEN 0 AND %(window_days)s) AS expiring_certs,
    (SELECT COUNT(DISTINCT serial) FROM expiring WHERE days BETWEEN 0 AND %(window_days)s) AS expiring_devices,
    (SELECT COUNT(*) FROM sec
      WHERE CASE WHEN jsonb_typeof(d->'certificateSummary'->'userExpiredCount') = 'number'
                 THEN (d->'certificateSummary'->>'userExpiredCount')::numeric ELSE 0 END > 0) AS expired_user_devices,
    (SELECT COUNT(*) FROM sec) AS devices
