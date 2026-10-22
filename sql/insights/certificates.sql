-- Card 9, Expiring Certificates: actionable certificates only (certificate_class.py
-- stamps each one at ingest; an unstamped certificate from before that counts as
-- actionable until the reclassify job reaches it). Expiry is worked out now from
-- notAfterEpoch, because daysUntilExpiry is frozen when the device collected it;
-- rows without the epoch fall back to the stored days and flags. The same
-- certificate listed in several Windows store views counts once per device.
WITH fleet AS (/*FLEET*/),
sec AS (
    SELECT f.serial, s.data AS d
    FROM fleet f
    JOIN security s ON s.device_id = f.serial
    WHERE s.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
),
certs AS (
    SELECT DISTINCT ON (sec.serial, k.cert_key)
           sec.serial,
           CASE WHEN jsonb_typeof(cert->'notAfterEpoch') = 'number'
                THEN ((cert->>'notAfterEpoch')::numeric - EXTRACT(EPOCH FROM NOW())) / 86400.0
                WHEN jsonb_typeof(cert->'daysUntilExpiry') = 'number'
                THEN (cert->>'daysUntilExpiry')::numeric
                WHEN cert->>'daysUntilExpiry' ~ '^\s*-?\d+(\.\d+)?\s*$'
                THEN (cert->>'daysUntilExpiry')::numeric END AS days,
           jsonb_typeof(cert->'notAfterEpoch') = 'number' AS live,
           COALESCE(LOWER(cert->>'isExpired') IN {{TRUE}}, FALSE) AS flagged_expired,
           COALESCE(LOWER(cert->>'isExpiringSoon') IN {{TRUE}}, FALSE) AS flagged_expiring
    FROM sec
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(sec.d->'certificates') = 'array' THEN sec.d->'certificates' ELSE '[]'::jsonb END) cert
    CROSS JOIN LATERAL (SELECT COALESCE(NULLIF(cert->>'thumbprint', ''), NULLIF(cert->>'sha1', ''),
        COALESCE(cert->>'serialNumber', '') || '|' || COALESCE(cert->>'issuer', '') || '|' || COALESCE(cert->>'commonName', '')) AS cert_key) k
    WHERE jsonb_typeof(cert) = 'object'
      AND COALESCE(cert->>'class', 'actionable') = 'actionable'
),
classified AS (
    SELECT serial, days,
           CASE WHEN live THEN days < 0 ELSE flagged_expired END AS expired,
           CASE WHEN live THEN days >= 0 AND days <= %(window_days)s
                ELSE flagged_expiring AND NOT flagged_expired AND COALESCE(days, 0) BETWEEN 0 AND %(window_days)s END AS expiring
    FROM certs
)
SELECT
    (SELECT COUNT(*) FROM classified WHERE expiring) AS expiring_certs,
    (SELECT COUNT(DISTINCT serial) FROM classified WHERE expiring) AS expiring_devices,
    (SELECT COUNT(DISTINCT serial) FROM classified WHERE expired) AS expired_user_devices,
    (SELECT COUNT(*) FROM sec) AS devices
