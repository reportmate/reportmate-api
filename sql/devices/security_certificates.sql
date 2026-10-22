-- Certificate search endpoint: /api/v1/security/certificates
-- Parameters: search (text), status (all/valid/expired/expiring),
-- cert_class (actionable/system-managed/trust-store/hidden/all),
-- include_archived (boolean), max_results (int).
--
-- Each certificate carries the class certificate_class.py stamped at ingest; an
-- unstamped one counts as actionable. Status is worked out now from
-- notAfterEpoch, falling back to the flags the device stored. Windows lists one
-- certificate in several store views, so each device returns a certificate once,
-- keeping its actionable view when it has one. Filters apply before that, so
-- a certificate is listed under each class one of its views falls in.

WITH certs AS (
    SELECT
        d.serial_number,
        d.platform,
        COALESCE(inv.data->>'device_name', inv.data->>'deviceName',
                 inv.data->>'computer_name', inv.data->>'computerName',
                 d.serial_number) AS device_name,
        cert,
        COALESCE(cert->>'class', 'actionable') AS cert_class,
        CASE WHEN jsonb_typeof(cert->'notAfterEpoch') = 'number'
             THEN FLOOR(((cert->>'notAfterEpoch')::numeric - EXTRACT(EPOCH FROM NOW())) / 86400.0)::int
             WHEN cert->>'daysUntilExpiry' ~ '^\s*-?\d+\s*$'
             THEN (cert->>'daysUntilExpiry')::int
             ELSE 0 END AS days,
        jsonb_typeof(cert->'notAfterEpoch') = 'number' AS live,
        COALESCE(NULLIF(cert->>'thumbprint', ''), NULLIF(cert->>'sha1', ''),
                 COALESCE(cert->>'serialNumber', '') || '|' || COALESCE(cert->>'issuer', '') || '|' || COALESCE(cert->>'commonName', '')) AS cert_key
    FROM devices d
    JOIN security sec ON d.serial_number = sec.device_id
    LEFT JOIN inventory inv ON d.serial_number = inv.device_id
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(sec.data->'certificates') = 'array' THEN sec.data->'certificates' ELSE '[]'::jsonb END) AS cert
    WHERE d.serial_number IS NOT NULL
        AND d.serial_number NOT LIKE 'TEST-%%'
        AND d.serial_number != 'localhost'
        AND jsonb_typeof(cert) = 'object'
        AND (%(include_archived)s = TRUE OR d.archived = FALSE)
        AND (
            %(search)s = '' OR
            cert->>'commonName' ILIKE '%%' || %(search)s || '%%' OR
            cert->>'displayName' ILIKE '%%' || %(search)s || '%%' OR
            cert->>'issuer' ILIKE '%%' || %(search)s || '%%' OR
            cert->>'subject' ILIKE '%%' || %(search)s || '%%' OR
            cert->>'serialNumber' ILIKE '%%' || %(search)s || '%%'
        )
),
statused AS (
    SELECT c.*,
           CASE WHEN live THEN days < 0
                ELSE COALESCE(LOWER(cert->>'isExpired') IN ('true', '1'), FALSE) END AS is_expired,
           CASE WHEN live THEN days >= 0 AND days <= 30
                ELSE COALESCE(LOWER(cert->>'isExpiringSoon') IN ('true', '1'), FALSE)
                     AND NOT COALESCE(LOWER(cert->>'isExpired') IN ('true', '1'), FALSE) END AS is_expiring_soon
    FROM certs c
),
deduped AS (
    SELECT DISTINCT ON (serial_number, cert_key) *
    FROM statused
    WHERE (
            %(cert_class)s = 'all'
            OR cert_class = %(cert_class)s
            OR (%(cert_class)s = 'hidden' AND cert_class <> 'actionable')
        )
        AND (
            %(status)s = 'all' OR
            (%(status)s = 'expired' AND is_expired) OR
            (%(status)s = 'expiring' AND is_expiring_soon) OR
            (%(status)s = 'valid' AND NOT is_expired AND NOT is_expiring_soon)
        )
    ORDER BY serial_number, cert_key,
             CASE cert_class WHEN 'actionable' THEN 0 WHEN 'system-managed' THEN 1 ELSE 2 END
)
SELECT
    serial_number,
    platform,
    device_name,
    cert->>'commonName' AS common_name,
    cert->>'issuer' AS issuer,
    cert->>'subject' AS subject,
    CASE WHEN is_expired THEN 'Expired'
         WHEN is_expiring_soon THEN 'ExpiringSoon'
         WHEN live THEN 'Valid'
         ELSE cert->>'status' END AS cert_status,
    cert->>'notAfter' AS not_after,
    cert->>'notBefore' AS not_before,
    days AS days_until_expiry,
    is_expired,
    is_expiring_soon,
    cert->>'storeName' AS store_name,
    cert->>'storeLocation' AS store_location,
    cert->>'keyAlgorithm' AS key_algorithm,
    cert->>'serialNumber' AS cert_serial_number,
    COALESCE(LOWER(cert->>'isSelfSigned') IN ('true', '1'), FALSE) AS is_self_signed,
    cert_class,
    COALESCE(NULLIF(cert->>'displayName', ''), cert->>'commonName') AS display_name,
    COALESCE(NULLIF(cert->>'issuerName', ''), cert->>'issuer') AS issuer_name,
    cert->>'path' AS keychain_path,
    COALESCE(NULLIF(cert->>'thumbprint', ''), cert->>'sha1') AS thumbprint
FROM deduped
ORDER BY serial_number, common_name
LIMIT %(max_results)s;
