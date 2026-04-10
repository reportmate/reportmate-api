-- Certificate search endpoint: /api/devices/security/certificates
-- Searches certificates across all devices in the fleet
-- Parameters: search (text), status (text: all/valid/expired/expiring), include_archived (boolean)

SELECT
    d.serial_number,
    d.platform,
    COALESCE(inv.data->>'device_name', inv.data->>'deviceName',
             inv.data->>'computer_name', inv.data->>'computerName',
             d.serial_number) as device_name,
    cert->>'commonName' as common_name,
    cert->>'issuer' as issuer,
    cert->>'subject' as subject,
    cert->>'status' as cert_status,
    cert->>'notAfter' as not_after,
    cert->>'notBefore' as not_before,
    COALESCE((cert->>'daysUntilExpiry')::int, 0) as days_until_expiry,
    COALESCE((cert->>'isExpired')::boolean, false) as is_expired,
    COALESCE((cert->>'isExpiringSoon')::boolean, false) as is_expiring_soon,
    cert->>'storeName' as store_name,
    cert->>'storeLocation' as store_location,
    cert->>'keyAlgorithm' as key_algorithm,
    cert->>'serialNumber' as cert_serial_number,
    COALESCE((cert->>'isSelfSigned')::boolean, false) as is_self_signed
FROM devices d
JOIN security sec ON d.serial_number = sec.device_id
LEFT JOIN inventory inv ON d.serial_number = inv.device_id
CROSS JOIN LATERAL jsonb_array_elements(sec.data->'certificates') AS cert
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND sec.data->'certificates' IS NOT NULL
    AND jsonb_array_length(sec.data->'certificates') > 0
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
    AND (
        %(search)s = '' OR
        cert->>'commonName' ILIKE '%%' || %(search)s || '%%' OR
        cert->>'issuer' ILIKE '%%' || %(search)s || '%%' OR
        cert->>'subject' ILIKE '%%' || %(search)s || '%%' OR
        cert->>'serialNumber' ILIKE '%%' || %(search)s || '%%'
    )
    AND (
        %(status)s = 'all' OR
        (%(status)s = 'expired' AND (cert->>'isExpired')::boolean = true) OR
        (%(status)s = 'expiring' AND (cert->>'isExpiringSoon')::boolean = true) OR
        (%(status)s = 'valid' AND COALESCE((cert->>'isExpired')::boolean, false) = false AND COALESCE((cert->>'isExpiringSoon')::boolean, false) = false)
    )
ORDER BY d.serial_number, cert->>'commonName'
LIMIT %(max_results)s;
