-- Bulk security endpoint: /api/devices/security
-- Returns devices with security summary fields (NOT the full JSONB blob)
-- Extracts only the fields needed by the frontend security page
-- Parameters: include_archived (boolean)

SELECT DISTINCT ON (d.serial_number)
    d.serial_number,
    d.device_id,
    d.last_seen,
    d.platform,
    sec.collected_at,
    -- Inventory fields
    COALESCE(inv.data->>'device_name', inv.data->>'deviceName') as device_name,
    COALESCE(inv.data->>'computer_name', inv.data->>'computerName') as computer_name,
    inv.data->>'usage' as usage,
    inv.data->>'catalog' as catalog,
    inv.data->>'location' as location,
    COALESCE(inv.data->>'asset_tag', inv.data->>'assetTag') as asset_tag,
    -- Security summary fields extracted from JSONB
    COALESCE((sec.data->>'firewallEnabled')::boolean, false) as firewall_enabled,
    COALESCE((sec.data->>'fileVaultEnabled')::boolean, false) as filevault_enabled,
    COALESCE((sec.data->>'edrActive')::boolean, false) as edr_active,
    sec.data->>'edrStatus' as edr_status,
    COALESCE((sec.data->>'cveCount')::int, 0) as cve_count,
    COALESCE((sec.data->>'criticalCveCount')::int, 0) as critical_cve_count,
    COALESCE((sec.data->>'expiredCertCount')::int, 0) as expired_cert_count,
    COALESCE((sec.data->>'expiringSoonCertCount')::int, 0) as expiring_soon_cert_count,
    COALESCE((sec.data->>'tpmPresent')::boolean, false) as tpm_present,
    COALESCE((sec.data->>'tpmEnabled')::boolean, false) as tpm_enabled,
    COALESCE((sec.data->>'secureBootEnabled')::boolean, false) as secure_boot_enabled,
    (sec.data->>'sipEnabled')::boolean as sip_enabled,
    sec.data->'secureShell'->>'statusDisplay' as ssh_status_display,
    COALESCE((sec.data->'secureShell'->>'isConfigured')::boolean, false) as ssh_is_configured,
    COALESCE((sec.data->'secureShell'->>'isServiceRunning')::boolean, false) as ssh_is_service_running,
    sec.data->>'secureBootLevel' as secure_boot_level,
    sec.data->>'autoLoginUser' as auto_login_user
FROM devices d
LEFT JOIN security sec ON d.id = sec.device_id
LEFT JOIN inventory inv ON d.id = inv.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND sec.data IS NOT NULL
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY d.serial_number, sec.updated_at DESC;
