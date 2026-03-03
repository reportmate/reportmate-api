-- Bulk security endpoint: /api/devices/security
-- Returns devices with structured security summary fields
-- Extracts fields needed by the frontend fleet security page
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

    -- Firewall
    COALESCE(
        (sec.data->'firewall'->>'isEnabled')::boolean,
        (sec.data->'firewall'->>'enabled')::boolean,
        CASE WHEN sec.data->'firewall'->>'globalState' IN ('on', '1') THEN true ELSE false END
    ) as firewall_enabled,

    -- Encryption (Windows: bitLocker, Mac: fileVault)
    COALESCE(
        (sec.data->'encryption'->'bitLocker'->>'isEnabled')::boolean,
        (sec.data->'fileVault'->>'enabled')::boolean,
        false
    ) as encryption_enabled,

    -- Antivirus
    COALESCE(sec.data->'antivirus'->>'name', '') as antivirus_name,
    COALESCE((sec.data->'antivirus'->>'isEnabled')::boolean, false) as antivirus_enabled,
    COALESCE((sec.data->'antivirus'->>'isUpToDate')::boolean, false) as antivirus_up_to_date,
    sec.data->'antivirus'->>'version' as antivirus_version,
    sec.data->'antivirus'->>'lastScan' as antivirus_last_scan,

    -- EDR / Detection
    COALESCE((sec.data->>'edrActive')::boolean, false) as edr_active,
    sec.data->>'edrStatus' as edr_status,

    -- Tampering: TPM (Windows)
    COALESCE((sec.data->'tpm'->>'isPresent')::boolean, false) as tpm_present,
    COALESCE((sec.data->'tpm'->>'isEnabled')::boolean, false) as tpm_enabled,
    -- Tampering: Secure Boot
    COALESCE((sec.data->'secureBoot'->>'isEnabled')::boolean, false) as secure_boot_enabled,
    -- Tampering: SIP (macOS)
    COALESCE(
        (sec.data->'systemIntegrityProtection'->>'enabled')::boolean,
        (sec.data->>'sipEnabled')::boolean
    ) as sip_enabled,
    -- Tampering: Gatekeeper (macOS)
    COALESCE(
        (sec.data->'gatekeeper'->>'enabled')::boolean,
        false
    ) as gatekeeper_enabled,

    -- Device Guard / Protection (Windows)
    COALESCE((sec.data->'deviceGuard'->>'memoryIntegrityEnabled')::boolean, false) as memory_integrity_enabled,
    COALESCE((sec.data->'deviceGuard'->>'coreIsolationEnabled')::boolean, false) as core_isolation_enabled,
    sec.data->'deviceGuard'->>'smartAppControlState' as smart_app_control_state,

    -- Remote Access: SSH
    sec.data->'secureShell'->>'statusDisplay' as ssh_status_display,
    COALESCE((sec.data->'secureShell'->>'isConfigured')::boolean, false) as ssh_is_configured,
    COALESCE((sec.data->'secureShell'->>'isServiceRunning')::boolean, false) as ssh_is_service_running,
    -- Remote Access: RDP (Windows)
    COALESCE((sec.data->'rdp'->>'isEnabled')::boolean, false) as rdp_enabled,

    -- Certificates (summary counts)
    COALESCE(jsonb_array_length(sec.data->'certificates'), 0) as certificate_count,
    COALESCE((
        SELECT count(*)::int FROM jsonb_array_elements(sec.data->'certificates') cert
        WHERE (cert->>'isExpired')::boolean = true
    ), 0) as expired_cert_count,
    COALESCE((
        SELECT count(*)::int FROM jsonb_array_elements(sec.data->'certificates') cert
        WHERE (cert->>'isExpiringSoon')::boolean = true
    ), 0) as expiring_soon_cert_count,

    -- Vulnerabilities (summary counts)
    COALESCE((sec.data->>'cveCount')::int, 0) as cve_count,
    COALESCE((sec.data->>'criticalCveCount')::int, 0) as critical_cve_count,

    -- Misc
    sec.data->>'autoLoginUser' as auto_login_user

FROM devices d
LEFT JOIN security sec ON d.serial_number = sec.device_id
LEFT JOIN inventory inv ON d.serial_number = inv.device_id
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND sec.data IS NOT NULL
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY d.serial_number, sec.updated_at DESC;
