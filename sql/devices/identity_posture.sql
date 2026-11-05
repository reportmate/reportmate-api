-- Sign-in and recovery posture, one row per device: /api/v1/identity/posture
-- Projects only the posture fields from the identity and security modules,
-- never the full module documents. Values are passed through as collected;
-- the router decides what counts as true, false or unknown.
-- Parameters: include_archived (boolean), platform ('' | 'windows' | 'macos')

SELECT jsonb_build_object(
    'serialNumber', d.serial_number,
    'deviceName', COALESCE(inv.data->>'deviceName', inv.data->>'device_name', d.name, d.serial_number),
    'computerName', COALESCE(inv.data->>'computerName', inv.data->>'computer_name'),
    'platform', d.platform,
    'assetTag', COALESCE(inv.data->>'assetTag', inv.data->>'asset_tag'),
    'usage', inv.data->>'usage',
    'catalog', inv.data->>'catalog',
    'area', inv.data->>'department',
    'fleet', inv.data->>'fleet',
    'location', inv.data->>'location',
    'room', COALESCE(inv.data->>'room', inv.data->>'location'),
    'archived', d.archived,
    'inventoryState', ist.state,
    'lastSeen', d.last_seen,
    'identityReported', jsonb_typeof(ident.data) = 'object',
    'securityReported', jsonb_typeof(sec.data) = 'object',
    'identityCollectedAt', COALESCE(ident.data->>'collectedAt', ident.data->>'collected_at', ident.collected_at::text),
    'securityCollectedAt', COALESCE(sec.data->>'collectedAt', sec.data->>'collected_at', sec.collected_at::text),
    'windows', jsonb_build_object(
        'laps', ident.data->'laps',
        'autoLogin', CASE WHEN jsonb_typeof(ident.data->'autoLogin') = 'object' THEN jsonb_build_object(
            'autoAdminLogon', ident.data->'autoLogin'->'autoAdminLogon',
            'hasDefaultPassword', ident.data->'autoLogin'->'hasDefaultPassword'
        ) END,
        'uac', ident.data->'uac',
        'passwordPolicy', ident.data->'passwordPolicy',
        'helloStatus', ident.data->'windowsHello'->'statusDisplay',
        'credentialProviders', CASE WHEN jsonb_typeof(ident.data->'windowsHello'->'credentialProviders') = 'object' THEN jsonb_build_object(
            'pinEnabled', ident.data->'windowsHello'->'credentialProviders'->'pinEnabled',
            'fingerprintEnabled', ident.data->'windowsHello'->'credentialProviders'->'fingerprintEnabled',
            'faceRecognitionEnabled', ident.data->'windowsHello'->'credentialProviders'->'faceRecognitionEnabled',
            'smartCardEnabled', ident.data->'windowsHello'->'credentialProviders'->'smartCardEnabled'
        ) END,
        'credentialGuard', CASE WHEN jsonb_typeof(ident.data->'windowsHello'->'credentialGuard') = 'object' THEN jsonb_build_object(
            'isEnabled', ident.data->'windowsHello'->'credentialGuard'->'isEnabled',
            'isConfigured', ident.data->'windowsHello'->'credentialGuard'->'isConfigured'
        ) END,
        'tpmOwnership', ident.data->'tpmOwnership',
        'failedLoginsLast7Days', ident.data->'summary'->'failedLoginsLast7Days'
    ),
    'mac', jsonb_build_object(
        'platformSSO', CASE WHEN jsonb_typeof(ident.data->'platformSSOUsers') = 'object' THEN jsonb_build_object(
            'supported', ident.data->'platformSSOUsers'->'supported',
            'deviceRegistered', ident.data->'platformSSOUsers'->'deviceRegistered',
            'provider', ident.data->'platformSSOUsers'->'provider',
            'users', COALESCE((
                SELECT jsonb_agg(jsonb_build_object(
                    'username', u->>'username',
                    'registered', u->'registered',
                    'tokenExpiration', u->>'tokenExpiration',
                    'tokenExpired', u->'tokenExpired'
                ) ORDER BY u->>'username')
                FROM jsonb_array_elements(CASE WHEN jsonb_typeof(ident.data->'platformSSOUsers'->'users') = 'array'
                    THEN ident.data->'platformSSOUsers'->'users' ELSE '[]'::jsonb END) u
                WHERE jsonb_typeof(u) = 'object'
            ), '[]'::jsonb)
        ) END,
        'secureToken', COALESCE(ident.data->'secureTokenUsers', sec.data->'secureToken'),
        'activationLock', CASE WHEN jsonb_typeof(sec.data->'activationLock') = 'object' THEN jsonb_build_object(
            'status', sec.data->'activationLock'->'status',
            'findMyMac', sec.data->'activationLock'->'findMyMac'
        ) END,
        'fileVault', CASE WHEN jsonb_typeof(sec.data->'fileVault') = 'object' THEN jsonb_build_object(
            'enabled', sec.data->'fileVault'->'enabled',
            'status', sec.data->'fileVault'->'status',
            'personalRecoveryKey', sec.data->'fileVault'->'personalRecoveryKey',
            'institutionalRecoveryKey', sec.data->'fileVault'->'institutionalRecoveryKey'
        ) END,
        'bootstrapToken', CASE WHEN jsonb_typeof(sec.data->'bootstrapToken') = 'object' THEN jsonb_build_object(
            'status', sec.data->'bootstrapToken'->'status',
            'escrowed', sec.data->'bootstrapToken'->'escrowed',
            'supported', sec.data->'bootstrapToken'->'supported'
        ) END
    )
)
FROM devices d
LEFT JOIN identity ident ON ident.device_id = d.serial_number
LEFT JOIN security sec ON sec.device_id = d.serial_number
LEFT JOIN inventory inv ON inv.device_id = d.serial_number
LEFT JOIN device_inventory_state ist ON ist.serial_number = upper(trim(d.serial_number))
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
    AND (
        %(platform)s = ''
        OR CASE
            WHEN lower(COALESCE(d.platform, '')) LIKE '%%windows%%' THEN 'windows'
            WHEN lower(COALESCE(d.platform, '')) LIKE '%%mac%%'
                OR lower(COALESCE(d.platform, '')) LIKE '%%darwin%%' THEN 'macos'
            ELSE lower(COALESCE(d.platform, ''))
        END = %(platform)s
    )
ORDER BY lower(COALESCE(inv.data->>'deviceName', inv.data->>'device_name', d.name, d.serial_number)), d.serial_number;
