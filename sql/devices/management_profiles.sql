-- Fleet configuration profile / managed preference coverage: /api/v1/management/profiles
-- One row per device with only the entries matching the selected identifiers,
-- never the full management document.
-- Parameters: kind ('profile' | 'preference'), identifiers (text[] lowercased),
--             preference_key (text, lowercased, '' for none), include_archived (boolean)

WITH base AS NOT MATERIALIZED (
    SELECT d.serial_number, d.archived, d.last_seen, d.platform, d.os_name,
        m.data AS mdata, m.collected_at AS m_collected_at,
        inv.data AS idata, ist.state AS inventory_state,
        CASE
            WHEN jsonb_typeof(m.data->'installed_profiles') = 'array' THEN m.data->'installed_profiles'
            WHEN jsonb_typeof(m.data->'installedProfiles') = 'array' THEN m.data->'installedProfiles'
            WHEN jsonb_typeof(m.data->'configurationProfiles') = 'array' THEN m.data->'configurationProfiles'
            WHEN jsonb_typeof(m.data->'configuration_profiles') = 'array' THEN m.data->'configuration_profiles'
        END AS profile_list,
        CASE
            WHEN jsonb_typeof(m.data->'managed_policies') = 'array' THEN m.data->'managed_policies'
            WHEN jsonb_typeof(m.data->'managedPolicies') = 'array' THEN m.data->'managedPolicies'
        END AS preference_list
    FROM devices d
    LEFT JOIN management m ON m.device_id = d.id
    LEFT JOIN inventory inv ON inv.device_id = d.id
    LEFT JOIN device_inventory_state ist ON ist.serial_number = upper(trim(d.serial_number))
    WHERE d.serial_number IS NOT NULL
        AND d.serial_number NOT LIKE 'TEST-%%'
        AND d.serial_number != 'localhost'
        AND (%(include_archived)s = TRUE OR d.archived = FALSE)
)
SELECT jsonb_build_object(
    'serialNumber', serial_number,
    'deviceName', COALESCE(idata->>'deviceName', idata->>'device_name', idata->>'computerName', idata->>'computer_name', serial_number),
    'platform', COALESCE(platform, os_name),
    'osName', os_name,
    'assetTag', COALESCE(idata->>'assetTag', idata->>'asset_tag'),
    'usage', idata->>'usage',
    'catalog', idata->>'catalog',
    'area', idata->>'department',
    'fleet', idata->>'fleet',
    'location', idata->>'location',
    'room', COALESCE(idata->>'room', idata->>'location'),
    'archived', archived,
    'inventoryState', inventory_state,
    'lastSeen', last_seen,
    'hasManagement', mdata IS NOT NULL,
    'collectedAt', COALESCE(mdata->>'collectedAt', mdata->>'collected_at', m_collected_at::text),
    'inventoryCount', CASE WHEN %(kind)s = 'profile'
        THEN COALESCE(jsonb_array_length(profile_list), 0)
        ELSE COALESCE(jsonb_array_length(preference_list), 0) END,
    'inventoryAvailable', CASE WHEN %(kind)s = 'profile'
        THEN profile_list IS NOT NULL AND jsonb_array_length(profile_list) > 0
        ELSE preference_list IS NOT NULL AND jsonb_array_length(preference_list) > 0 END,
    'matches', CASE WHEN %(kind)s = 'profile' THEN COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
            'key', lower(COALESCE(NULLIF(p->>'identifier', ''), NULLIF(p->>'uuid', ''), NULLIF(p->>'profile_name', ''), NULLIF(p->>'profileName', ''), p->>'name')),
            'identifier', COALESCE(NULLIF(p->>'identifier', ''), NULLIF(p->>'uuid', ''), NULLIF(p->>'profile_name', ''), NULLIF(p->>'profileName', ''), p->>'name'),
            'name', COALESCE(NULLIF(p->>'name', ''), NULLIF(p->>'profile_name', ''), p->>'profileName'),
            'uuid', p->>'uuid',
            'version', COALESCE(p->>'version', p->>'PayloadVersion', p->>'profileVersion', p->>'profile_version'),
            'organization', COALESCE(NULLIF(p->>'organization', ''), NULLIF(p->>'source', '')),
            'installDate', COALESCE(p->>'install_date', p->>'installDate'),
            'user', p->>'user',
            'type', p->>'type',
            'source', p->>'source',
            'status', p->>'status',
            'verificationState', COALESCE(p->>'verification_state', p->>'verificationState'),
            'removalDisallowed', COALESCE(p->'removal_disallowed', p->'removalDisallowed'),
            'payloadCount', COALESCE(p->'payload_count', p->'payloadCount',
                CASE WHEN jsonb_typeof(p->'payloads') = 'array' THEN to_jsonb(jsonb_array_length(p->'payloads')) END)
        ))
        FROM jsonb_array_elements(COALESCE(profile_list, '[]'::jsonb)) p
        WHERE jsonb_typeof(p) = 'object'
            AND lower(COALESCE(NULLIF(p->>'identifier', ''), NULLIF(p->>'uuid', ''), NULLIF(p->>'profile_name', ''), NULLIF(p->>'profileName', ''), p->>'name', ''))
                = ANY(%(identifiers)s::text[])
    ), '[]'::jsonb) ELSE COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
            'key', lower(pol->>'domain'),
            'identifier', pol->>'domain',
            'name', pol->>'domain',
            'settingCount', COALESCE(pol->'setting_count', pol->'settingCount',
                CASE WHEN jsonb_typeof(pol->'settings') = 'array' THEN to_jsonb(jsonb_array_length(pol->'settings')) END),
            'scopes', COALESCE((
                SELECT jsonb_agg(DISTINCT s->>'scope')
                FROM jsonb_array_elements(CASE WHEN jsonb_typeof(pol->'settings') = 'array' THEN pol->'settings' ELSE '[]'::jsonb END) s
                WHERE COALESCE(s->>'scope', '') != ''
            ), '[]'::jsonb),
            'values', CASE WHEN %(preference_key)s = '' THEN NULL ELSE COALESCE((
                SELECT jsonb_agg(jsonb_build_object('scope', s->>'scope', 'value', s->>'value') ORDER BY s->>'scope')
                FROM jsonb_array_elements(CASE WHEN jsonb_typeof(pol->'settings') = 'array' THEN pol->'settings' ELSE '[]'::jsonb END) s
                WHERE lower(COALESCE(s->>'name', '')) = %(preference_key)s
            ), '[]'::jsonb) END
        ))
        FROM jsonb_array_elements(COALESCE(preference_list, '[]'::jsonb)) pol
        WHERE jsonb_typeof(pol) = 'object' AND lower(COALESCE(pol->>'domain', '')) = ANY(%(identifiers)s::text[])
    ), '[]'::jsonb) END
)
FROM base
ORDER BY lower(COALESCE(idata->>'deviceName', idata->>'device_name', serial_number)), serial_number;
