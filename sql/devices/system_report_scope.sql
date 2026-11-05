WITH platformed AS NOT MATERIALIZED (
    SELECT d.serial_number,
        COALESCE(inv.data->>'deviceName', inv.data->>'device_name', d.name, d.serial_number) AS device_name,
        COALESCE(sys.data->'operatingSystem'->>'computerName', sys.data->'operatingSystem'->>'hostname',
            net.data->>'hostname', inv.data->>'computerName', inv.data->>'computer_name') AS hostname,
        COALESCE(sys.data->'operatingSystem'->>'name', d.platform) AS platform,
        COALESCE(inv.data->>'assetTag', inv.data->>'asset_tag') AS asset_tag,
        inv.data->>'usage' AS usage, inv.data->>'catalog' AS catalog,
        inv.data->>'department' AS area, inv.data->>'fleet' AS fleet,
        inv.data->>'location' AS location,
        COALESCE(inv.data->>'room', inv.data->>'location') AS room,
        d.archived, d.last_seen,
        COALESCE(ist.state, 'unknown') AS inventory_state,
        COALESCE(sys.data->>'collectedAt', sys.data->>'collected_at', sys.collected_at::text) AS collected_at,
        sys.data AS system_data,
        CASE
            WHEN lower(COALESCE(sys.data->'operatingSystem'->>'name', d.platform, '')) LIKE '%%windows%%' THEN 'windows'
            WHEN lower(COALESCE(sys.data->'operatingSystem'->>'name', d.platform, '')) LIKE '%%mac%%'
                OR lower(COALESCE(sys.data->'operatingSystem'->>'name', d.platform, '')) LIKE '%%darwin%%' THEN 'macos'
            ELSE lower(COALESCE(sys.data->'operatingSystem'->>'name', d.platform, ''))
        END AS platform_key
    FROM devices d
    LEFT JOIN system sys ON sys.device_id = d.serial_number
    LEFT JOIN inventory inv ON inv.device_id = d.serial_number
    LEFT JOIN network net ON net.device_id = d.serial_number
    LEFT JOIN device_inventory_state ist ON ist.serial_number = upper(trim(d.serial_number))
    WHERE d.serial_number IS NOT NULL
        AND d.serial_number NOT LIKE 'TEST-%%'
        AND d.serial_number != 'localhost'
        AND (%(include_archived)s OR d.archived = FALSE)
), base AS NOT MATERIALIZED (
    SELECT * FROM platformed WHERE %(platform)s = '' OR platform_key = %(platform)s
), scoped AS NOT MATERIALIZED (
    SELECT * FROM base WHERE TRUE
        AND (%(usages)s::text[] = '{}' OR lower(usage) = ANY(%(usages)s))
        AND (%(catalogs)s::text[] = '{}' OR lower(catalog) = ANY(%(catalogs)s))
        AND (%(areas)s::text[] = '{}' OR lower(area) = ANY(%(areas)s))
        AND (%(fleets)s::text[] = '{}' OR lower(fleet) = ANY(%(fleets)s))
        AND (%(locations)s::text[] = '{}' OR lower(location) = ANY(%(locations)s))
        AND (%(rooms)s::text[] = '{}' OR lower(room) = ANY(%(rooms)s))
        AND (%(inventory_states)s::text[] = '{}' OR lower(inventory_state) = ANY(%(inventory_states)s))
)
