-- Extract unique application names, publishers, categories from JSONB arrays
-- Used by /api/devices/applications/filters to avoid downloading all records
-- Parameters: include_archived (boolean)
--
-- Deduplicates at the device level first (one applications row per device)
-- before unnesting, to avoid multiplicative cross products.

WITH device_base AS (
    SELECT DISTINCT ON (d.serial_number)
        d.id,
        COALESCE(
            sys.data->'operatingSystem'->>'platform',
            d.platform,
            'Unknown'
        ) AS platform,
        CASE
            WHEN a.data ? 'installedApplications' THEN a.data->'installedApplications'
            WHEN a.data ? 'InstalledApplications' THEN a.data->'InstalledApplications'
            WHEN a.data ? 'installed_applications' THEN a.data->'installed_applications'
            WHEN jsonb_typeof(a.data) = 'array' THEN a.data
            ELSE '[]'::jsonb
        END AS apps_array
    FROM devices d
    JOIN applications a ON d.id = a.device_id
    LEFT JOIN system sys ON d.id = sys.device_id
    WHERE d.serial_number IS NOT NULL
        AND d.serial_number NOT LIKE 'TEST-%%'
        AND d.serial_number != 'localhost'
        AND a.data IS NOT NULL
        AND (%(include_archived)s = TRUE OR d.archived = FALSE)
    ORDER BY d.serial_number, a.updated_at DESC
)
SELECT DISTINCT
    COALESCE(elem->>'name', elem->>'displayName') AS app_name,
    COALESCE(elem->>'publisher', elem->>'signed_by', elem->>'vendor') AS publisher,
    elem->>'category' AS category,
    platform
FROM device_base
CROSS JOIN LATERAL jsonb_array_elements(apps_array) AS elem
WHERE COALESCE(elem->>'name', elem->>'displayName') IS NOT NULL
ORDER BY app_name;
