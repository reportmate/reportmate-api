-- Extract unique application names, publishers, categories from JSONB arrays
-- Used by /api/devices/applications/filters to avoid downloading all records
-- Parameters: include_archived (boolean)

SELECT DISTINCT
    COALESCE(elem->>'name', elem->>'displayName') as app_name,
    COALESCE(elem->>'publisher', elem->>'signed_by', elem->>'vendor') as publisher,
    elem->>'category' as category,
    COALESCE(sys.data->'operatingSystem'->>'platform', 'Unknown') as platform
FROM devices d
JOIN applications a ON d.id = a.device_id
LEFT JOIN system sys ON d.id = sys.device_id
CROSS JOIN LATERAL jsonb_array_elements(
    CASE
        WHEN a.data ? 'installedApplications' THEN a.data->'installedApplications'
        WHEN a.data ? 'InstalledApplications' THEN a.data->'InstalledApplications'
        WHEN a.data ? 'installed_applications' THEN a.data->'installed_applications'
        WHEN jsonb_typeof(a.data) = 'array' THEN a.data
        ELSE '[]'::jsonb
    END
) AS elem
WHERE d.serial_number IS NOT NULL
    AND d.serial_number NOT LIKE 'TEST-%%'
    AND d.serial_number != 'localhost'
    AND a.data IS NOT NULL
    AND (%(include_archived)s = TRUE OR d.archived = FALSE)
ORDER BY app_name;
