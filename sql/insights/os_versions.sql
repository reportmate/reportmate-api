-- OS Currency: device counts per reported OS version. The currency rules are
-- relative to the whole fleet, so this is not platform filtered;
-- dashboard_insights.os_currency applies the rules and the platform filter.
-- Each system document is read once through jsonb_to_record and only its
-- operating-system object is kept (MATERIALIZED), so the multi-megabyte
-- document is not detoasted again for every field (see reboot_debt.sql).
WITH fleet AS (/*FLEET*/),
o AS MATERIALIZED (
    SELECT COALESCE(NULLIF(NULLIF(r.operating_system, 'null'::jsonb), '{}'::jsonb),
                    NULLIF(r."operatingSystem", 'null'::jsonb), '{}'::jsonb) AS os
    FROM fleet f
    JOIN system s ON s.device_id = f.serial
    CROSS JOIN LATERAL jsonb_to_record(
        CASE WHEN jsonb_typeof(s.data) = 'object' THEN s.data
             WHEN jsonb_typeof(s.data->0) = 'object' THEN s.data->0
             ELSE '{}'::jsonb END
    ) AS r(operating_system jsonb, "operatingSystem" jsonb)
    WHERE s.data IS NOT NULL
)
SELECT
    COALESCE(os->>'platform', '') AS os_platform,
    COALESCE(os->>'name', '') AS os_name,
    COALESCE(os->>'edition', '') AS edition,
    COALESCE(os->>'displayVersion', '') AS display_version,
    COALESCE(os->>'version', '') AS version,
    COALESCE(os->>'build', '') AS build,
    COALESCE(os->>'featureUpdate', os->>'feature_update', '') AS feature_update,
    COUNT(*) AS devices
FROM o
WHERE jsonb_typeof(os) = 'object'
GROUP BY 1, 2, 3, 4, 5, 6, 7
