-- Card 7, OS Currency: device counts per reported OS version. The currency
-- rules are relative to the whole fleet, so this is not platform filtered;
-- dashboard_insights.os_currency applies the rules and the platform filter.
WITH fleet AS (/*FLEET*/),
o AS (
    SELECT COALESCE(NULLIF(NULLIF(sd->'operating_system', 'null'::jsonb), '{}'::jsonb),
                    sd->'operatingSystem', '{}'::jsonb) AS os
    FROM fleet f
    JOIN system s ON s.device_id = f.serial
    CROSS JOIN LATERAL (
        SELECT CASE WHEN jsonb_typeof(s.data) = 'array' THEN s.data->0 ELSE s.data END AS sd
    ) x
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
GROUP BY 1, 2, 3, 4, 5, 6, 7
