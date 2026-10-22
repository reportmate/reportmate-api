-- Card 10, Local Admin Exposure: local administrator counts and directory
-- join per device, reduced in Postgres. Join rules are the ones the identity
-- report directory donut applies to GET /identity directoryServices.
WITH fleet AS (/*FLEET*/),
i AS (
    SELECT f.serial, f.platform, f.device_name, f.id, ident.data AS d
    FROM fleet f
    JOIN identity ident ON ident.device_id = f.serial
    WHERE ident.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
),
parts AS (
    SELECT i.serial, i.platform, i.device_name, i.id,
           CASE
               WHEN jsonb_array_length(CASE WHEN jsonb_typeof(d->'users') = 'array' THEN d->'users' ELSE '[]'::jsonb END) > 0 THEN d->'users'
               WHEN jsonb_typeof(d->'userAccounts') = 'array' THEN d->'userAccounts'
               ELSE '[]'::jsonb
           END AS users,
           COALESCE(NULLIF(NULLIF(d->'directoryServices', 'null'::jsonb), '{}'::jsonb),
                    d->'directory_services', '{}'::jsonb) AS ds
    FROM i
),
x AS (
    SELECT serial, platform, device_name, id,
           (SELECT COUNT(*) FROM jsonb_array_elements(users) u
             WHERE jsonb_typeof(u) = 'object' AND COALESCE(LOWER(u->>'isAdmin') IN {{TRUE}}, FALSE)) AS admins,
           COALESCE(
               LOWER(az->>'joined') IN {{TRUE}} OR LOWER(az->>'is_aad_joined') IN {{TRUE}}
               OR LOWER(az->>'isAadJoined') IN {{TRUE}} OR LOWER(az->>'is_entra_joined') IN {{TRUE}}
               OR LOWER(az->>'isEntraJoined') IN {{TRUE}}, FALSE) AS entra,
           COALESCE(
               LOWER(ad->>'bound') IN {{TRUE}} OR LOWER(ad->>'is_domain_joined') IN {{TRUE}}
               OR LOWER(ad->>'isDomainJoined') IN {{TRUE}}, FALSE) AS domain
    FROM parts
    CROSS JOIN LATERAL (
        SELECT COALESCE(NULLIF(ds->'azureAd', '{}'::jsonb), NULLIF(ds->'azure_ad', '{}'::jsonb),
                        NULLIF(ds->'entraId', '{}'::jsonb), ds->'entra_id') AS az,
               COALESCE(NULLIF(ds->'activeDirectory', '{}'::jsonb), ds->'active_directory') AS ad
    ) dirs
)
SELECT
    platform,
    COUNT(*) AS devices,
    COUNT(*) FILTER (WHERE admins > 1) AS extra_admins,
    COUNT(*) FILTER (WHERE admins = 2) AS admins_2,
    COUNT(*) FILTER (WHERE admins = 3) AS admins_3,
    COUNT(*) FILTER (WHERE admins >= 4) AS admins_4_plus,
    COUNT(*) FILTER (WHERE entra AND domain) AS hybrid,
    COUNT(*) FILTER (WHERE entra AND NOT domain) AS entra,
    COUNT(*) FILTER (WHERE domain AND NOT entra) AS domain,
    COUNT(*) FILTER (WHERE NOT entra AND NOT domain) AS workgroup
FROM x
GROUP BY platform
ORDER BY platform
