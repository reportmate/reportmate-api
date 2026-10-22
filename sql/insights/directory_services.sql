-- Directory Services: the Identity report Directory Services classification,
-- applied to the same fields GET /identity returns (the identity route reads
-- them as JavaScript truthiness, mirrored here as not false, 0, "" or null):
--   domainJoined = activeDirectory bound or isDomainJoined
--   entraJoined  = azureAd joined (any of the joined flags GET /identity folds
--                  into it) or Platform SSO deviceRegistered
--   Domain Joined when domain joined (with or without Entra), else Cloud
--   Joined when Entra joined, else Unjoined when directoryServices names a
--   workgroup, else Standard.
-- Domain Joined splits by domainTrust.trustStatus: Healthy is Trusted, Broken
-- is Broken, anything else Unconfirmed. Also extra local admins (more than
-- one) and inventory usage.
WITH fleet AS (/*FLEET*/),
i AS (
    SELECT f.id, ident.data AS d
    FROM fleet f
    JOIN identity ident ON ident.device_id = f.serial
    WHERE ident.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
),
parts AS (
    SELECT i.id,
           CASE
               WHEN jsonb_array_length(CASE WHEN jsonb_typeof(d->'users') = 'array' THEN d->'users' ELSE '[]'::jsonb END) > 0 THEN d->'users'
               WHEN jsonb_typeof(d->'userAccounts') = 'array' THEN d->'userAccounts'
               ELSE '[]'::jsonb
           END AS users,
           COALESCE(NULLIF(NULLIF(d->'directoryServices', 'null'::jsonb), '{}'::jsonb),
                    NULLIF(d->'directory_services', 'null'::jsonb), '{}'::jsonb) AS ds,
           COALESCE(NULLIF(NULLIF(d->'platformSSOUsers', 'null'::jsonb), '{}'::jsonb),
                    NULLIF(d->'platform_sso_users', 'null'::jsonb), '{}'::jsonb) AS psso,
           d->'domainTrust'->>'trustStatus' AS trust
    FROM i
),
x AS (
    SELECT p.id, p.trust,
           (SELECT COUNT(*) FROM jsonb_array_elements(p.users) u
             WHERE jsonb_typeof(u) = 'object' AND COALESCE(LOWER(u->>'isAdmin') IN {{TRUE}}, FALSE)) AS admins,
           (
               COALESCE(ad->'bound' NOT IN {{JS_FALSY}}, FALSE)
               OR COALESCE(COALESCE(NULLIF(ad->'is_domain_joined', 'null'::jsonb), ad->'isDomainJoined') NOT IN {{JS_FALSY}}, FALSE)
           ) AS domain_joined,
           (
               COALESCE(az->'joined' NOT IN {{JS_FALSY}}, FALSE)
               OR COALESCE(az->'is_aad_joined' NOT IN {{JS_FALSY}}, FALSE)
               OR COALESCE(az->'isAadJoined' NOT IN {{JS_FALSY}}, FALSE)
               OR COALESCE(az->'is_entra_joined' NOT IN {{JS_FALSY}}, FALSE)
               OR COALESCE(az->'isEntraJoined' NOT IN {{JS_FALSY}}, FALSE)
               OR COALESCE(COALESCE(NULLIF(p.psso->'deviceRegistered', 'null'::jsonb), p.psso->'device_registered') NOT IN {{JS_FALSY}}, FALSE)
           ) AS entra_joined,
           COALESCE(p.ds->'workgroup' NOT IN {{JS_FALSY}}, FALSE) AS workgroup,
           LOWER(COALESCE(inv.data->>'usage', '')) AS usage
    FROM parts p
    LEFT JOIN inventory inv ON inv.device_id = p.id
    CROSS JOIN LATERAL (
        SELECT COALESCE(NULLIF(NULLIF(p.ds->'azureAd', 'null'::jsonb), '{}'::jsonb),
                        NULLIF(NULLIF(p.ds->'azure_ad', 'null'::jsonb), '{}'::jsonb),
                        NULLIF(NULLIF(p.ds->'entraId', 'null'::jsonb), '{}'::jsonb),
                        p.ds->'entra_id') AS az,
               COALESCE(NULLIF(NULLIF(p.ds->'activeDirectory', 'null'::jsonb), '{}'::jsonb),
                        p.ds->'active_directory') AS ad
    ) dirs
),
classified AS (
    SELECT x.*,
           CASE
               WHEN domain_joined THEN 'Domain Joined'
               WHEN entra_joined THEN 'Cloud Joined'
               WHEN workgroup THEN 'Unjoined'
               ELSE 'Standard'
           END AS directory
    FROM x
)
SELECT
    COUNT(*) AS devices,
    COUNT(*) FILTER (WHERE directory = 'Cloud Joined') AS cloud_joined,
    COUNT(*) FILTER (WHERE directory = 'Domain Joined') AS domain_joined,
    COUNT(*) FILTER (WHERE directory = 'Domain Joined' AND trust = 'Healthy') AS trusted,
    COUNT(*) FILTER (WHERE directory = 'Domain Joined' AND trust = 'Broken') AS broken,
    COUNT(*) FILTER (WHERE directory = 'Domain Joined' AND trust IS DISTINCT FROM 'Healthy'
                                                       AND trust IS DISTINCT FROM 'Broken') AS unconfirmed,
    COUNT(*) FILTER (WHERE directory = 'Standard') AS standard,
    COUNT(*) FILTER (WHERE directory = 'Unjoined') AS unjoined,
    COUNT(*) FILTER (WHERE admins > 1) AS extra_admins,
    COUNT(*) FILTER (WHERE usage LIKE '%%shared%%') AS shared,
    COUNT(*) FILTER (WHERE usage NOT LIKE '%%shared%%' AND usage LIKE '%%assigned%%') AS assigned
FROM classified
