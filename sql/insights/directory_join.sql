-- Card: Directory Join. Per platform, the directory state of each device,
-- extra local administrators (more than one) and inventory usage.
-- Windows: Entra, domain, hybrid or workgroup, from directoryServices as the
-- identity report reads it. Mac: Platform SSO registered (or Entra joined),
-- bound to AD or LDAP, or not bound, the identity report auth rules.
WITH fleet AS (/*FLEET*/),
i AS (
    SELECT f.platform, f.id, ident.data AS d
    FROM fleet f
    JOIN identity ident ON ident.device_id = f.serial
    WHERE ident.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
),
parts AS (
    SELECT i.platform, i.id,
           CASE
               WHEN jsonb_array_length(CASE WHEN jsonb_typeof(d->'users') = 'array' THEN d->'users' ELSE '[]'::jsonb END) > 0 THEN d->'users'
               WHEN jsonb_typeof(d->'userAccounts') = 'array' THEN d->'userAccounts'
               ELSE '[]'::jsonb
           END AS users,
           COALESCE(NULLIF(NULLIF(d->'directoryServices', 'null'::jsonb), '{}'::jsonb),
                    d->'directory_services', '{}'::jsonb) AS ds,
           COALESCE(NULLIF(d->'platformSSOUsers', 'null'::jsonb), d->'platform_sso_users', '{}'::jsonb) AS psso
    FROM i
),
x AS (
    SELECT p.platform,
           (SELECT COUNT(*) FROM jsonb_array_elements(p.users) u
             WHERE jsonb_typeof(u) = 'object' AND COALESCE(LOWER(u->>'isAdmin') IN {{TRUE}}, FALSE)) AS admins,
           COALESCE(
               LOWER(az->>'joined') IN {{TRUE}} OR LOWER(az->>'is_aad_joined') IN {{TRUE}}
               OR LOWER(az->>'isAadJoined') IN {{TRUE}} OR LOWER(az->>'is_entra_joined') IN {{TRUE}}
               OR LOWER(az->>'isEntraJoined') IN {{TRUE}}, FALSE) AS entra,
           COALESCE(
               LOWER(ad->>'bound') IN {{TRUE}} OR LOWER(ad->>'is_domain_joined') IN {{TRUE}}
               OR LOWER(ad->>'isDomainJoined') IN {{TRUE}}, FALSE) AS domain,
           COALESCE(LOWER(p.ds->'ldap'->>'bound') IN {{TRUE}}, FALSE) AS ldap,
           COALESCE(LOWER(COALESCE(p.psso->>'deviceRegistered', p.psso->>'device_registered')) IN {{TRUE}}, FALSE) AS psso,
           LOWER(COALESCE(inv.data->>'usage', '')) AS usage
    FROM parts p
    LEFT JOIN inventory inv ON inv.device_id = p.id
    CROSS JOIN LATERAL (
        SELECT COALESCE(NULLIF(p.ds->'azureAd', '{}'::jsonb), NULLIF(p.ds->'azure_ad', '{}'::jsonb),
                        NULLIF(p.ds->'entraId', '{}'::jsonb), p.ds->'entra_id') AS az,
               COALESCE(NULLIF(p.ds->'activeDirectory', '{}'::jsonb), p.ds->'active_directory') AS ad
    ) dirs
)
SELECT
    platform,
    COUNT(*) AS devices,
    COUNT(*) FILTER (WHERE entra AND domain) AS hybrid,
    COUNT(*) FILTER (WHERE entra AND NOT domain) AS entra,
    COUNT(*) FILTER (WHERE domain AND NOT entra) AS domain,
    COUNT(*) FILTER (WHERE NOT entra AND NOT domain) AS workgroup,
    COUNT(*) FILTER (WHERE psso OR entra) AS mac_psso,
    COUNT(*) FILTER (WHERE NOT (psso OR entra) AND (domain OR ldap)) AS mac_bound,
    COUNT(*) FILTER (WHERE NOT (psso OR entra) AND NOT (domain OR ldap)) AS mac_unbound,
    COUNT(*) FILTER (WHERE admins > 1) AS extra_admins,
    COUNT(*) FILTER (WHERE usage LIKE '%%shared%%') AS shared,
    COUNT(*) FILTER (WHERE usage NOT LIKE '%%shared%%' AND usage LIKE '%%assigned%%') AS assigned
FROM x
GROUP BY platform
ORDER BY platform
