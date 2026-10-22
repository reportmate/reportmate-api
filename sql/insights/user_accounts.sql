-- User Accounts: the Identity report Authentication donut and the extra local
-- admins count, from the identity fields GET /identity returns and the
-- identity route reads (JavaScript truthiness, as not false, 0, "" or null).
--   Modern   = Platform SSO deviceRegistered, or Windows Hello statusDisplay
--              set and not starting with Disabled (the route authMethod)
--   Legacy   = not Modern, and bound to Active Directory or LDAP
--   Standard = everything else
-- Extra local admins is the report "more than one admin": adminUsers > 1,
-- where adminUsers counts the users flagged isAdmin.
WITH fleet AS (/*FLEET*/),
i AS (
    SELECT ident.data AS d
    FROM fleet f
    JOIN identity ident ON ident.device_id = f.serial
    WHERE ident.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
),
parts AS (
    SELECT
        CASE
            WHEN jsonb_array_length(CASE WHEN jsonb_typeof(d->'users') = 'array' THEN d->'users' ELSE '[]'::jsonb END) > 0 THEN d->'users'
            WHEN jsonb_typeof(d->'userAccounts') = 'array' THEN d->'userAccounts'
            ELSE '[]'::jsonb
        END AS users,
        COALESCE(NULLIF(NULLIF(d->'directoryServices', 'null'::jsonb), '{}'::jsonb),
                 NULLIF(d->'directory_services', 'null'::jsonb), '{}'::jsonb) AS ds,
        COALESCE(NULLIF(NULLIF(d->'platformSSOUsers', 'null'::jsonb), '{}'::jsonb),
                 NULLIF(d->'platform_sso_users', 'null'::jsonb), '{}'::jsonb) AS psso,
        d->'windowsHello'->>'statusDisplay' AS hello
    FROM i
),
x AS (
    SELECT
        (SELECT COUNT(*) FROM jsonb_array_elements(p.users) u
          WHERE jsonb_typeof(u) = 'object' AND COALESCE(u->'isAdmin' NOT IN {{JS_FALSY}}, FALSE)) AS admins,
        (COALESCE(COALESCE(NULLIF(p.psso->'deviceRegistered', 'null'::jsonb), p.psso->'device_registered') NOT IN {{JS_FALSY}}, FALSE)
         OR (COALESCE(p.hello, '') <> '' AND p.hello NOT LIKE 'Disabled%%')) AS modern,
        (COALESCE(COALESCE(NULLIF(NULLIF(p.ds->'activeDirectory', 'null'::jsonb), '{}'::jsonb), p.ds->'active_directory')->'bound' NOT IN {{JS_FALSY}}, FALSE)
         OR COALESCE(p.ds->'ldap'->'bound' NOT IN {{JS_FALSY}}, FALSE)) AS bound
    FROM parts p
)
SELECT
    COUNT(*) AS devices,
    COUNT(*) FILTER (WHERE modern) AS modern,
    COUNT(*) FILTER (WHERE NOT modern AND bound) AS legacy,
    COUNT(*) FILTER (WHERE NOT modern AND NOT bound) AS standard,
    COUNT(*) FILTER (WHERE admins > 1) AS extra_admins
FROM x
