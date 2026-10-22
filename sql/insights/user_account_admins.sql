-- User Accounts: administrator account names by the number of devices that
-- have them, as the Identity report Administrator Accounts widget counts
-- adminUsernames (users flagged isAdmin, named by username, userName or name,
-- once per device, case-insensitively).
WITH fleet AS (/*FLEET*/),
admins AS (
    SELECT DISTINCT f.serial, LOWER(n.name) AS name_key, n.name
    FROM fleet f
    JOIN identity ident ON ident.device_id = f.serial
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE
            WHEN jsonb_array_length(CASE WHEN jsonb_typeof(ident.data->'users') = 'array' THEN ident.data->'users' ELSE '[]'::jsonb END) > 0 THEN ident.data->'users'
            WHEN jsonb_typeof(ident.data->'userAccounts') = 'array' THEN ident.data->'userAccounts'
            ELSE '[]'::jsonb
        END) u
    CROSS JOIN LATERAL (SELECT NULLIF(COALESCE(NULLIF(u->>'username', ''), NULLIF(u->>'userName', ''), u->>'name'), '') AS name) n
    WHERE ident.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
      AND jsonb_typeof(u) = 'object'
      AND COALESCE(u->'isAdmin' NOT IN {{JS_FALSY}}, FALSE)
      AND n.name IS NOT NULL
)
SELECT name_key, MIN(name COLLATE "C") AS name, COUNT(DISTINCT serial) AS devices
FROM admins
GROUP BY name_key
ORDER BY devices DESC, name_key COLLATE "C"
LIMIT %(limit)s
