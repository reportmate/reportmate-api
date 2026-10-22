-- Card 10: the devices with the most local administrators.
WITH fleet AS (/*FLEET*/),
x AS (
    SELECT f.serial, f.platform, f.id, f.device_name,
           (SELECT COUNT(*) FROM jsonb_array_elements(
                CASE
                    WHEN jsonb_array_length(CASE WHEN jsonb_typeof(ident.data->'users') = 'array' THEN ident.data->'users' ELSE '[]'::jsonb END) > 0 THEN ident.data->'users'
                    WHEN jsonb_typeof(ident.data->'userAccounts') = 'array' THEN ident.data->'userAccounts'
                    ELSE '[]'::jsonb
                END) u
             WHERE jsonb_typeof(u) = 'object' AND COALESCE(LOWER(u->>'isAdmin') IN {{TRUE}}, FALSE)) AS admins
    FROM fleet f
    JOIN identity ident ON ident.device_id = f.serial
    WHERE ident.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
)
SELECT x.serial,
       COALESCE(NULLIF(inv.data->>'device_name', ''), NULLIF(inv.data->>'deviceName', ''),
                NULLIF(x.device_name, ''), x.serial) AS name,
       x.platform,
       x.admins
FROM x
LEFT JOIN inventory inv ON inv.device_id = x.id
WHERE x.admins > 1
ORDER BY x.admins DESC, x.serial
LIMIT %(limit)s
