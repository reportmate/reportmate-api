-- The management tool log roots the Management Tools Logs card counts, one
-- row per device and root. Not a query on its own: card_sql substitutes it
-- for /*MANAGEMENT_ROOTS*/ inside a WITH, after the fleet CTE.
--
-- The MDM agent is not a management tool, so its logs are left out without
-- naming any one MDM. A root is dropped when the runner tagged it as the MDM
-- or enrollment agent (tool mdm or enrollment), or when its tool key or name
-- names the MDM the device is enrolled in, as the management module reports it
-- (provider, or the server and check-in URLs that GET /management reads).
SELECT f.serial, f.id, f.platform, f.device_name,
       LOWER(COALESCE(root->>'tool', '')) AS tool,
       root->'levelSummary' AS s
FROM fleet f
JOIN management m ON m.device_id = f.id
CROSS JOIN LATERAL (
    SELECT LOWER(CONCAT_WS(' ',
               me->>'provider', me->>'serverUrl', me->>'server_url',
               me->>'checkinUrl', me->>'checkin_url')) AS enrollment
    FROM (SELECT COALESCE(NULLIF(NULLIF(m.data->'mdmEnrollment', 'null'::jsonb), '{}'::jsonb),
                          m.data->'mdm_enrollment') AS me) x
) mdm
CROSS JOIN LATERAL (
    SELECT CASE
        WHEN mdm.enrollment ~ '(intune|manage\.microsoft\.com)' THEN 'intune'
        WHEN mdm.enrollment ~ 'jamf' THEN 'jamf'
        WHEN mdm.enrollment ~ 'kandji' THEN 'kandji'
        WHEN mdm.enrollment ~ 'mosyle' THEN 'mosyle'
        WHEN mdm.enrollment ~ '(workspace ?one|airwatch|awmdm)' THEN 'workspace ?one|airwatch|intelligent ?hub'
        WHEN mdm.enrollment ~ 'micromdm' THEN 'micromdm'
        WHEN mdm.enrollment ~ 'nanomdm' THEN 'nanomdm'
        WHEN mdm.enrollment ~ 'addigy' THEN 'addigy'
        WHEN mdm.enrollment ~ 'simplemdm' THEN 'simplemdm'
        ELSE NULL
    END AS agent
) provider
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(m.data->'logs'->'roots') = 'array' THEN m.data->'logs'->'roots' ELSE '[]'::jsonb END) root
WHERE m.data IS NOT NULL
  AND (%(platform)s = 'all' OR f.platform = %(platform)s)
  AND jsonb_typeof(root) = 'object'
  AND jsonb_typeof(root->'levelSummary') = 'object'
  AND COALESCE(root->>'tool', '') <> ''
  AND LOWER(root->>'tool') NOT IN ('mdm', 'enrollment')
  AND NOT COALESCE(LOWER(CONCAT_WS(' ', root->>'tool', root->>'name')) ~ provider.agent, FALSE)
