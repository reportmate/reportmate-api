-- The management tool log roots the Management Tools Logs card counts, one
-- row per device and root. Not a query on its own: card_sql substitutes it
-- for the MANAGEMENT_ROOTS marker inside a WITH, after the fleet CTE.
--
-- A management document carries every log tail and runs large, and each
-- m.data access detoasts all of it again. jsonb_to_record reads it once and
-- keeps only the enrollment block and the logs; the slim subquery then keeps only
-- each root tool, name and levelSummary, so nothing
-- downstream goes back to the document.
--
-- The MDM agent is not a management tool, so its logs are left out without
-- naming any one MDM. A root is dropped when the runner tagged it as the MDM
-- or enrollment agent (tool mdm or enrollment), or when its tool key or name
-- names the MDM the device is enrolled in, as the management module reports it
-- (provider, or the server and check-in URLs that GET /management reads).
SELECT slim.serial, slim.id, slim.platform, slim.device_name,
       LOWER(COALESCE(root->>'tool', '')) AS tool,
       root->'levelSummary' AS s
FROM (
    SELECT f.serial, f.id, f.platform, f.device_name,
           LOWER(CONCAT_WS(' ', me->>'provider', me->>'serverUrl', me->>'server_url',
                                me->>'checkinUrl', me->>'checkin_url')) AS enrollment,
           (SELECT jsonb_agg(jsonb_build_object('tool', x->'tool', 'name', x->'name',
                                                'levelSummary', x->'levelSummary'))
              FROM jsonb_array_elements(
                  CASE WHEN jsonb_typeof(r.logs->'roots') = 'array' THEN r.logs->'roots' ELSE '[]'::jsonb END) x
             WHERE jsonb_typeof(x) = 'object') AS roots
    FROM fleet f
    JOIN management m ON m.device_id = f.id
    CROSS JOIN LATERAL jsonb_to_record(
        CASE WHEN jsonb_typeof(m.data) = 'object' THEN m.data ELSE '{}'::jsonb END
    ) AS r("mdmEnrollment" jsonb, mdm_enrollment jsonb, logs jsonb)
    CROSS JOIN LATERAL (
        SELECT COALESCE(NULLIF(NULLIF(r."mdmEnrollment", 'null'::jsonb), '{}'::jsonb), r.mdm_enrollment) AS me
    ) e
    WHERE (%(platform)s = 'all' OR f.platform = %(platform)s)
) slim
CROSS JOIN LATERAL (
    SELECT CASE
        WHEN slim.enrollment ~ '(intune|manage\.microsoft\.com)' THEN 'intune'
        WHEN slim.enrollment ~ 'jamf' THEN 'jamf'
        WHEN slim.enrollment ~ 'kandji' THEN 'kandji'
        WHEN slim.enrollment ~ 'mosyle' THEN 'mosyle'
        WHEN slim.enrollment ~ '(workspace ?one|airwatch|awmdm)' THEN 'workspace ?one|airwatch|intelligent ?hub'
        WHEN slim.enrollment ~ 'micromdm' THEN 'micromdm'
        WHEN slim.enrollment ~ 'nanomdm' THEN 'nanomdm'
        WHEN slim.enrollment ~ 'addigy' THEN 'addigy'
        WHEN slim.enrollment ~ 'simplemdm' THEN 'simplemdm'
        ELSE NULL
    END AS agent
) provider
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(slim.roots, '[]'::jsonb)) root
WHERE jsonb_typeof(root->'levelSummary') = 'object'
  AND COALESCE(root->>'tool', '') <> ''
  AND LOWER(root->>'tool') NOT IN ('mdm', 'enrollment')
  AND NOT COALESCE(LOWER(CONCAT_WS(' ', root->>'tool', root->>'name')) ~ provider.agent, FALSE)
