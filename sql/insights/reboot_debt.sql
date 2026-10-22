-- Reboot & Update Debt: uptime buckets and pending/deferred updates.
-- Mirrors the uptime and pending-update parsing in GET /system.
--
-- A system document runs to megabytes (services, updates, extensions), and
-- every d->key access on it detoasts the whole value again. The slim CTE
-- reads each document once through jsonb_to_record, keeps only the keys
-- this card uses, and is MATERIALIZED so later steps work on the small row.
WITH fleet AS (/*FLEET*/),
slim AS MATERIALIZED (
    SELECT
        r.uptime,
        COALESCE(r."uptimeString", r.uptime_string) AS uptime_text,
        CASE
            WHEN jsonb_typeof(r."pendingAppleUpdates") = 'array'
             AND jsonb_array_length(CASE WHEN jsonb_typeof(r."pendingAppleUpdates") = 'array' THEN r."pendingAppleUpdates" ELSE '[]'::jsonb END) > 0
                THEN r."pendingAppleUpdates"
            WHEN jsonb_typeof(r.pending_apple_updates) = 'array' THEN r.pending_apple_updates
            ELSE '[]'::jsonb
        END AS apple_items,
        CASE WHEN jsonb_typeof(r."pendingWindowsUpdatesCount") = 'number'
             THEN (r."pendingWindowsUpdatesCount")::text::numeric END AS win_count,
        CASE
            WHEN jsonb_typeof(r."pendingWindowsUpdates") = 'array'
             AND jsonb_array_length(CASE WHEN jsonb_typeof(r."pendingWindowsUpdates") = 'array' THEN r."pendingWindowsUpdates" ELSE '[]'::jsonb END) > 0
                THEN jsonb_array_length(r."pendingWindowsUpdates")
            WHEN jsonb_typeof(r.pending_windows_updates) = 'array' THEN jsonb_array_length(r.pending_windows_updates)
            ELSE 0
        END AS win_list_count
    FROM fleet f
    JOIN system s ON s.device_id = f.serial
    CROSS JOIN LATERAL jsonb_to_record(
        CASE WHEN jsonb_typeof(s.data) = 'object' THEN s.data
             WHEN jsonb_typeof(s.data->0) = 'object' THEN s.data->0
             ELSE '{}'::jsonb END
    ) AS r(
        uptime jsonb, "uptimeString" text, uptime_string text,
        "pendingAppleUpdates" jsonb, pending_apple_updates jsonb,
        "pendingWindowsUpdatesCount" jsonb, "pendingWindowsUpdates" jsonb, pending_windows_updates jsonb
    )
    WHERE s.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
),
counted AS (
    SELECT
        COALESCE(
            CASE
                WHEN jsonb_typeof(uptime) = 'number' THEN (uptime)::text::numeric
                WHEN uptime #>> '{}' ~ '^\s*\d+\s*$' THEN (uptime #>> '{}')::numeric
                WHEN uptime #>> '{}' ~ '^\d+[.:]\d+:\d+:\d+' THEN (
                    SELECT p[1]::numeric * 86400 + p[2]::numeric * 3600 + p[3]::numeric * 60 + p[4]::numeric
                    FROM regexp_match(uptime #>> '{}', '^(\d+)[.:](\d+):(\d+):(\d+)') AS p
                )
            END,
            CASE
                WHEN uptime_text ~ '\d+\s*[dhms]\M' THEN
                    COALESCE((regexp_match(uptime_text, '(\d+)\s*d\M'))[1]::numeric, 0) * 86400
                  + COALESCE((regexp_match(uptime_text, '(\d+)\s*h\M'))[1]::numeric, 0) * 3600
                  + COALESCE((regexp_match(uptime_text, '(\d+)\s*m\M'))[1]::numeric, 0) * 60
                  + COALESCE((regexp_match(uptime_text, '(\d+)\s*s\M'))[1]::numeric, 0)
            END
        ) AS uptime_s,
        CASE
            WHEN jsonb_array_length(apple_items) > 0 THEN jsonb_array_length(apple_items)
            WHEN win_count > 0 THEN win_count
            ELSE win_list_count
        END AS pending,
        (
            SELECT COUNT(*)
            FROM jsonb_array_elements(apple_items) u
            WHERE jsonb_typeof(u) = 'object'
              AND (
                  (u->'deferred' IS NOT NULL
                   AND u->'deferred' NOT IN ('false'::jsonb, '0'::jsonb, '""'::jsonb, 'null'::jsonb))
                  OR COALESCE(u->>'deferredUntil', '') <> ''
              )
        ) AS deferred
    FROM slim
)
SELECT
    COUNT(*) AS devices,
    COUNT(*) FILTER (WHERE uptime_s > 0 AND uptime_s < 86400) AS up_lt1d,
    COUNT(*) FILTER (WHERE uptime_s >= 86400 AND uptime_s < 259200) AS up_1_3d,
    COUNT(*) FILTER (WHERE uptime_s >= 259200 AND uptime_s < 604800) AS up_3_7d,
    COUNT(*) FILTER (WHERE uptime_s >= 604800 AND uptime_s < 1209600) AS up_1_2w,
    COUNT(*) FILTER (WHERE uptime_s >= 1209600 AND uptime_s < 2592000) AS up_2_4w,
    COUNT(*) FILTER (WHERE uptime_s >= 2592000) AS up_30d,
    COUNT(*) FILTER (WHERE pending > 0) AS pending,
    COUNT(*) FILTER (WHERE deferred > 0) AS deferred
FROM counted
