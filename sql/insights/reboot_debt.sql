-- Card 1, Reboot & Update Debt: uptime buckets and pending/deferred updates.
-- Mirrors the uptime and pending-update parsing in GET /system.
WITH fleet AS (/*FLEET*/),
sd AS (
    SELECT CASE WHEN jsonb_typeof(s.data) = 'array' THEN s.data->0 ELSE s.data END AS d
    FROM fleet f
    JOIN system s ON s.device_id = f.serial
    WHERE s.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
),
parsed AS (
    SELECT
        COALESCE(
            CASE
                WHEN jsonb_typeof(d->'uptime') = 'number' THEN (d->>'uptime')::numeric
                WHEN d->>'uptime' ~ '^\s*\d+\s*$' THEN (d->>'uptime')::numeric
                WHEN d->>'uptime' ~ '^\d+[.:]\d+:\d+:\d+' THEN (
                    SELECT p[1]::numeric * 86400 + p[2]::numeric * 3600 + p[3]::numeric * 60 + p[4]::numeric
                    FROM regexp_match(d->>'uptime', '^(\d+)[.:](\d+):(\d+):(\d+)') AS p
                )
            END,
            CASE
                WHEN COALESCE(d->>'uptimeString', d->>'uptime_string') ~ '\d+\s*[dhms]\M' THEN (
                    SELECT COALESCE((regexp_match(t, '(\d+)\s*d\M'))[1]::numeric, 0) * 86400
                         + COALESCE((regexp_match(t, '(\d+)\s*h\M'))[1]::numeric, 0) * 3600
                         + COALESCE((regexp_match(t, '(\d+)\s*m\M'))[1]::numeric, 0) * 60
                         + COALESCE((regexp_match(t, '(\d+)\s*s\M'))[1]::numeric, 0)
                    FROM (SELECT COALESCE(d->>'uptimeString', d->>'uptime_string') AS t) u
                )
            END
        ) AS uptime_s,
        apple.items AS apple_items,
        d AS d
    FROM sd
    CROSS JOIN LATERAL (
        SELECT CASE
            WHEN jsonb_array_length(CASE WHEN jsonb_typeof(d->'pendingAppleUpdates') = 'array' THEN d->'pendingAppleUpdates' ELSE '[]'::jsonb END) > 0 THEN d->'pendingAppleUpdates'
            WHEN jsonb_typeof(d->'pending_apple_updates') = 'array' THEN d->'pending_apple_updates'
            ELSE '[]'::jsonb
        END AS items
    ) apple
),
counted AS (
    SELECT
        uptime_s,
        CASE
            WHEN jsonb_array_length(apple_items) > 0 THEN jsonb_array_length(apple_items)
            WHEN jsonb_typeof(d->'pendingWindowsUpdatesCount') = 'number'
             AND (d->>'pendingWindowsUpdatesCount')::numeric > 0 THEN (d->>'pendingWindowsUpdatesCount')::numeric
            WHEN jsonb_array_length(CASE WHEN jsonb_typeof(d->'pendingWindowsUpdates') = 'array' THEN d->'pendingWindowsUpdates' ELSE '[]'::jsonb END) > 0 THEN jsonb_array_length(d->'pendingWindowsUpdates')
            WHEN jsonb_typeof(d->'pending_windows_updates') = 'array' THEN jsonb_array_length(d->'pending_windows_updates')
            ELSE 0
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
    FROM parsed
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
