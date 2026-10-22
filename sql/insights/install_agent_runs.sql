-- Card 5: the run timestamps each management agent recorded, per device, so
-- agent_last_run in routers/fleet.py can decide which agents have gone silent.
-- Only the four timestamp keys leave Postgres, never the module itself.
WITH fleet AS (/*FLEET*/)
SELECT
    f.serial,
    f.platform,
    f.last_seen,
    (jsonb_typeof(i.data->'cimian') = 'object' AND i.data->'cimian' <> '{}'::jsonb) AS has_cimian,
    (jsonb_typeof(i.data->'munki') = 'object' AND i.data->'munki' <> '{}'::jsonb) AS has_munki,
    (
        SELECT jsonb_agg(jsonb_build_object(
            'end_time', s->'end_time', 'endTime', s->'endTime',
            'start_time', s->'start_time', 'startTime', s->'startTime'))
        FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(i.data->'cimian'->'sessions') = 'array'
                 THEN i.data->'cimian'->'sessions' ELSE '[]'::jsonb END) s
        WHERE jsonb_typeof(s) = 'object'
    ) AS cimian_sessions,
    jsonb_build_object(
        'end_time', i.data->'cimian'->'end_time', 'endTime', i.data->'cimian'->'endTime',
        'start_time', i.data->'cimian'->'start_time', 'startTime', i.data->'cimian'->'startTime') AS cimian_run,
    (
        SELECT jsonb_agg(jsonb_build_object(
            'end_time', s->'end_time', 'endTime', s->'endTime',
            'start_time', s->'start_time', 'startTime', s->'startTime'))
        FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(i.data->'munki'->'sessions') = 'array'
                 THEN i.data->'munki'->'sessions' ELSE '[]'::jsonb END) s
        WHERE jsonb_typeof(s) = 'object'
    ) AS munki_sessions,
    jsonb_build_object(
        'end_time', i.data->'munki'->'end_time', 'endTime', i.data->'munki'->'endTime',
        'start_time', i.data->'munki'->'start_time', 'startTime', i.data->'munki'->'startTime') AS munki_run
FROM fleet f
JOIN installs i ON i.device_id = f.id
WHERE i.data IS NOT NULL
  AND (%(platform)s = 'all' OR f.platform = %(platform)s)
