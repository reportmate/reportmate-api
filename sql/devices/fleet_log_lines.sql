-- Fleet log lines: /api/v1/logs/{tool}
-- One row per (device, tail file) for the requested log root, with the tail's
-- lines already narrowed in Postgres when a level pattern is given so a fleet
-- sweep for errors does not ship every INFO line to Python.
-- Parameters: tool (text), pattern (text or NULL), include_archived (boolean)

SELECT
    d.serial_number,
    d.last_seen,
    COALESCE(inv.data->>'device_name', inv.data->>'deviceName') AS device_name,
    inv.data->>'platform' AS platform,
    root - 'tails' AS root_meta,
    t->>'file' AS file,
    CASE
        WHEN %(pattern)s::text IS NULL THEN t->'lines'
        ELSE COALESCE(
            (SELECT jsonb_agg(l.value ORDER BY l.ordinality)
             FROM jsonb_array_elements_text(t->'lines') WITH ORDINALITY AS l
             WHERE l.value ~* %(pattern)s::text),
            '[]'::jsonb)
    END AS lines
FROM devices d
JOIN management m ON m.device_id = d.id
LEFT JOIN inventory inv ON inv.device_id = d.id
CROSS JOIN LATERAL jsonb_array_elements(m.data->'logs'->'roots') AS root
CROSS JOIN LATERAL jsonb_array_elements(root->'tails') AS t
WHERE d.serial_number IS NOT NULL
  AND d.serial_number NOT LIKE 'TEST-%%'
  AND (%(include_archived)s = TRUE OR d.archived = FALSE)
  AND jsonb_typeof(m.data->'logs'->'roots') = 'array'
  AND jsonb_typeof(root->'tails') = 'array'
  AND jsonb_typeof(t->'lines') = 'array'
  AND lower(root->>'tool') = lower(%(tool)s)
ORDER BY d.serial_number, t->>'file';
