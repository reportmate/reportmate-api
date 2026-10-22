-- Card: Management Tools Errors. Per management tool log root, the devices
-- with error and warning lines in the window, and the error and warning line
-- totals, from the levelSummary ingest stamps on each root (log_tails.py).
-- Hour keys are UTC, YYYY-MM-DDTHH, so the window is a text comparison.
WITH fleet AS (/*FLEET*/),
roots AS (
    SELECT f.serial, f.platform,
           LOWER(COALESCE(root->>'tool', '')) AS tool,
           CASE WHEN LOWER(COALESCE(root->>'tool', '')) = 'mdm' THEN COALESCE(NULLIF(TRIM(root->>'name'), ''), 'MDM') END AS mdm_name,
           root->'levelSummary' AS s
    FROM fleet f
    JOIN management m ON m.device_id = f.id
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(m.data->'logs'->'roots') = 'array' THEN m.data->'logs'->'roots' ELSE '[]'::jsonb END) root
    WHERE m.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
      AND jsonb_typeof(root) = 'object'
      AND jsonb_typeof(root->'levelSummary') = 'object'
      AND COALESCE(root->>'tool', '') <> ''
),
counted AS (
    SELECT r.serial, r.platform, r.tool, r.mdm_name, w.errors, w.warnings
    FROM roots r
    CROSS JOIN LATERAL (
        SELECT COALESCE(SUM(CASE WHEN jsonb_typeof(h.value->0) = 'number' THEN (h.value->>0)::int ELSE 0 END), 0) AS errors,
               COALESCE(SUM(CASE WHEN jsonb_typeof(h.value->1) = 'number' THEN (h.value->>1)::int ELSE 0 END), 0) AS warnings
        FROM jsonb_each(CASE WHEN jsonb_typeof(r.s->'hours') = 'object' THEN r.s->'hours' ELSE '{}'::jsonb END) h
        WHERE h.key >= %(since_hour)s
    ) w
)
SELECT tool, platform, mdm_name,
       COUNT(DISTINCT serial) AS devices,
       COUNT(DISTINCT serial) FILTER (WHERE errors > 0) AS devices_with_errors,
       COUNT(DISTINCT serial) FILTER (WHERE warnings > 0) AS devices_with_warnings,
       SUM(errors) AS error_lines,
       SUM(warnings) AS warning_lines
FROM counted
GROUP BY tool, platform, mdm_name
