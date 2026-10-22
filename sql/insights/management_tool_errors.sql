-- Management Tools Logs: per tool and platform, the devices with error and
-- warning lines in the window and the line totals, from the levelSummary
-- ingest stamps on each root (log_tails.py). Hour keys are UTC YYYY-MM-DDTHH,
-- so the window is a text comparison. MDM agent roots are excluded upstream.
WITH fleet AS (/*FLEET*/),
roots AS (/*MANAGEMENT_ROOTS*/),
counted AS (
    SELECT r.serial, r.platform, r.tool, w.errors, w.warnings
    FROM roots r
    CROSS JOIN LATERAL (
        SELECT COALESCE(SUM(CASE WHEN jsonb_typeof(h.value->0) = 'number' THEN (h.value->>0)::int ELSE 0 END), 0) AS errors,
               COALESCE(SUM(CASE WHEN jsonb_typeof(h.value->1) = 'number' THEN (h.value->>1)::int ELSE 0 END), 0) AS warnings
        FROM jsonb_each(CASE WHEN jsonb_typeof(r.s->'hours') = 'object' THEN r.s->'hours' ELSE '{}'::jsonb END) h
        WHERE h.key >= %(since_hour)s
    ) w
)
SELECT tool, platform, NULL::text AS mdm_name,
       COUNT(DISTINCT serial) AS devices,
       COUNT(DISTINCT serial) FILTER (WHERE errors > 0) AS devices_with_errors,
       COUNT(DISTINCT serial) FILTER (WHERE warnings > 0) AS devices_with_warnings,
       SUM(errors) AS error_lines,
       SUM(warnings) AS warning_lines
FROM counted
GROUP BY tool, platform
