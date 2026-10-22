-- Fleet Management Tools Logs report, per tool and platform: devices with the
-- tool, devices with error and warning lines in the window, line totals and
-- the latest hour with one. From the levelSummary ingest stamps on each log
-- root, MDM agent excluded (management_roots.sql).
WITH fleet AS (/*FLEET*/),
roots AS (/*MANAGEMENT_ROOTS*/),
counted AS (
    SELECT r.serial, r.platform, r.tool, w.errors, w.warnings, w.last_hour
    FROM roots r
    CROSS JOIN LATERAL (
        SELECT COALESCE(SUM(c.e), 0) AS errors, COALESCE(SUM(c.w), 0) AS warnings,
               MAX(h.key) FILTER (WHERE c.e + c.w > 0) AS last_hour
        FROM jsonb_each(CASE WHEN jsonb_typeof(r.s->'hours') = 'object' THEN r.s->'hours' ELSE '{}'::jsonb END) h
        CROSS JOIN LATERAL (
            SELECT CASE WHEN jsonb_typeof(h.value->0) = 'number' THEN (h.value->>0)::int ELSE 0 END AS e,
                   CASE WHEN jsonb_typeof(h.value->1) = 'number' THEN (h.value->>1)::int ELSE 0 END AS w
        ) c
        WHERE h.key >= %(since_hour)s
    ) w
)
SELECT tool, platform,
       COUNT(DISTINCT serial) AS devices,
       COUNT(DISTINCT serial) FILTER (WHERE errors > 0) AS devices_with_errors,
       COUNT(DISTINCT serial) FILTER (WHERE warnings > 0) AS devices_with_warnings,
       SUM(errors) AS error_lines,
       SUM(warnings) AS warning_lines,
       MAX(last_hour) AS last_hour
FROM counted
GROUP BY tool, platform
