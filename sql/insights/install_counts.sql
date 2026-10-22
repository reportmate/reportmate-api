-- Card 5, Install Health: devices with install errors and warnings, from the
-- per-device counters ingest maintains (the same source as the dashboard
-- installStats). Cimian counts for Windows, Munki for macOS.
WITH fleet AS (/*FLEET*/)
SELECT
    COUNT(*) AS devices,
    COUNT(*) FILTER (WHERE (f.platform = 'Windows' AND i.cimian_errors > 0)
                        OR (f.platform = 'macOS' AND i.munki_errors > 0)) AS with_errors,
    COUNT(*) FILTER (WHERE (f.platform = 'Windows' AND i.cimian_warnings > 0)
                        OR (f.platform = 'macOS' AND i.munki_warnings > 0)) AS with_warnings
FROM fleet f
JOIN installs i ON i.device_id = f.serial
WHERE (%(platform)s = 'all' OR f.platform = %(platform)s)
