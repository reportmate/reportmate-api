-- Card: Install Health. Devices with install errors and warnings and the item
-- totals behind them, per agent, from the counters ingest keeps per device
-- (the same source as the dashboard installStats): Munki on macOS, Cimian on
-- Windows.
WITH fleet AS (/*FLEET*/)
SELECT
    COUNT(*) AS devices,
    COUNT(*) FILTER (WHERE f.platform = 'macOS') AS munki_devices,
    COUNT(*) FILTER (WHERE f.platform = 'Windows') AS cimian_devices,
    COUNT(*) FILTER (WHERE f.platform = 'macOS' AND i.munki_errors > 0) AS munki_with_errors,
    COUNT(*) FILTER (WHERE f.platform = 'macOS' AND i.munki_warnings > 0) AS munki_with_warnings,
    COUNT(*) FILTER (WHERE f.platform = 'Windows' AND i.cimian_errors > 0) AS cimian_with_errors,
    COUNT(*) FILTER (WHERE f.platform = 'Windows' AND i.cimian_warnings > 0) AS cimian_with_warnings,
    COALESCE(SUM(i.munki_errors) FILTER (WHERE f.platform = 'macOS'), 0) AS munki_error_items,
    COALESCE(SUM(i.munki_warnings) FILTER (WHERE f.platform = 'macOS'), 0) AS munki_warning_items,
    COALESCE(SUM(i.cimian_errors) FILTER (WHERE f.platform = 'Windows'), 0) AS cimian_error_items,
    COALESCE(SUM(i.cimian_warnings) FILTER (WHERE f.platform = 'Windows'), 0) AS cimian_warning_items
FROM fleet f
JOIN installs i ON i.device_id = f.serial
WHERE (%(platform)s = 'all' OR f.platform = %(platform)s)
