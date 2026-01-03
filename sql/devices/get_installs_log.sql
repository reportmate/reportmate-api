-- Get installs run log for device (lazy loaded)
-- Parameters:
--   %(device_id)s: string - device serial number

SELECT data->>'runLog' as run_log
FROM installs 
WHERE device_id = %(device_id)s
