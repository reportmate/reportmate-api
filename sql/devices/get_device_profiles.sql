-- Get device profiles data
-- Returns profiles JSON data for a device
-- Parameters:
--   %(device_id)s: string - device serial number

SELECT data, collected_at, updated_at
FROM profiles
WHERE device_id = %(device_id)s
