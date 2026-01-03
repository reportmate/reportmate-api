-- Get module data for a device
-- NOTE: Table name is substituted in Python code (validated against whitelist)
-- Parameters:
--   %(device_id)s: string - device serial number

SELECT data FROM {table_name} WHERE device_id = %(device_id)s
