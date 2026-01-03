-- Get device serial number from any identifier
-- Parameters:
--   %(device_id)s: string - device serial number or ID

SELECT serial_number FROM devices 
WHERE serial_number = %(device_id)s OR id = %(device_id)s
