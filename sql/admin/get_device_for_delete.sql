-- Get device details before deletion
-- Parameters:
--   %(serial_number)s: string - device serial number

SELECT id, device_id, name, archived 
FROM devices 
WHERE serial_number = %(serial_number)s OR id = %(serial_number)s
