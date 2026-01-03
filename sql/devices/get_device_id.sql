-- Get device ID from serial number or ID
-- Parameters:
--   %(serial_number)s: string - device serial number or ID

SELECT id FROM devices 
WHERE serial_number = %(serial_number)s OR id = %(serial_number)s
