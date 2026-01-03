-- Check device archive status
-- Parameters:
--   %(serial_number)s: string - device serial number

SELECT id, archived 
FROM devices 
WHERE serial_number = %(serial_number)s OR id = %(serial_number)s
