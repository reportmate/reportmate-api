-- Get single device by serial number or ID
-- Parameters:
--   %(serial_number)s: string - device serial number or ID

SELECT id, device_id, name, serial_number, last_seen, status, 
       model, manufacturer, os, os_name, os_version, platform, created_at,
       archived, archived_at, client_version
FROM devices 
WHERE serial_number = %(serial_number)s OR id = %(serial_number)s
