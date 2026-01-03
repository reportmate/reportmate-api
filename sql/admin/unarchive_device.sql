-- Unarchive a device (restore from soft delete)
-- Parameters:
--   %(serial_number)s: string - device serial number
--   %(updated_at)s: timestamp - update timestamp

UPDATE devices 
SET archived = FALSE, 
    archived_at = NULL,
    status = 'active',
    updated_at = %(updated_at)s
WHERE serial_number = %(serial_number)s OR id = %(serial_number)s
