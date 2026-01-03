-- Archive a device (soft delete)
-- Parameters:
--   %(serial_number)s: string - device serial number
--   %(archived_at)s: timestamp - archive timestamp
--   %(updated_at)s: timestamp - update timestamp

UPDATE devices 
SET archived = TRUE, 
    archived_at = %(archived_at)s,
    status = 'archived',
    updated_at = %(updated_at)s
WHERE serial_number = %(serial_number)s OR id = %(serial_number)s
