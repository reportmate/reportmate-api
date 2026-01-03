-- Get events for a specific device
-- Parameters:
--   %(device_id)s: string - device ID (serial number)
--   %(limit)s: integer - maximum events to return

SELECT id, event_type, message, details, timestamp, created_at
FROM events
WHERE device_id = %(device_id)s
ORDER BY timestamp DESC
LIMIT %(limit)s
