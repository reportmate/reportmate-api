-- Get events for a specific device
-- Parameters:
--   %(device_id)s: string - device ID (serial number)
--   %(limit)s: integer - maximum events to return
--   %(event_type)s: text - filter by event type (nullable)

SELECT id, event_type, message, details, timestamp, created_at
FROM events
WHERE device_id = %(device_id)s
  AND (%(event_type)s::text IS NULL OR event_type = %(event_type)s::text)
ORDER BY timestamp DESC
LIMIT %(limit)s
