-- Dashboard events query
-- Fetches recent events with device names for dashboard widget
-- Parameters:
--   %(limit)s: integer - maximum events to return

SELECT 
    e.id,
    e.device_id,
    i.data->>'deviceName' as device_name,
    e.event_type,
    e.message,
    e.timestamp
FROM events e
LEFT JOIN inventory i ON e.device_id = i.device_id
ORDER BY e.timestamp DESC 
LIMIT %(limit)s
