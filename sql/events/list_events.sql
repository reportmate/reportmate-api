-- Get recent events with device names
-- Parameters:
--   %(limit)s: integer - maximum events to return

SELECT 
    e.id,
    e.device_id,
    i.data->>'deviceName' as device_name,
    i.data->>'assetTag' as asset_tag,
    e.event_type,
    e.message,
    e.timestamp
FROM events e
LEFT JOIN inventory i ON e.device_id = i.device_id
ORDER BY e.timestamp DESC 
LIMIT %(limit)s
