-- Get recent events with device names and platform (with pagination and date filtering)
-- Parameters:
--   %(limit)s: integer - maximum events to return
--   %(offset)s: integer - number of events to skip (for pagination)
--   %(start_date)s: timestamp - filter events after this date (nullable)
--   %(end_date)s: timestamp - filter events before this date (nullable)

SELECT 
    e.id,
    e.device_id,
    COALESCE(i.data->>'device_name', i.data->>'deviceName') as device_name,
    COALESCE(i.data->>'asset_tag', i.data->>'assetTag') as asset_tag,
    e.event_type,
    e.message,
    e.timestamp,
    COALESCE(
        s.data->'operating_system'->>'name',
        s.data->'operatingSystem'->>'name',
        i.data->>'platform'
    ) as platform
FROM events e
LEFT JOIN inventory i ON e.device_id = i.device_id
LEFT JOIN system s ON e.device_id = s.device_id
WHERE (%(start_date)s::timestamptz IS NULL OR e.timestamp >= %(start_date)s::timestamptz)
  AND (%(end_date)s::timestamptz IS NULL OR e.timestamp <= %(end_date)s::timestamptz)
ORDER BY e.timestamp DESC 
LIMIT %(limit)s
OFFSET %(offset)s
