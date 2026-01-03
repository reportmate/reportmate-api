-- pgAdmin Test Wrapper: events/list_events.sql
-- Copy this to pgAdmin to test with sample values

-- Set test parameter values
DO $$
DECLARE
    -- Test parameters
    p_limit INTEGER := 100;
BEGIN
    RAISE NOTICE 'Testing events/list_events.sql with limit=%', p_limit;
END $$;

-- Execute the actual query (replace parameters manually for pgAdmin)
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
LIMIT 100;  -- Replace with desired limit
