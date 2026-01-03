-- Get event payload details
-- Parameters:
--   %(event_id)s: integer - event ID

SELECT details, device_id, timestamp
FROM events 
WHERE id = %(event_id)s
