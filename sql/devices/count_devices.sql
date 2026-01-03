-- Count total devices
-- Parameters:
--   %(include_archived)s: boolean - whether to include archived devices

SELECT COUNT(*) 
FROM devices 
WHERE (%(include_archived)s = TRUE OR archived = FALSE)
