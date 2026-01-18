-- Count total events (with optional date filtering for pagination info)
-- Parameters:
--   %(start_date)s: timestamp - filter events after this date (nullable)
--   %(end_date)s: timestamp - filter events before this date (nullable)

SELECT COUNT(*) as total
FROM events e
WHERE (%(start_date)s IS NULL OR e.timestamp >= %(start_date)s)
  AND (%(end_date)s IS NULL OR e.timestamp <= %(end_date)s)
