-- Check for duplicate records in module tables
-- NOTE: Table name substituted in Python (validated against whitelist)

SELECT device_id, COUNT(*) as cnt 
FROM {table_name} 
GROUP BY device_id 
HAVING COUNT(*) > 1
