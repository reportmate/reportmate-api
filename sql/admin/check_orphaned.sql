-- Check for orphaned module records
-- NOTE: Table name substituted in Python (validated against whitelist)

SELECT COUNT(*) 
FROM {table_name} m
LEFT JOIN devices d ON m.device_id = d.serial_number
WHERE d.serial_number IS NULL
