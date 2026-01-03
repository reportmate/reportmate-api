-- pgAdmin Test Wrapper: admin/archive_device.sql
-- Copy this to pgAdmin to test with sample values

-- Set test parameter values
DO $$
DECLARE
    -- Test parameters
    p_serial_number TEXT := 'TEST-SERIAL-001';  -- Replace with actual serial
    p_timestamp TIMESTAMP := NOW();
BEGIN
    RAISE NOTICE 'Testing admin/archive_device.sql with serial=%', p_serial_number;
END $$;

-- DRY RUN: Show what would be updated (remove RETURNING for actual update)
SELECT id, serial_number, archived, status
FROM devices 
WHERE serial_number = 'TEST-SERIAL-001' OR id = 'TEST-SERIAL-001';

-- ACTUAL UPDATE (uncomment to execute):
-- UPDATE devices 
-- SET archived = TRUE, 
--     archived_at = NOW(),
--     status = 'archived',
--     updated_at = NOW()
-- WHERE serial_number = 'TEST-SERIAL-001' OR id = 'TEST-SERIAL-001'
-- RETURNING id, serial_number, archived, archived_at;
