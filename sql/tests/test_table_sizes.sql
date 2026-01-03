-- pgAdmin Test Wrapper: admin/table_sizes.sql
-- Copy this to pgAdmin to test diagnostics

-- Get table sizes and row counts for all ReportMate tables
SELECT 
    relname as table_name,
    n_live_tup as live_rows,
    n_dead_tup as dead_rows,
    pg_size_pretty(pg_total_relation_size(relid)) as total_size
FROM pg_stat_user_tables 
WHERE relname IN ('devices', 'events', 'inventory', 'system', 'hardware', 
                 'applications', 'profiles', 'network', 'security',
                 'management', 'installs', 'printers', 'displays')
ORDER BY pg_total_relation_size(relid) DESC;
