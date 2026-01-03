-- Get table sizes and row counts for diagnostics
SELECT 
    relname,
    n_live_tup,
    n_dead_tup,
    pg_size_pretty(pg_total_relation_size(relid)) as total_size
FROM pg_stat_user_tables 
WHERE relname IN ('devices', 'events', 'inventory', 'system', 'hardware', 
                 'applications', 'profiles', 'network', 'security')
ORDER BY pg_total_relation_size(relid) DESC
