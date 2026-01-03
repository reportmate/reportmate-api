-- Get events statistics for diagnostics
SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM events
