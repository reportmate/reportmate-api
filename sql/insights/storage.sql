-- Card: Storage, fleet buckets. Appended to storage_devices.sql.
SELECT
    platform,
    COUNT(*) AS devices,
    COUNT(*) FILTER (WHERE free_ratio < 0.05) AS free_lt5,
    COUNT(*) FILTER (WHERE free_ratio >= 0.05 AND free_ratio < 0.10) AS free_5_10,
    COUNT(*) FILTER (WHERE free_ratio >= 0.10 AND free_ratio < 0.20) AS free_10_20,
    COUNT(*) FILTER (WHERE free_ratio >= 0.20) AS free_20_plus,
    COUNT(*) FILTER (WHERE total_bytes < 384000000000) AS cap_le256,
    COUNT(*) FILTER (WHERE total_bytes >= 384000000000 AND total_bytes < 768000000000) AS cap_512,
    COUNT(*) FILTER (WHERE total_bytes >= 768000000000 AND total_bytes < 1536000000000) AS cap_1t,
    COUNT(*) FILTER (WHERE total_bytes >= 1536000000000) AS cap_2t_plus
FROM measured
GROUP BY platform
ORDER BY platform
