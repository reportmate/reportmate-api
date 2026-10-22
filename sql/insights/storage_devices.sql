-- Card: Storage. Internal capacity and free space per device, as the web
-- reportRules storageBytes reads GET /hardware drives (capacity or size,
-- freeSpace or free_space, isInternal not false). The two storage queries
-- share this per-device reduction and differ only in the final select.
WITH fleet AS (/*FLEET*/),
drives AS (
    SELECT f.serial, f.id, f.platform, f.device_name,
           CASE
               WHEN jsonb_array_length(CASE WHEN jsonb_typeof(h.data->'storage') = 'array' THEN h.data->'storage' ELSE '[]'::jsonb END) > 0 THEN h.data->'storage'
               WHEN jsonb_typeof(h.data->'drives') = 'array' THEN h.data->'drives'
               ELSE '[]'::jsonb
           END AS list
    FROM fleet f
    JOIN hardware h ON h.device_id = f.id
    WHERE h.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
),
per_device AS (
    SELECT d.serial, d.id, d.platform, d.device_name, st.total_bytes, st.free_bytes,
           st.free_bytes / NULLIF(st.total_bytes, 0) AS free_ratio
    FROM drives d
    CROSS JOIN LATERAL (
        SELECT
            SUM(COALESCE(
                NULLIF(CASE WHEN jsonb_typeof(dr->'capacity') = 'number' THEN (dr->>'capacity')::numeric END, 0),
                CASE WHEN jsonb_typeof(dr->'size') = 'number' THEN (dr->>'size')::numeric END, 0)) AS total_bytes,
            SUM(COALESCE(
                NULLIF(CASE WHEN jsonb_typeof(dr->'freeSpace') = 'number' THEN (dr->>'freeSpace')::numeric END, 0),
                CASE WHEN jsonb_typeof(dr->'free_space') = 'number' THEN (dr->>'free_space')::numeric END, 0)) AS free_bytes
        FROM jsonb_array_elements(d.list) dr
        WHERE jsonb_typeof(dr) = 'object'
          AND COALESCE(LOWER(dr->>'isInternal'), '') NOT IN {{FALSE}}
    ) st
),
measured AS (
    SELECT * FROM per_device WHERE total_bytes > 0 AND free_bytes > 0
)
/*STORAGE_SELECT*/
