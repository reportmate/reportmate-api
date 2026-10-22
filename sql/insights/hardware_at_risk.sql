-- Card 4, Hardware at Risk: low storage (under a tenth free on internal
-- drives), 8 GB of memory or less, and Intel Macs. Rules mirror the web
-- reportRules isLowStorage / isLowMemory / archFamily over GET /hardware rows.
WITH fleet AS (/*FLEET*/),
h AS (
    SELECT f.platform,
           h.data AS d,
           COALESCE(
               CASE WHEN jsonb_typeof(s.data) = 'array' THEN s.data->0 ELSE s.data END
                   ->'operatingSystem'->>'architecture',
               ''
           ) AS os_arch
    FROM fleet f
    JOIN hardware h ON h.device_id = f.id
    LEFT JOIN system s ON s.device_id = f.id
    WHERE h.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
),
parts AS (
    SELECT platform, os_arch,
           COALESCE(NULLIF(d->'memory', 'null'::jsonb), NULLIF(d->'totalMemory', 'null'::jsonb),
                    d->'physicalMemory') AS mem,
           COALESCE(NULLIF(d->'processor', 'null'::jsonb), d->'cpu') AS cpu,
           CASE
               WHEN jsonb_array_length(CASE WHEN jsonb_typeof(d->'storage') = 'array' THEN d->'storage' ELSE '[]'::jsonb END) > 0 THEN d->'storage'
               WHEN jsonb_typeof(d->'drives') = 'array' THEN d->'drives'
               ELSE '[]'::jsonb
           END AS drives
    FROM h
),
measured AS (
    SELECT
        platform,
        CASE jsonb_typeof(mem)
            WHEN 'number' THEN (mem#>>'{}')::numeric
            WHEN 'string' THEN CASE
                WHEN mem#>>'{}' ~* '\d+(\.\d+)?\s*GB' THEN (regexp_match(mem#>>'{}', '(\d+(?:\.\d+)?)\s*GB', 'i'))[1]::numeric * 1073741824
                WHEN mem#>>'{}' ~ '^\s*\d+(\.\d+)?\s*$' THEN (mem#>>'{}')::numeric
            END
            WHEN 'object' THEN COALESCE(
                CASE WHEN mem->>'totalFormatted' ~* '\d+(\.\d+)?\s*GB'
                     THEN (regexp_match(mem->>'totalFormatted', '(\d+(?:\.\d+)?)\s*GB', 'i'))[1]::numeric * 1073741824 END,
                CASE WHEN jsonb_typeof(mem->'physical_memory') = 'number' THEN (mem->>'physical_memory')::numeric END,
                CASE WHEN jsonb_typeof(mem->'physicalMemory') = 'number' THEN (mem->>'physicalMemory')::numeric END,
                CASE WHEN jsonb_typeof(mem->'totalPhysical') = 'number' THEN (mem->>'totalPhysical')::numeric END
            )
        END AS mem_bytes,
        LOWER(CASE WHEN jsonb_typeof(cpu) = 'string' THEN cpu#>>'{}'
                   ELSE COALESCE(cpu->>'name', cpu->>'model', cpu->>'brand', '') END) AS cpu_name,
        LOWER(COALESCE(NULLIF(os_arch, ''),
                       CASE WHEN jsonb_typeof(cpu) = 'object' THEN cpu->>'architecture' END,
                       '')) AS arch,
        st.total_bytes,
        st.free_bytes
    FROM parts
    CROSS JOIN LATERAL (
        SELECT
            SUM(COALESCE(
                NULLIF(CASE WHEN jsonb_typeof(dr->'capacity') = 'number' THEN (dr->>'capacity')::numeric END, 0),
                CASE WHEN jsonb_typeof(dr->'size') = 'number' THEN (dr->>'size')::numeric END, 0)) AS total_bytes,
            SUM(COALESCE(
                NULLIF(CASE WHEN jsonb_typeof(dr->'freeSpace') = 'number' THEN (dr->>'freeSpace')::numeric END, 0),
                CASE WHEN jsonb_typeof(dr->'free_space') = 'number' THEN (dr->>'free_space')::numeric END, 0)) AS free_bytes
        FROM jsonb_array_elements(drives) dr
        WHERE jsonb_typeof(dr) = 'object'
          AND COALESCE(LOWER(dr->>'isInternal'), '') NOT IN {{FALSE}}
    ) st
)
SELECT
    COUNT(*) AS devices,
    COUNT(*) FILTER (WHERE total_bytes > 0 AND free_bytes > 0 AND free_bytes / total_bytes < 0.1) AS low_storage,
    COUNT(*) FILTER (WHERE mem_bytes > 0 AND mem_bytes <= 8589934592) AS low_memory,
    COUNT(*) FILTER (WHERE platform = 'macOS') AS macs,
    COUNT(*) FILTER (
        WHERE platform = 'macOS'
          AND (arch <> '' OR cpu_name <> '')
          AND arch !~ 'arm'
          AND cpu_name !~ 'apple'
    ) AS intel_macs
FROM measured
