-- Auto-discover inventory keys and sample values across the fleet.
-- Used by /api/v1/settings/inventory/discover to drive the onboarding wizard's
-- field-mapping step (so admins map whatever keys their Inventory.yaml emits).
-- Parameters: include_archived (boolean)
--
-- Dedupes to one (latest) inventory row per device, then enumerates every
-- top-level key with its value cardinality and a capped set of sample values.

WITH latest_inventory AS (
    SELECT DISTINCT ON (inv.device_id)
        inv.device_id,
        inv.data
    FROM inventory inv
    JOIN devices d ON d.serial_number = inv.device_id
    WHERE inv.data IS NOT NULL
        AND jsonb_typeof(inv.data) = 'object'
        AND d.serial_number IS NOT NULL
        AND d.serial_number NOT LIKE 'TEST-%%'
        AND d.serial_number != 'localhost'
        AND (%(include_archived)s = TRUE OR d.archived = FALSE)
    ORDER BY inv.device_id, inv.updated_at DESC
),
kv AS (
    SELECT kv.key AS k, kv.value AS v
    FROM latest_inventory li
    CROSS JOIN LATERAL jsonb_each_text(li.data) AS kv(key, value)
    WHERE kv.value IS NOT NULL AND kv.value <> ''
)
SELECT
    k AS key,
    COUNT(*) AS device_count,
    COUNT(DISTINCT v) AS distinct_count,
    (array_agg(DISTINCT v ORDER BY v))[1:25] AS sample_values
FROM kv
GROUP BY k
ORDER BY device_count DESC, k;
