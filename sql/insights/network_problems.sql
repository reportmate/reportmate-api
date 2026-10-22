-- Card 12, Connectivity Problems: weak Wi-Fi (signal above 0 and under 25,
-- the network report Poor bucket), a Low network-quality rating, and devices
-- on VPN, read the way the web extractNetwork reads GET /network raw data.
WITH fleet AS (/*FLEET*/),
n AS (
    SELECT f.platform, nw.data AS d
    FROM fleet f
    JOIN network nw ON nw.device_id = f.id
    WHERE nw.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
),
parts AS (
    SELECT platform,
           COALESCE(NULLIF(d->'active_connection', 'null'::jsonb), d->'activeConnection', '{}'::jsonb) AS ac,
           COALESCE(d->'networkQuality', '{}'::jsonb) AS nq,
           COALESCE(NULLIF(d->'vpn_connections', 'null'::jsonb), d->'vpnConnections', '[]'::jsonb) AS vpns
    FROM n
),
x AS (
    SELECT platform,
           CASE
               WHEN jsonb_typeof(COALESCE(NULLIF(ac->'wifi_signal_strength', 'null'::jsonb), ac->'wifiSignalStrength')) = 'number'
               THEN COALESCE(NULLIF(ac->'wifi_signal_strength', 'null'::jsonb), ac->'wifiSignalStrength')::text::numeric
               WHEN COALESCE(ac->>'wifi_signal_strength', ac->>'wifiSignalStrength') ~ '^\s*-?\d+(\.\d+)?\s*$'
               THEN COALESCE(ac->>'wifi_signal_strength', ac->>'wifiSignalStrength')::numeric
           END AS signal,
           CASE WHEN jsonb_typeof(nq) = 'object' THEN LOWER(COALESCE(nq->>'rating', '')) ELSE '' END AS rating,
           CASE WHEN jsonb_typeof(nq) = 'object' THEN LOWER(COALESCE(nq->>'dlRating', nq->>'dl_rating', '')) ELSE '' END AS dl_rating,
           CASE WHEN jsonb_typeof(nq) = 'object' THEN LOWER(COALESCE(nq->>'ulRating', nq->>'ul_rating', '')) ELSE '' END AS ul_rating,
           (
               COALESCE(LOWER(COALESCE(ac->>'is_vpn_active', ac->>'isVpnActive')) IN {{TRUE}}, FALSE)
               OR COALESCE(ac->>'interface_name', ac->>'interfaceName', ac->>'interface',
                           ac->>'friendly_name', ac->>'friendlyName', '') ~ '^(utun|ppp)'
               OR EXISTS (
                   SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(vpns) = 'array' THEN vpns ELSE '[]'::jsonb END) v
                   WHERE LOWER(COALESCE(v->>'status', '')) = 'connected'
                     AND TRIM(COALESCE(v->>'name', '')) NOT IN ('', 'Unknown VPN')
               )
           ) AS on_vpn
    FROM parts
)
SELECT
    COUNT(*) AS devices,
    COUNT(*) FILTER (WHERE signal > 0 AND signal < 25) AS weak_signal,
    COUNT(*) FILTER (WHERE rating <> '' OR dl_rating <> '' OR ul_rating <> '') AS quality_measured,
    COUNT(*) FILTER (WHERE rating = 'low' OR (rating = '' AND (dl_rating = 'low' OR ul_rating = 'low'))) AS poor_quality,
    COUNT(*) FILTER (WHERE on_vpn) AS on_vpn
FROM x
