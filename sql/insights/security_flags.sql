-- Cards 2 (Protection Gaps) and 8 (Software Risk, CVE half): one row per
-- platform with the count of devices missing each protection. The flag
-- expressions are the ones GET /security derives per device; text is matched
-- instead of cast to boolean so one malformed value cannot fail the card.
WITH fleet AS (/*FLEET*/),
s AS (
    SELECT f.platform, sec.data AS d
    FROM fleet f
    JOIN security sec ON sec.device_id = f.serial
    WHERE sec.data IS NOT NULL
      AND (%(platform)s = 'all' OR f.platform = %(platform)s)
),
flags AS (
    SELECT
        platform,
        COALESCE(
            CASE WHEN LOWER(d->'firewall'->>'isEnabled') IN {{TRUE}} THEN TRUE
                 WHEN LOWER(d->'firewall'->>'isEnabled') IN {{FALSE}} THEN FALSE END,
            CASE WHEN LOWER(d->'firewall'->>'enabled') IN {{TRUE}} THEN TRUE
                 WHEN LOWER(d->'firewall'->>'enabled') IN {{FALSE}} THEN FALSE END,
            COALESCE(d->'firewall'->>'globalState', '') IN ('on', '1')
        ) AS firewall_on,
        -- BitLocker counts only with a real encryption method on a volume
        -- (osquery reports protection on unencrypted Win11 26100 drives).
        COALESCE(
            CASE
                WHEN LOWER(d->'encryption'->'bitLocker'->>'isEnabled') IN {{TRUE}}
                 AND jsonb_typeof(d->'encryption'->'encryptedVolumes') = 'array'
                 AND EXISTS (
                     SELECT 1 FROM jsonb_array_elements(d->'encryption'->'encryptedVolumes') vol
                     WHERE COALESCE(vol->>'encryptionMethod', 'None') NOT IN ('None', '')
                 ) THEN TRUE
                WHEN LOWER(d->'encryption'->'bitLocker'->>'isEnabled') IN {{TRUE}} THEN FALSE
            END,
            CASE WHEN LOWER(d->'fileVault'->>'enabled') IN {{TRUE}} THEN TRUE
                 WHEN LOWER(d->'fileVault'->>'enabled') IN {{FALSE}} THEN FALSE END,
            FALSE
        ) AS encryption_on,
        COALESCE(d->'antivirus'->>'name', '') <> '' AS has_av_name,
        COALESCE(LOWER(d->'antivirus'->>'isEnabled') IN {{TRUE}}, FALSE) AS av_on,
        COALESCE(LOWER(d->'secureBoot'->>'isEnabled') IN {{TRUE}}, FALSE) AS secure_boot_on,
        COALESCE(
            CASE WHEN LOWER(d->'systemIntegrityProtection'->>'enabled') IN {{TRUE}} THEN TRUE
                 WHEN LOWER(d->'systemIntegrityProtection'->>'enabled') IN {{FALSE}} THEN FALSE END,
            CASE WHEN LOWER(d->>'sipEnabled') IN {{TRUE}} THEN TRUE
                 WHEN LOWER(d->>'sipEnabled') IN {{FALSE}} THEN FALSE END
        ) AS sip_on,
        -- Active threats only: ASR rule blocks are protection working.
        CASE WHEN jsonb_typeof(d->'detections') = 'array' THEN (
            SELECT COUNT(*) FROM jsonb_array_elements(d->'detections') det
            WHERE COALESCE(det->>'category', '') <> 'ASR Rule'
              AND COALESCE(det->>'eventId', '') <> '1121'
        ) ELSE 0 END AS threats,
        CASE WHEN jsonb_typeof(d->'securityCves') = 'array' THEN (
            SELECT COUNT(*) FROM jsonb_array_elements(d->'securityCves') c
            WHERE c->>'status' = 'Unpatched' AND c->>'severity' = 'Critical'
        ) ELSE 0 END AS critical_cves,
        CASE WHEN jsonb_typeof(d->'securityCves') = 'array' THEN (
            SELECT COUNT(*) FROM jsonb_array_elements(d->'securityCves') c
            WHERE c->>'status' = 'Unpatched'
              AND COALESCE(LOWER(c->>'activelyExploited') IN {{TRUE}}, FALSE)
        ) ELSE 0 END AS exploited_cves
    FROM s
)
SELECT
    COUNT(*) AS devices,
    COUNT(*) FILTER (WHERE NOT encryption_on) AS encryption_off,
    COUNT(*) FILTER (WHERE NOT firewall_on) AS firewall_off,
    COUNT(*) FILTER (WHERE platform = 'Windows' OR av_on OR has_av_name) AS antivirus_total,
    COUNT(*) FILTER (WHERE (platform = 'Windows' OR av_on OR has_av_name) AND NOT av_on) AS antivirus_off,
    COUNT(*) FILTER (WHERE platform <> 'Windows' AND sip_on IS NOT NULL) AS sip_total,
    COUNT(*) FILTER (WHERE platform <> 'Windows' AND sip_on = FALSE) AS sip_off,
    COUNT(*) FILTER (WHERE platform = 'Windows') AS secure_boot_total,
    COUNT(*) FILTER (WHERE platform = 'Windows' AND NOT secure_boot_on) AS secure_boot_off,
    COUNT(*) FILTER (WHERE threats > 0) AS with_threats,
    COUNT(*) FILTER (WHERE critical_cves > 0) AS critical_cves,
    COUNT(*) FILTER (WHERE exploited_cves > 0) AS exploited_cves
FROM flags
