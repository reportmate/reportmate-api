-- Get device profiles with policy references
-- Returns normalized policy hashes for deduplication
-- Parameters:
--   %(device_id)s: string - device serial number

SELECT intune_policy_hashes, security_policy_hashes, mdm_policy_hashes, metadata
FROM profiles
WHERE device_id = %(device_id)s
