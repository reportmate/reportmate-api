-- Get policies from catalog by hash
-- Parameters:
--   %(policy_hashes)s: array of strings - policy hash values

SELECT policy_data 
FROM policy_catalog 
WHERE policy_hash = ANY(%(policy_hashes)s)
ORDER BY policy_name
