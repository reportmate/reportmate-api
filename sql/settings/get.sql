-- Fetch a settings document for a given scope/principal.
-- Parameters: scope (text), principal (text)
SELECT value, schema_version, updated_at, updated_by
FROM app_settings
WHERE scope = %(scope)s AND principal = %(principal)s;
