-- Insert or replace a settings document for a scope/principal.
-- Parameters: scope (text), principal (text), value (jsonb text), schema_version (int), updated_by (text)
INSERT INTO app_settings (scope, principal, value, schema_version, updated_at, updated_by)
VALUES (%(scope)s, %(principal)s, %(value)s::jsonb, %(schema_version)s, NOW(), %(updated_by)s)
ON CONFLICT (scope, principal) DO UPDATE
SET value = EXCLUDED.value,
    schema_version = EXCLUDED.schema_version,
    updated_at = NOW(),
    updated_by = EXCLUDED.updated_by
RETURNING value, schema_version, updated_at, updated_by;
