# API Production Readiness

Status of the FastAPI tier against production hardening, and what remains.

## Done

- **Schema migrations are versioned.** Alembic owns the schema: migrations live in `alembic/versions` (`0001_baseline.py` onward) and are recorded in the `alembic_version` table. `run_migrations()` in `migrations.py` upgrades to head from the application lifespan in `main.py` before the app serves traffic, replacing the old ad-hoc startup DDL and the hand-maintained migration runner. The `app_settings` table is created idempotently by `0001_baseline.py`, so no manual step is required for it to exist on a running container.
- **Connection pooling.** `dependencies.py` builds a bounded DBUtils `PooledDB` over pg8000 (`DB_POOL_MIN`, default 2; `DB_POOL_MAX`, default 40, sized to the request threadpool). Connections are returned with a rollback (`reset=True`), and dropped sockets, including a bare `OSError` from a NAT idle drop, are reconnected on borrow through the `failures` list rather than a `SELECT 1` ping, which pg8000 does not support. TCP keepalive holds idle sockets open. `tests/test_db_pool.py` covers it.
- **Disable-auth is guarded.** When `DISABLE_AUTH` is set, the API logs a prominent security warning at startup, and `assert_auth_enabled_for_prod` refuses to start when `APP_ENV` names a production or staging environment or real auth secrets are configured. It must never be set in production.
- **Rate limiting, in-memory caching, parameterized SQL, CORS, request validation** are in place. Queries live as `.sql` files under `sql/`.

## Remaining — priority order

### 1. Auth model still grants full access to legacy credentials

`verify_authentication` in `dependencies.py` resolves every request to a principal with a list of scopes. Per-client API keys (`X-API-Key`, managed under `/admin` in `routers/api_keys.py`) and OIDC bearer tokens (`oidc_auth.py`, inert until `ENABLE_OIDC_AUTH` and its issuers and audience are configured) are scope-limited. The legacy credentials, `X-Internal-Secret` and the client passphrase, still receive every scope for backward compatibility, so anything holding them is fully authorized.

Writing org settings with `PUT /api/v1/settings` accepts only the internal secret (`require_internal_secret` in `routers/settings.py`); the admin-role check itself is enforced **upstream** in the Next.js proxy. Treat this as a known v1 constraint. Moving callers onto scoped API keys or OIDC, then narrowing the legacy credentials, closes it.

### 2. WebPubSub

Confirm `EVENTS_CONNECTION` is configured in the deployed environment so real-time event updates work. Without it, the negotiate endpoint in `routers/health.py` returns an error instead of a token (or a placeholder URL when the Web PubSub SDK is missing), and the dashboard falls back to polling.
