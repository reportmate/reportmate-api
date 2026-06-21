# API Production Readiness

Status of the FastAPI tier against production hardening, and what remains.

## Done

- **Settings store self-provisions.** The `app_settings` table is created idempotently on startup in `main.py` (`ensure_performance_indexes`) and is also listed in `schemas/run-migrations.ps1` and `schemas/011-app-settings.sql`. No manual step is required for the table to exist on a running container.
- **Disable-auth is visible.** When `DISABLE_AUTH` is set, the API logs a prominent security warning at startup (in addition to the per-request bypass). This must never be set in production.
- **Rate limiting, in-memory caching, parameterized SQL, CORS, request validation** are in place.

## Remaining — priority order

### 1. Connection pooling (highest impact)

`get_db_connection()` in `dependencies.py` opens a **new pg8000 connection per request** (TLS handshake to Azure Postgres each time). Under conference / fleet load this is the first thing that will saturate.

This is deliberately **not** changed here because a pooling rewrite must be validated against the live database before a demo — a mis-handled pool (connections not returned on exception, stale sockets) causes outages. Recommended approach when validated:

- Introduce a small bounded pool (e.g. `DB_POOL_SIZE`, default conservative) guarding pg8000 connections behind a thread-safe queue.
- Retrofit the per-request `conn.close()` call sites to return-to-pool semantics (wrap the connection, or centralize acquire/release in a context manager) — this is the part that needs care, since routers currently call `conn.close()` directly.
- Add a liveness check (`SELECT 1`) on checkout and discard dead connections.
- Load-test the bulk endpoints before/after.

### 2. Auth model is a single shared secret

There is no per-user identity or RBAC on the API. Anything holding `X-Internal-Secret` (or the client passphrase) is fully authorized, including writing org settings via `PUT /api/v1/settings`. Settings write-gating is enforced **upstream** in the Next.js proxy (admin role check) — document this and treat it as a known v1 constraint. If stronger control is needed later, forward the session principal in a header and enforce server-side.

### 3. WebPubSub

Confirm `EVENTS_CONNECTION` / WebPubSub is configured in the deployed environment so real-time event updates work, rather than the mock fallback in `routers/health.py`. Otherwise the dashboard falls back to polling.

### 4. Migration runner is stale

`schemas/run-migrations.ps1` lists only a subset of migrations (001–004 + 011). The authoritative provisioning path is the idempotent startup-ensure in `main.py`. Before relying on the runner for a fresh database, reconcile its list with the actual `NNN-*.sql` files (note: some older migrations use non-idempotent `ALTER TABLE`, so a naive glob-all is unsafe).
