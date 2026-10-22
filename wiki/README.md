# ReportMate API wiki

The API owns ReportMate's stored device telemetry, events, settings and access control. The macOS and Windows agents post module payloads to it, and the web dashboard, native apps, the `reportmateutil` CLI and the MCP server read the fleet back through its versioned HTTP contract under `/api/v1`.

## Read first

- [Project overview, authentication and license](../README.md)
- [Production readiness notes](../PRODUCTION-READINESS.md)
- [Application entry point](../main.py)
- [OpenAPI export script](../scripts/export_openapi.py)

## Architecture

The service is a FastAPI application backed by PostgreSQL through pg8000 and a bounded connection pool. [main.py](../main.py) builds the app, applies middleware and rate limiting, and mounts each router under `/api/v1`. [dependencies.py](../dependencies.py) holds the shared pieces: the connection pool, the response cache, the SQL loader, the authentication dependency and the Pydantic models.

Routes live in [routers/](../routers/), one module per area: [health](../routers/health.py), [devices](../routers/devices.py), [fleet](../routers/fleet.py), [events](../routers/events.py), [statistics](../routers/statistics.py), [admin](../routers/admin.py), [settings](../routers/settings.py), [api_keys](../routers/api_keys.py), [auth_config](../routers/auth_config.py) and [inventory_state](../routers/inventory_state.py). Ingest arrives through the events router, which writes each module's payload as one JSONB row per device in that module's table. The accepted module names are listed in `VALID_MODULE_NAMES` in [dependencies.py](../dependencies.py). Because the server stores payloads as sent, an agent can change what it collects without a schema migration.

Larger read queries are plain SQL files under [sql/](../sql/), grouped by area and loaded by name at runtime. Schema changes are Alembic migrations in [alembic/versions/](../alembic/versions/); [migrations.py](../migrations.py) runs them to head when the app starts, so a new container brings its database up to date before serving traffic.

Every request is authorized against the fleet passphrase, a per-client API key, an OIDC bearer token or the dashboard's internal secret, then gated by the `read`, `ingest` or `admin` scope. API keys are handled in [routers/api_keys.py](../routers/api_keys.py) and token validation in [oidc_auth.py](../oidc_auth.py). Supporting modules cover [pagination](../pagination.py), [ETags](../etag.py), [rate limiting](../rate_limit.py), [metrics](../metrics.py), [install status](../install_status.py) and [log tails](../log_tails.py).

The [Dockerfile](../Dockerfile) builds one image that runs on Azure, AWS or a local Docker host. The interactive OpenAPI page is served at `/docs` on a running instance.

## Development and verification

Use the current [README](../README.md) for configuration and the container quick start. Install the test dependencies from [requirements-dev.txt](../requirements-dev.txt), then run the suite from the repository root.

```
pip install -r requirements-dev.txt
```

```
pytest -rs
```

Tests live in [tests/](../tests/). The migration and SQL tests need a real PostgreSQL server and skip themselves unless `TEST_DATABASE_URL` points at one, so set it when a change touches SQL or migrations.

```
TEST_DATABASE_URL=postgresql://reportmate:reportmate@localhost:5432/reportmate pytest -rs
```

The [build workflow](../.github/workflows/build.yml) runs on every pull request. It runs the suite against a PostgreSQL 16 service, exports the OpenAPI spec with [scripts/export_openapi.py](../scripts/export_openapi.py) and checks that it rendered in full, then builds the container image. Images are pushed to the GitHub Container Registry only from `main` and version tags.

## Documentation ownership

Keep this wiki as the entry point and update the linked pages where the facts belong: configuration and authentication in the README, open hardening work in the production readiness notes, and the HTTP contract in the code that generates the OpenAPI spec. Examples use fictional data. Deployment inventories, credentials, provider mappings and organization-specific operations belong with their deployment owner, starting from the Terraform modules for [Azure](https://github.com/reportmate/terraform-azurerm-reportmate) and [AWS](https://github.com/reportmate/terraform-aws-reportmate).
