# ReportMate API

The open-source endpoint management server. FastAPI + PostgreSQL.

ReportMate collects hardware, software, network, and security telemetry from macOS and Windows endpoints via lightweight native agents and exposes it through a clean REST API. This repository contains the server. The dashboard, client agents, and Terraform deploy modules live in sibling repositories under [github.com/reportmate](https://github.com/reportmate).

## What this is

- **REST API** over FastAPI (Python 3.11). 34+ versioned endpoints under `/api/v1`.
- **PostgreSQL** storage (JSONB per module). Schema migrations included.
- **Container-first**. Same image runs on Azure Container Apps, AWS ECS Fargate, or `docker run` locally.
- **Cloud-agnostic core** — Azure WebPubSub for real-time push is the only cloud-specific dependency today, and it is being made pluggable.

## Quick start (local)

```
docker run --rm -p 8000:8000 \
  -e DATABASE_URL=postgresql://reportmate:password@host.docker.internal:5432/reportmate \
  -e REPORTMATE_PASSPHRASE=changeme \
  ghcr.io/reportmate/reportmate-api:latest
```

OpenAPI spec is served at `http://localhost:8000/docs`.

## Architecture

```
clients (macOS, Windows)  ──submit──>  reportmate-api  ──reads/writes──>  PostgreSQL
                                            ▲
                                            │
                                         dashboard (apps/www, Next.js)
```

Each endpoint payload is module-scoped (hardware, software, network, security, etc.) and stored as JSONB so schema evolution does not require migrations on the client.

## License

ReportMate API is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0). See `LICENSE`.

The AGPL ensures that anyone running ReportMate as a hosted service must publish their modifications. This protects the project from hostile cloud-forks and keeps the ecosystem healthy.

**For organizations that cannot use AGPL code**, a commercial license is available that lifts the share-alike obligations. Contact `hello@reportmate.app`. See `COMMERCIAL-LICENSE.md`.

The ReportMate client agents (`reportmate-client-mac`, `reportmate-client-win`) and Terraform deploy modules are Apache-2.0 — you can embed and customize them without copyleft obligations.

## Trademark

"ReportMate" and the ReportMate logo are reserved. Forks may use the code under AGPL terms but must rename. See [TRADEMARK.md](https://github.com/reportmate/.github/blob/main/TRADEMARK.md).

## Contributing

Contributions are welcome. Because ReportMate offers a dual-license, contributors must sign a Contributor License Agreement (CLA) before a PR can be merged. The CLA Assistant bot will request this automatically on your first PR.

## Related repositories

- [`reportmate-app-web`](https://github.com/reportmate/reportmate-app-web) — Next.js dashboard (AGPL-3.0)
- [`reportmate-client-mac`](https://github.com/reportmate/reportmate-client-mac) — macOS agent (Apache-2.0)
- [`reportmate-client-win`](https://github.com/reportmate/reportmate-client-win) — Windows agent (Apache-2.0)
- [`terraform-azurerm-reportmate`](https://github.com/reportmate/terraform-azurerm-reportmate) — Azure deploy module (Apache-2.0)
- [`terraform-aws-reportmate`](https://github.com/reportmate/terraform-aws-reportmate) — AWS deploy module (Apache-2.0)
- [`reportmate-website`](https://github.com/reportmate/reportmate-website) — Marketing site (Apache-2.0)
