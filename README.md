# reportmate-api

The server side of [ReportMate](https://reportmate.app). Mac and Windows agents post fleet telemetry to this. The dashboard reads from it. You host the whole stack — no SaaS vendor sitting in the middle of your fleet's data, no per-device fees.

If you're trying to see your whole fleet across both platforms without paying Jamf + Intune + Kandji to do it for you, this is the thing.

## What it does

Agents on each device collect their state (hardware specs, installed apps, network config, security posture, MDM enrollment, etc.) and POST it here every check-in. The API writes each module's payload to its own Postgres JSONB column so schemas can evolve without forcing client updates. The Next.js dashboard reads back through the same REST surface.

Same image runs on Azure Container Apps, AWS ECS, or your laptop:

```
docker run --rm -p 8000:8000 \
  -e DATABASE_URL=postgresql://reportmate:password@host.docker.internal:5432/reportmate \
  -e REPORTMATE_PASSPHRASE=changeme \
  ghcr.io/reportmate/reportmate-api:latest
```

OpenAPI is at `http://localhost:8000/docs`.

## How the pieces fit

```
clients (macOS, Windows)  ──submit──>  reportmate-api  ──reads/writes──>  PostgreSQL
                                            ▲
                                            │
                                         dashboard (apps/www, Next.js)
```

Module payloads are stored verbatim as JSONB, one column per module. The client decides what to send; the server doesn't try to be smart about it. That means you can change what a client collects without writing a migration.

## Authentication

Every request is authorized against one of these credentials, then gated by a least-privilege scope (`read` for GETs, `ingest` for telemetry POSTs, `admin` for mutations and admin endpoints):

- **`X-Client-Passphrase`** — the shared fleet passphrase the device agents send. Full access. This is the simplest self-host path.
- **`X-API-Key`** — per-client keys (`rm_<id>_<secret>`), scope-limited and audited. Mint these for individual integrations and retire the shared passphrase over time.
- **`Authorization: Bearer <jwt>`** — a federated OIDC token, described below.
- **`X-Internal-Secret`** — the dashboard BFF → API hop only.

### OIDC bearer tokens (SSO)

The API can accept short-lived JWTs issued by any OpenID Connect provider — Microsoft Entra, Okta, Auth0, Keycloak, Google — so an operator's own SSO session becomes their API credential, scoped to the roles their IdP grants them. The API stores no secret for this path: identity is proven by the provider's signature, so there is nothing to rotate and nothing to leak.

It is inert until you configure it. Enable it by pointing the API at one or more trusted issuers and the audience your tokens are minted for:

```
ENABLE_OIDC_AUTH=true
OIDC_ISSUERS=https://login.microsoftonline.com/<tenant-id>/v2.0
OIDC_AUDIENCE=api://reportmate
```

`OIDC_ISSUERS` and `OIDC_AUDIENCE` are comma-separated, so multiple providers or audiences can be trusted at once. Signing keys are discovered from each issuer's `/.well-known/openid-configuration`; set `OIDC_JWKS_URI` to pin a JWKS endpoint for providers without a discovery document.

The token's IdP roles or scopes are mapped to ReportMate scopes. By default the app roles `ReportMate.Read`, `ReportMate.Ingest`, and `ReportMate.Admin` (and the bare names `read` / `ingest` / `admin`) are recognized; override the mapping — for example to grant scopes by group id — with `OIDC_ROLE_SCOPE_MAP` (JSON). A valid token that maps to no scope is rejected.

With that configured, a caller in the tenant gets a token the way they get one for any other resource and sends it as a bearer — the Entra example mirrors the Azure CLI exactly:

```
az account get-access-token --resource api://reportmate --query accessToken -o tsv
```

Only asymmetric signatures (`RS*`/`ES*`) are accepted; `none` and `HS*` are refused to prevent algorithm-confusion attacks. Full env reference: `ENABLE_OIDC_AUTH`, `OIDC_ISSUERS`, `OIDC_AUDIENCE`, `OIDC_JWKS_URI`, `OIDC_ALGORITHMS`, `OIDC_ROLE_SCOPE_MAP`, `OIDC_DEFAULT_SCOPES`, `OIDC_LEEWAY`.

## License

AGPL-3.0. If you self-host this for your own fleet, you're done — use it, change it, run it, that's the whole point.

If you're planning to take this code, run it as a hosted service for other people, and not share your changes back — the AGPL says you have to share. That's the deal. If your legal team can't live with that, [a commercial license](./COMMERCIAL-LICENSE.md) is available; email `hello@reportmate.app`.

The client agents and Terraform modules live in separate repos and are Apache-2.0, so you can embed them in your own tooling without copyleft pulling on the rest of your codebase.

## Trademark

The name "ReportMate" and the logo are not part of the license grant. Fork the code freely, but rename your fork. [TRADEMARK.md](https://github.com/reportmate/.github/blob/main/TRADEMARK.md) has the details.

## Contributing

PRs are welcome. First-time contributors get pinged by the CLA Assistant bot to sign a one-page CLA — this is what makes the dual-license model legally work. Sign it once and you're set for all future PRs.

## The rest of the project

- [`reportmate-app-web`](https://github.com/reportmate/reportmate-app-web) — Next.js dashboard (AGPL-3.0)
- [`reportmate-client-mac`](https://github.com/reportmate/reportmate-client-mac) — macOS agent (Apache-2.0)
- [`reportmate-client-win`](https://github.com/reportmate/reportmate-client-win) — Windows agent (Apache-2.0)
- [`terraform-azurerm-reportmate`](https://github.com/reportmate/terraform-azurerm-reportmate) — Azure deploy module (Apache-2.0)
- [`terraform-aws-reportmate`](https://github.com/reportmate/terraform-aws-reportmate) — AWS deploy module (Apache-2.0)
- [`reportmate-website`](https://github.com/reportmate/reportmate-website) — Marketing site (Apache-2.0)
