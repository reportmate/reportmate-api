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

## Dashboard insights

The dashboard's insight cards come from small cached endpoints, one per card, so a client can request them all at once and draw each card as soon as it arrives. Each card answers one question with a few counts and short top-N lists, so no client downloads a bulk report to draw one. The cards are `installHealth`, `rebootDebt`, `protectionGaps`, `managementToolErrors`, `storage`, `checkinGaps`, `osCurrency`, `softwareRisk`, `expiringCertificates`, `directoryJoin`, `connectivityProblems` and `appUsage`. Request one card for one platform:

```
curl -H "X-API-Key: $REPORTMATE_KEY" "http://localhost:8000/api/v1/dashboard/insights/storage?platform=macOS"
```

`platform` is `all` (the default), `macOS` or `Windows`, and `includeArchived=true` counts archived devices too. The response is `{card, platform, includeArchived, generatedAt, data}`. `data` is the card itself, with its own `generatedAt`. A card that fails server-side has `data` set to `{"error": "..."}`, and the other cards are unaffected.

App Usage takes its own filters: comma-separated inventory `usages` and `catalogs`, and `days` (30 by default). It returns the ten most-used apps and the usage and catalog values available to filter by:

```
curl -H "X-API-Key: $REPORTMATE_KEY" "http://localhost:8000/api/v1/dashboard/insights/appUsage?usages=Shared&catalogs=Lab"
```

`GET /api/v1/dashboard/insights` returns every card except App Usage in one document, `{generatedAt, platform, includeArchived, cards}`, built from the same per-card cache.

Every number and list item the apps can click carries a `link` with the report path and the full filter it opens, for example:

```
{"count": 42, "link": {"path": "/hardware", "params": {"storage": "low", "platform": "macOS"}}}
```

Each card is aggregate SQL over the module tables, run under a 20-second statement timeout. A background refresher recomputes every card, App Usage included, for `all`, `macOS` and `Windows` every four minutes. It runs one card at a time with a short pause between cards, so requests are answered from the cache. A cached value lasts five minutes, or one minute for a card that failed. A value past that is still served while a single background refresh replaces it. Only a combination nobody has asked for yet is computed on request, and concurrent requests for it share one computation.

The `X-Insights-Cache` response header says `fresh`, `stale` or `miss`, and `Age` gives the value's age in seconds. Every response carries an ETag, so a client that polls with `If-None-Match` gets a 304 with no body until the card changes.

Management Tools Errors counts the error and warning lines in each management tool's log tails over the last 24 hours. Ingest parses the tails once, as they arrive, and stores a small `levelSummary` on each log root: error and warning counts per UTC hour, and the most frequent error messages with numbers, paths and GUIDs stripped. The card is SQL over those summaries, so it never reads the tails themselves.

The devices behind a tool's row come from the same summaries. This lists the devices with error lines in the Munki or Cimian log over the last 24 hours, most lines first:

```
curl -H "X-API-Key: $REPORTMATE_KEY" "http://localhost:8000/api/v1/dashboard/insights/managementToolErrors/devices?tool=installs&level=error&hours=24&platform=macOS"
```

`tool` is the log root key from the card's link, `level` is `error` or `warning`, and `hours` is 1 to 168. The response is `{tool, level, hours, platform, generatedAt, devices}`. Each device has `serialNumber`, `deviceName`, `platform`, `count`, `lastAt` (the start of the latest UTC hour with such a line) and a `link` to its log viewer. It is cached like the cards.

These environment variables tune it: `INSIGHTS_CACHE_TTL_SECONDS` (300), `INSIGHTS_ERROR_TTL_SECONDS` (60), `INSIGHTS_REFRESH_INTERVAL_SECONDS` (240), `INSIGHTS_REFRESH_STAGGER_SECONDS` (1), `INSIGHTS_BACKGROUND_REFRESH` (true), `INSIGHTS_WARM_DELAY_SECONDS` (15), `INSIGHTS_STATEMENT_TIMEOUT_SECONDS` (20), `INSIGHTS_CONCURRENCY` (3, capped at a quarter of `DB_POOL_MAX`, which bounds on-demand computations) and `INSIGHTS_CACHE_MAX_ENTRIES` (256).

## License

AGPL-3.0. If you self-host this for your own fleet, you're done — use it, change it, run it, that's the whole point.

If you're planning to take this code, run it as a hosted service for other people, and not share your changes back — the AGPL says you have to share. That's the deal. If your legal team can't live with that, [a commercial license](./COMMERCIAL-LICENSE.md) is available; email `hello@reportmate.app`.

The client agents and Terraform modules live in separate repos and are Apache-2.0, so you can embed them in your own tooling without copyleft pulling on the rest of your codebase.

## Trademark

The name "ReportMate" and the logo are not part of the license grant. Fork the code freely, but rename your fork.

## Contributing

PRs are welcome. First-time contributors get pinged by the CLA Assistant bot to sign a one-page CLA — this is what makes the dual-license model legally work. Sign it once and you're set for all future PRs.

Development guide: [wiki](wiki/README.md)

## The rest of the project

- [`reportmate-app-web`](https://github.com/reportmate/reportmate-app-web) — Next.js dashboard (AGPL-3.0)
- [`reportmate-client-mac`](https://github.com/reportmate/reportmate-client-mac) — macOS agent (Apache-2.0)
- [`reportmate-client-win`](https://github.com/reportmate/reportmate-client-win) — Windows agent (Apache-2.0)
- [`terraform-azurerm-reportmate`](https://github.com/reportmate/terraform-azurerm-reportmate) — Azure deploy module (Apache-2.0)
- [`terraform-aws-reportmate`](https://github.com/reportmate/terraform-aws-reportmate) — AWS deploy module (Apache-2.0)
- [`reportmate-website`](https://github.com/reportmate/reportmate-website) — Marketing site (Apache-2.0)
