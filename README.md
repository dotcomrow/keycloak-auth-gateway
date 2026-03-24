# Keycloak Auth Gateway

A small OIDC callback broker for Keycloak that supports:

- Shared redirect callback endpoint (`/callback`)
- DB-backed allowed app configuration
- CRUD APIs for app management (for GUI use)
- One-time code exchange API for apps (`/v1/auth/exchange`)

## Endpoints

- `GET /healthz`
- `GET /start?app=<slug>&return_to=<path-or-url>`
- `GET /callback`
- `POST /v1/auth/exchange`
- `GET /v1/apps`
- `POST /v1/apps`
- `GET /v1/apps/{slug}`
- `PUT /v1/apps/{slug}`
- `DELETE /v1/apps/{slug}`

## Management API Auth

Set `ADMIN_API_TOKEN` (or `ADMIN_API_TOKEN_FILE`) to require:

`Authorization: Bearer <token>`

for `/v1/apps*` endpoints.

## App Registration Example

```sh
curl -X POST http://localhost:8080/v1/apps \
  -H 'Content-Type: application/json' \
  -d '{
    "slug": "shell",
    "display_name": "Shell App",
    "base_url": "https://shell.suncoast.systems",
    "enabled": true
  }'
```

## Login Start Example

```sh
curl -i 'http://localhost:8080/start?app=shell&return_to=/auth/callback'
```

## Exchange Example

```sh
curl -X POST http://localhost:8080/v1/auth/exchange \
  -H 'Content-Type: application/json' \
  -d '{"code":"<gateway_code>","app_slug":"shell"}'
```

## Exchange With Requested Claims/Audience

To keep default behavior unchanged, token shaping is opt-in at exchange time.

Request a token exchange for a specific audience:

```sh
curl -X POST http://localhost:8080/v1/auth/exchange \
  -H 'Content-Type: application/json' \
  -d '{
    "code":"<gateway_code>",
    "app_slug":"shell",
    "requested_audience":"graphql-api-7603d234"
  }'
```

Request Hasura claims using a configured audience shortcut:

```sh
curl -X POST http://localhost:8080/v1/auth/exchange \
  -H 'Content-Type: application/json' \
  -d '{
    "code":"<gateway_code>",
    "app_slug":"shell",
    "request_hasura_claims": true
  }'
```

## Configuration

### Required

- `EXTERNAL_BASE_URL` (for example `https://login.suncoast.systems`)
- `KEYCLOAK_ISSUER` (for example `https://auth.suncoast.systems/realms/external`)
- `OIDC_CLIENT_ID`
- Database config via `DATABASE_URL` or `DB_*` vars

### Optional

- `OIDC_CLIENT_SECRET` or `OIDC_CLIENT_SECRET_FILE`
- `ADMIN_API_TOKEN` or `ADMIN_API_TOKEN_FILE`
- `CORS_ALLOW_ORIGINS` (comma-separated list or `*`)
- `HASURA_TOKEN_AUDIENCE` (used when `request_hasura_claims=true`)
- `STATE_TTL` (default `10m`)
- `EXCHANGE_CODE_TTL` (default `2m`)
- `APP_CODE_PARAM` (default `gateway_code`)
- `CALLBACK_PATH` (default `/callback`)

### Database Variables

If not using `DATABASE_URL`:

- `DB_HOST` (default `yb-tserver-service.yugabyte.svc.cluster.local`)
- `DB_PORT` (default `5433`)
- `DB_NAME` (default `keycloak`)
- `DB_SEARCH_PATH` (default `keycloak`)
- `DB_SSLMODE` (default `disable`)
- `DB_USER` or `DB_USER_FILE`
- `DB_PASSWORD` or `DB_PASSWORD_FILE`

## Local Build

```sh
docker build -t keycloak-auth-gateway:local .
```

## Image Publishing (GHCR)

This repo includes a GitHub Actions workflow at `.github/workflows/publish-image.yml`.

On pushes to the default branch (and on tags), it builds and publishes:

- `ghcr.io/<repo-owner>/keycloak-auth-gateway:latest` (default branch)
- `ghcr.io/<repo-owner>/keycloak-auth-gateway:sha-<commit>`

You can also run the workflow manually with `workflow_dispatch`.
