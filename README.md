# Keycloak Auth Gateway

A small OIDC callback broker for Keycloak that supports:

- Shared redirect callback endpoint (`/callback`)
- DB-backed allowed app configuration
- CRUD APIs for app management (for GUI use)
- One-time code exchange API for apps (`/v1/auth/exchange`)
- Dedicated audience token exchange API for MFEs (`/v1/auth/token-exchange`)

## Endpoints

- `GET /healthz`
- `GET /start?app=<slug>&return_to=<path-or-url>`
- `GET /callback`
- `POST /v1/auth/exchange`
- `POST /v1/auth/token-exchange`
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
    "base_urls": [
      "https://shell.suncoast.systems",
      "http://localhost:4173"
    ],
    "enabled": true
  }'
```

`base_url` is still accepted for backward compatibility, but `base_urls` is preferred.

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

Request Hasura claims using the configured Hasura audience lookup:

```sh
curl -X POST http://localhost:8080/v1/auth/exchange \
  -H 'Content-Type: application/json' \
  -d '{
    "code":"<gateway_code>",
    "app_slug":"shell",
    "request_hasura_claims": true
  }'
```

When `request_hasura_claims=true` and `requested_audience` is not provided, the audience is resolved in this order:

1. Vault lookup (`HASURA_TOKEN_AUDIENCE_VAULT_PATH`, if configured)
2. Fallback static value (`HASURA_TOKEN_AUDIENCE` or `HASURA_TOKEN_AUDIENCE_FILE`)

Vault lookup supports `{app_slug}` in the path template. Example:

- `HASURA_TOKEN_AUDIENCE_VAULT_PATH=kv/data/keycloak/hasura/{app_slug}`
- `HASURA_TOKEN_AUDIENCE_VAULT_KEY=audience`

## MFE Audience Exchange API

Use this when an MFE already has a bearer token and needs a different audience (or multiple audiences).

Request:

```sh
curl -X POST http://localhost:8080/v1/auth/token-exchange \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <user_access_token>' \
  -d '{
    "app_slug":"shell",
    "requested_audience":"graphql-api-7603d234"
  }'
```

Multiple audiences (single exchanged token with multiple `aud` values):

```sh
curl -X POST http://localhost:8080/v1/auth/token-exchange \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <user_access_token>' \
  -d '{
    "app_slug":"shell",
    "requested_audiences":["graphql-api-7603d234","openwebui"]
  }'
```

Request body fields:

- `app_slug` (required)
- `subject_token` (optional if passed as `Authorization: Bearer ...`)
- `requested_audience` (optional)
- `requested_audiences` (optional array)
- `requested_scope` (optional)
- `request_hasura_claims` (optional; resolves audience using Hasura audience config if no audience is provided)

## Configuration

### Required

- `EXTERNAL_BASE_URL` (for example `https://login.suncoast.systems`)
- `KEYCLOAK_ISSUER` (for example `https://auth.suncoast.systems/realms/external`)
- `OIDC_CLIENT_ID`
- `OIDC_EXCHANGE_CLIENT_ID` (optional; defaults to `OIDC_CLIENT_ID`)
- Database config via `DATABASE_URL` or `DB_*` vars

### Optional

- `OIDC_CLIENT_SECRET` or `OIDC_CLIENT_SECRET_FILE`
- `OIDC_EXCHANGE_CLIENT_SECRET` or `OIDC_EXCHANGE_CLIENT_SECRET_FILE` (optional; defaults to `OIDC_CLIENT_SECRET`)
- `ADMIN_API_TOKEN` or `ADMIN_API_TOKEN_FILE`
- `CORS_ALLOW_ORIGINS` (comma-separated list, `*`, wildcard subdomain patterns like `*.suncoast.systems`, and `localhost`)
- `HASURA_TOKEN_AUDIENCE` or `HASURA_TOKEN_AUDIENCE_FILE` (fallback when `request_hasura_claims=true`)
- `VAULT_ADDR` (required when `HASURA_TOKEN_AUDIENCE_VAULT_PATH` is set)
- `VAULT_TOKEN` or `VAULT_TOKEN_FILE` (required when `HASURA_TOKEN_AUDIENCE_VAULT_PATH` is set)
- `HASURA_TOKEN_AUDIENCE_VAULT_PATH` (Vault API path; can include `{app_slug}`)
- `HASURA_TOKEN_AUDIENCE_VAULT_KEY` (field name in the Vault secret, default `audience`)
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
