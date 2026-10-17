# Udemy Personal Backend

## Configuration

`NODE_ENV` accepts `development`, `test`, or `production` and defaults to `development`.
`PORT` defaults to `3000`. `CORS_ALLOWED_ORIGINS` is a comma-separated allowlist: local
HTTP `localhost` or `127.0.0.1` origins in development and test, and explicit HTTPS origins
in production. Production startup fails when its allowlist is absent.

Database-backed startup requires all of these values and fails when any is absent or invalid:

```text
DATABASE_HOST
DATABASE_PORT
DATABASE_USERNAME
DATABASE_PASSWORD
DATABASE_NAME
DATABASE_SCHEMA
```

Identity authentication also requires `IDENTITY_THROTTLE_HMAC_SECRET`: a base64url-encoded secret
of at least 32 bytes. Supply it through the runtime environment; do not place a secret value in
source control or this example configuration.

`DATABASE_SCHEMA` must be a lowercase PostgreSQL identifier. TypeORM schema synchronization is
disabled. Create the selected database and schema before applying forward-only migrations:

```bash
npm run migration:run
```

Minimal NestJS backend baseline for the Udemy Personal project.

## API

The health-style Hello endpoint is available at `GET /api/v1/hello` and returns the current service greeting.

The identity boundary provides `GET /api/v1/auth/csrf`, `POST /api/v1/auth/register`,
`POST /api/v1/auth/login`, `GET /api/v1/auth/me`, and `POST /api/v1/auth/logout`.
Registration creates an ordinary account and does not authenticate it. `GET /api/v1/auth/csrf`
creates a pre-auth session when no cookie is supplied, rotates active pre-auth or authenticated
session CSRF state, and clears/returns `401` for terminal supplied cookies. `GET /api/v1/auth/me`
returns only the current authenticated user's `id` and `email`, sends `Cache-Control: no-store`,
and does not renew the session. Registration, login, and logout require an allowed `Origin`, the
`__Host-session` cookie, and the current `X-CSRF-Token`; logout clears the cookie and returns a
bodyless `204`.

## Prerequisites

Use Node.js 22 and npm.

## Commands

```bash
npm ci
npm run format:check
npm run lint
npm run typecheck
npm run test:unit
npm run test:e2e
npm run build
```

For local development:

```bash
npm run start:dev
```
