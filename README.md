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

`DATABASE_SCHEMA` must be a lowercase PostgreSQL identifier. TypeORM schema synchronization is
disabled. Create the selected database and schema before applying forward-only migrations:

```bash
npm run migration:run
```

Minimal NestJS backend baseline for the Udemy Personal project.

## API

The health-style Hello endpoint is available at `GET /api/v1/hello` and returns the current service greeting.

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
