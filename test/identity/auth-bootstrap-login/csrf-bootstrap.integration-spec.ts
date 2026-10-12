import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';

import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import request, { Response } from 'supertest';
import { DataSource } from 'typeorm';

import { AppModule } from '../../../src/app.module';
import { sha256Hex } from '../../../src/modules/identity/application/auth-secrets';
import { SessionEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/session.entity';
import { createIdentityDataSource } from '../../../src/shared/database/identity-database-options';
import { configureApplication } from '../../../src/main';
import {
  createIsolatedPostgresDatabaseOptions,
  createIsolatedPostgresEnvironment,
  createIsolatedPostgresPlan,
  IsolatedPostgresPlan,
  startIsolatedPostgres,
} from '../../support/isolated-postgres-harness';

const ORIGIN = 'http://localhost:4200';

describe('Pre-auth CSRF bootstrap', () => {
  let app: INestApplication;
  let observer: DataSource;
  let plan: IsolatedPostgresPlan;
  let cleanup: (() => Promise<void>) | undefined;
  let previousEnvironment: Map<string, string | undefined>;

  beforeAll(async () => {
    previousEnvironment = captureEnvironment();
    plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(
        randomBytes(32).toString('hex'),
        await selectLoopbackPort(),
      ),
    );
    const run = await startIsolatedPostgres(plan);
    cleanup = (): Promise<void> => run.cleanup();
    await run.migrate({ createDataSource: createIdentityDataSource });
    applyEnvironment(plan);
    app = await NestFactory.create(AppModule, { abortOnError: false, logger: false });
    configureApplication(app);
    await app.init();
    observer = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
    await observer.initialize();
  });

  afterAll(async () => {
    if (observer?.isInitialized) await observer.destroy();
    if (app !== undefined) await app.close();
    if (cleanup !== undefined) await cleanup();
    restoreEnvironment(previousEnvironment);
  });

  it('creates a ten-minute hash-only pre-auth session with independent 32-byte opaque cookie and CSRF tokens', async () => {
    const response = await request(app.getHttpServer()).get('/api/v1/auth/csrf').expect(200);
    const receipt = readBootstrap(response);
    const rawCookie = readRawSetCookie(response);
    const cookieToken = readCookieToken(rawCookie);
    const session = await observer.getRepository(SessionEntity).findOneByOrFail({
      tokenHash: sha256Hex(cookieToken),
    });

    expect(response.body).toEqual({ data: { csrfToken: receipt.csrfToken } });
    expect(cookieToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(receipt.csrfToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(cookieToken).not.toBe(receipt.csrfToken);
    expect(rawCookie).toMatch(/; Path=\//);
    expect(rawCookie).toContain('; HttpOnly');
    expect(rawCookie).toContain('; Secure');
    expect(rawCookie).toContain('; SameSite=Lax');
    expect(rawCookie).not.toMatch(/; Domain=/i);
    expect(session).toMatchObject({ state: 'pre_auth', userId: null, revokedAt: null });
    expect(session.tokenHash).toBe(sha256Hex(cookieToken));
    expect(session.csrfTokenHash).toBe(sha256Hex(receipt.csrfToken));
    expect(session.tokenHash).not.toContain(cookieToken);
    expect(session.csrfTokenHash).not.toContain(receipt.csrfToken);
    expect(session.absoluteExpiresAt.getTime() - session.createdAt.getTime()).toBe(10 * 60 * 1000);
    expect(session.idleExpiresAt.getTime()).toBe(session.absoluteExpiresAt.getTime());
  });

  it('allows an absent or allowlisted Origin and conditionally rotates the active pre-auth CSRF hash', async () => {
    const first = await request(app.getHttpServer()).get('/api/v1/auth/csrf').expect(200);
    const firstReceipt = readBootstrap(first);
    const firstCookie = readCookieToken(readRawSetCookie(first));
    const before = await observer.getRepository(SessionEntity).findOneByOrFail({
      tokenHash: sha256Hex(firstCookie),
    });

    const rotated = await request(app.getHttpServer())
      .get('/api/v1/auth/csrf')
      .set('Origin', ORIGIN)
      .set('Cookie', `__Host-session=${firstCookie}`)
      .expect(200);
    const rotatedReceipt = readBootstrap(rotated);
    const after = await observer.getRepository(SessionEntity).findOneByOrFail({ id: before.id });

    expect(readCookieToken(readRawSetCookie(rotated))).toBe(firstCookie);
    expect(rotatedReceipt.csrfToken).not.toBe(firstReceipt.csrfToken);
    expect(after.csrfTokenHash).toBe(sha256Hex(rotatedReceipt.csrfToken));
    expect(after.csrfTokenHash).not.toBe(before.csrfTokenHash);
  });

  it('clears malformed, unknown, expired, or revoked session cookies without creating a replacement session', async () => {
    const cases = [
      { label: 'malformed', cookie: '__Host-session=not-an-opaque-token' },
      { label: 'unknown', cookie: `__Host-session=${randomBytes(32).toString('base64url')}` },
    ];
    for (const testCase of cases) {
      const before = await observer.getRepository(SessionEntity).count();
      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/csrf')
        .set('Cookie', testCase.cookie)
        .expect(401);
      expect(response.body.code).toBe('AUTHENTICATION_REQUIRED');
      expect(readRawSetCookie(response)).toContain('__Host-session=;');
      expect(await observer.getRepository(SessionEntity).count()).toBe(before);
    }

    for (const state of ['expired', 'revoked'] as const) {
      const token = randomBytes(32).toString('base64url');
      await insertPreAuthSession(observer, token, state);
      const before = await observer.getRepository(SessionEntity).count();
      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/csrf')
        .set('Cookie', `__Host-session=${token}`)
        .expect(401);
      expect(response.body.code).toBe('AUTHENTICATION_REQUIRED');
      expect(readRawSetCookie(response)).toContain('__Host-session=;');
      expect(await observer.getRepository(SessionEntity).count()).toBe(before);
    }
  });

  it('rejects an active authenticated session without rotating, clearing, or touching its exact row', async () => {
    const token = randomBytes(32).toString('base64url');
    const session = await insertAuthenticatedSession(observer, token);
    const response = await request(app.getHttpServer())
      .get('/api/v1/auth/csrf')
      .set('Cookie', `__Host-session=${token}`)
      .expect(403);
    const after = await observer.getRepository(SessionEntity).findOneByOrFail({ id: session.id });

    expect(response.headers['set-cookie']).toBeUndefined();
    expect(after).toMatchObject({
      tokenHash: session.tokenHash,
      csrfTokenHash: session.csrfTokenHash,
      state: 'authenticated',
      lastSeenAt: session.lastSeenAt,
      revokedAt: null,
    });
  });
});

type BootstrapReceipt = { readonly csrfToken: string };
type InvalidPreAuthState = 'expired' | 'revoked';

function readBootstrap(response: Response): BootstrapReceipt {
  const token = response.body?.data?.csrfToken;
  if (typeof token !== 'string') throw new Error('CSRF bootstrap did not return a token.');
  return { csrfToken: token };
}

function readRawSetCookie(response: Response): string {
  const values = response.headers['set-cookie'];
  if (!Array.isArray(values) || typeof values[0] !== 'string') {
    throw new Error('Expected identity Set-Cookie header.');
  }
  return values[0];
}

function readCookieToken(rawCookie: string): string {
  const match = /^__Host-session=([^;]+)/.exec(rawCookie);
  if (match?.[1] === undefined) throw new Error('Expected identity cookie value.');
  return match[1];
}

async function insertPreAuthSession(
  source: DataSource,
  token: string,
  state: InvalidPreAuthState,
): Promise<void> {
  const now = new Date();
  const expired = state === 'expired';
  await source.getRepository(SessionEntity).save({
    id: randomUUID(),
    userId: null,
    tokenHash: sha256Hex(token),
    csrfTokenHash: sha256Hex(randomBytes(32).toString('base64url')),
    state: expired ? 'pre_auth' : 'revoked',
    createdAt: new Date(now.getTime() - 20 * 60 * 1000),
    lastSeenAt: new Date(now.getTime() - 20 * 60 * 1000),
    absoluteExpiresAt: expired
      ? new Date(now.getTime() - 10 * 60 * 1000)
      : new Date(now.getTime() + 10 * 60 * 1000),
    idleExpiresAt: expired
      ? new Date(now.getTime() - 10 * 60 * 1000)
      : new Date(now.getTime() + 10 * 60 * 1000),
    revokedAt: expired ? null : now,
  });
}

async function insertAuthenticatedSession(
  source: DataSource,
  token: string,
): Promise<SessionEntity> {
  const now = new Date();
  return source.getRepository(SessionEntity).save({
    id: randomUUID(),
    userId: randomUUID(),
    tokenHash: sha256Hex(token),
    csrfTokenHash: sha256Hex(randomBytes(32).toString('base64url')),
    state: 'authenticated',
    createdAt: now,
    lastSeenAt: now,
    absoluteExpiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1000),
    idleExpiresAt: new Date(now.getTime() + 8 * 60 * 60 * 1000),
    revokedAt: null,
  });
}

function captureEnvironment(): Map<string, string | undefined> {
  return new Map(
    [
      'DATABASE_HOST',
      'DATABASE_PORT',
      'DATABASE_USERNAME',
      'DATABASE_PASSWORD',
      'DATABASE_NAME',
      'DATABASE_SCHEMA',
      'IDENTITY_THROTTLE_HMAC_SECRET',
      'NODE_ENV',
      'CORS_ALLOWED_ORIGINS',
    ].map((key) => [key, process.env[key]]),
  );
}

function applyEnvironment(plan: IsolatedPostgresPlan): void {
  process.env.NODE_ENV = 'test';
  process.env.CORS_ALLOWED_ORIGINS = ORIGIN;
  process.env.IDENTITY_THROTTLE_HMAC_SECRET = randomBytes(32).toString('base64url');
  process.env.DATABASE_HOST = plan.environment.IDENTITY_TEST_POSTGRES_HOST;
  process.env.DATABASE_PORT = plan.environment.IDENTITY_TEST_POSTGRES_PORT;
  process.env.DATABASE_USERNAME = plan.environment.IDENTITY_TEST_DATABASE_USER;
  process.env.DATABASE_PASSWORD = plan.environment.IDENTITY_TEST_DATABASE_PASSWORD;
  process.env.DATABASE_NAME = plan.databaseName;
  process.env.DATABASE_SCHEMA = plan.schemaName;
}

function restoreEnvironment(previous: Map<string, string | undefined>): void {
  for (const [key, value] of previous) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

function selectLoopbackPort(): Promise<number> {
  return new Promise((resolvePort, rejectPort) => {
    const server = createServer();
    server.once('error', rejectPort);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') {
        server.close(() => rejectPort(new Error('No loopback port.')));
        return;
      }
      server.close((error) =>
        error === undefined ? resolvePort(address.port) : rejectPort(error),
      );
    });
  });
}
