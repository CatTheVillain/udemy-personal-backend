import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { Writable } from 'node:stream';
import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import request, { Response } from 'supertest';
import { DataSource } from 'typeorm';
import { AppModule } from '../../../src/app.module';
import {
  IDENTITY_CLOCK,
  IdentityClock,
} from '../../../src/modules/identity/application/identity-clock';
import { SessionEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/session.entity';
import { createIdentityDataSource } from '../../../src/shared/database/identity-database-options';
import { ApplicationOptions, configureApplication } from '../../../src/main';
import {
  createIsolatedPostgresDatabaseOptions,
  createIsolatedPostgresEnvironment,
  createIsolatedPostgresPlan,
  IsolatedPostgresPlan,
  startIsolatedPostgres,
} from '../../support/isolated-postgres-harness';

const ORIGIN = 'http://localhost:4200';
const PASSWORD = 'literal valid password';
const HOUR = 60 * 60 * 1000;
type Receipt = { readonly cookie: string; readonly csrfToken: string };
type SessionView = Pick<
  SessionEntity,
  | 'id'
  | 'userId'
  | 'csrfTokenHash'
  | 'state'
  | 'lastSeenAt'
  | 'idleExpiresAt'
  | 'absoluteExpiresAt'
  | 'revokedAt'
>;

describe('Authenticated session HTTP lifecycle', () => {
  let app: INestApplication;
  let observer: DataSource;
  let cleanup: (() => Promise<void>) | undefined;
  let prior: Map<string, string | undefined>;
  let logOutput = '';

  beforeAll(async () => {
    prior = savedEnvironment();
    const plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(randomBytes(32).toString('hex'), await loopbackPort()),
    );
    const run = await startIsolatedPostgres(plan);
    cleanup = (): Promise<void> => run.cleanup();
    await run.migrate({ createDataSource: createIdentityDataSource });
    setEnvironment(plan);
    observer = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
    await observer.initialize();
  });

  beforeEach(async () => {
    logOutput = '';
    app = await NestFactory.create(AppModule, { abortOnError: false, logger: false });
    configureApplication(
      app,
      new ApplicationOptions(
        undefined,
        new Writable({
          write(chunk, _encoding, callback): void {
            logOutput += chunk.toString();
            callback();
          },
        }),
      ),
    );
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  afterAll(async () => {
    if (observer?.isInitialized) await observer.destroy();
    if (cleanup !== undefined) await cleanup();
    restoreEnvironment(prior);
  });

  it('retains pre-auth shared GET csrf behavior and rotates only the real authenticated session row', async () => {
    const preAuth = await bootstrap(app);
    const preAuthRotation = await request(app.getHttpServer())
      .get('/api/v1/auth/csrf')
      .set('Origin', ORIGIN)
      .set('Cookie', preAuth.cookie)
      .expect(200);
    expect(cookie(preAuthRotation)).toBe(preAuth.cookie);
    expect(csrf(preAuthRotation)).not.toBe(preAuth.csrfToken);
    const authenticated = await login(app);
    const before = await row(authenticated.cookie);
    const rotation = await request(app.getHttpServer())
      .get('/api/v1/auth/csrf')
      .set('Origin', ORIGIN)
      .set('Cookie', authenticated.cookie)
      .expect(200);
    const after = await row(authenticated.cookie);
    expect(cookie(rotation)).toBe(authenticated.cookie);
    expect(after).toMatchObject({
      id: before.id,
      userId: before.userId,
      state: 'authenticated',
      revokedAt: null,
    });
    expect(after.csrfTokenHash).toBe(hash(csrf(rotation)));
    expect(after.csrfTokenHash).not.toBe(before.csrfTokenHash);
    expect(after.lastSeenAt.getTime()).toBeGreaterThanOrEqual(before.lastSeenAt.getTime());
  });

  it('maps /me to id and email only, no-store, without mutating its authenticated row', async () => {
    const authenticated = await login(app);
    const before = await row(authenticated.cookie);
    const response = await request(app.getHttpServer())
      .get('/api/v1/auth/me')
      .set('Cookie', authenticated.cookie)
      .expect(200);
    const after = await row(authenticated.cookie);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.body).toEqual({ data: { id: before.userId, email: authenticated.email } });
    expect(response.text).not.toMatch(/password|csrf|token|hash|expires|lastSeen/i);
    expect(after).toEqual(before);
  });

  it('captures a legitimate safe Pino completion event while keeping secrets and client identity selectors out of logs and bodies', async () => {
    const authenticated = await login(app);
    const before = await row(authenticated.cookie);
    const passwordMarker = 'pino-password-marker';
    const emailMarker = 'pino-email-marker@example.test';
    const tokenMarker = randomBytes(32).toString('base64url');
    const csrfMarker = randomBytes(32).toString('base64url');
    const queryMarker = 'pino-query-marker';
    const current = await activeCsrf(app, authenticated.cookie);
    logOutput = '';
    const projection = await request(app.getHttpServer())
      .get(`/api/v1/auth/me?id=${queryMarker}&email=${emailMarker}`)
      .set('Cookie', authenticated.cookie)
      .expect(200);
    expect(projection.body).toEqual({ data: { id: before.userId, email: authenticated.email } });
    const problem = await request(app.getHttpServer())
      .post(`/api/v1/auth/login?token=${queryMarker}`)
      .set('Origin', ORIGIN)
      .set('Cookie', `__Host-session=${tokenMarker}`)
      .set('X-CSRF-Token', csrfMarker)
      .send({ email: emailMarker, password: passwordMarker })
      .expect(401);
    expect(problem.body.code).toBe('AUTHENTICATION_REQUIRED');
    expect(logOutput).toContain('http_request_completed');
    for (const value of [
      passwordMarker,
      emailMarker,
      tokenMarker,
      csrfMarker,
      queryMarker,
      cookieValue(authenticated.cookie),
      current,
    ]) {
      expect(logOutput).not.toContain(value);
      expect(projection.text).not.toContain(value);
      expect(problem.text).not.toContain(value);
    }
    expect(logOutput).not.toContain('__Host-session');
    expect(logOutput).not.toContain('set-cookie');
  });

  it('uses injected time for the eight-hour renewal and twenty-four-hour absolute caps', async () => {
    const clock = app.get<IdentityClock>(IDENTITY_CLOCK);
    const start = new Date('2031-01-01T00:00:00.000Z');
    const spy = jest.spyOn(clock, 'now').mockReturnValue(start);
    try {
      const authenticated = await login(app);
      const initial = await row(authenticated.cookie);
      spy.mockReturnValue(new Date(start.getTime() + 7 * HOUR));
      await request(app.getHttpServer())
        .get('/api/v1/auth/csrf')
        .set('Cookie', authenticated.cookie)
        .expect(200);
      const renewed = await row(authenticated.cookie);
      expect(renewed.idleExpiresAt.getTime()).toBe(start.getTime() + 15 * HOUR);
      spy.mockReturnValue(new Date(start.getTime() + 23 * HOUR));
      await request(app.getHttpServer())
        .get('/api/v1/auth/csrf')
        .set('Cookie', authenticated.cookie)
        .expect(200);
      const capped = await row(authenticated.cookie);
      expect(capped.idleExpiresAt.getTime()).toBe(initial.absoluteExpiresAt.getTime());
      expect(capped.lastSeenAt.getTime()).toBe(start.getTime() + 23 * HOUR);
    } finally {
      spy.mockRestore();
    }
  });

  it('rejects bad Origin before csrf, preserves the valid row on both 403 branches, then revokes logout terminally', async () => {
    const authenticated = await login(app);
    const before = await row(authenticated.cookie);
    const origin = await request(app.getHttpServer())
      .post('/api/v1/auth/logout')
      .set('Origin', 'https://untrusted.example')
      .set('Cookie', authenticated.cookie)
      .set('X-CSRF-Token', 'wrong')
      .expect(403);
    expect(origin.body.code).toBe('ACCESS_DENIED');
    expect(await row(authenticated.cookie)).toEqual(before);
    const invalid = await request(app.getHttpServer())
      .post('/api/v1/auth/logout')
      .set('Origin', ORIGIN)
      .set('Cookie', authenticated.cookie)
      .set('X-CSRF-Token', 'wrong')
      .expect(403);
    expect(invalid.body.code).toBe('CSRF_INVALID');
    expect(await row(authenticated.cookie)).toEqual(before);
    const current = await activeCsrf(app, authenticated.cookie);
    const beforeLogout = await row(authenticated.cookie);
    const logout = await request(app.getHttpServer())
      .post('/api/v1/auth/logout')
      .set('Origin', ORIGIN)
      .set('Cookie', authenticated.cookie)
      .set('X-CSRF-Token', current)
      .expect(204);
    expect(logout.text).toBe('');
    expect(rawCookie(logout)).toContain('__Host-session=;');
    const revoked = await row(authenticated.cookie);
    expect(revoked).toMatchObject({ id: before.id, state: 'revoked' });
    expect(revoked.lastSeenAt).toEqual(beforeLogout.lastSeenAt);
    for (const endpoint of ['/api/v1/auth/csrf', '/api/v1/auth/me']) {
      const terminal = await request(app.getHttpServer())
        .get(endpoint)
        .set('Cookie', authenticated.cookie)
        .expect(401);
      expect(rawCookie(terminal)).toContain('__Host-session=;');
    }
  });

  it('denies malformed and database-idle-expired supplied cookies without rotating or touching their rows', async () => {
    const malformed = await request(app.getHttpServer())
      .get('/api/v1/auth/csrf')
      .set('Cookie', '__Host-session=bad')
      .expect(401);
    expect(rawCookie(malformed)).toContain('__Host-session=;');
    const unknown = await request(app.getHttpServer())
      .get('/api/v1/auth/csrf')
      .set('Cookie', `__Host-session=${randomBytes(32).toString('base64url')}`)
      .expect(401);
    expect(rawCookie(unknown)).toContain('__Host-session=;');
    const authenticated = await login(app);
    const before = await row(authenticated.cookie);
    await observer
      .getRepository(SessionEntity)
      .update({ id: before.id }, { idleExpiresAt: new Date(Date.now() - 1) });
    const expired = await request(app.getHttpServer())
      .get('/api/v1/auth/csrf')
      .set('Cookie', authenticated.cookie)
      .expect(401);
    expect(rawCookie(expired)).toContain('__Host-session=;');
    const after = await row(authenticated.cookie);
    expect(after.csrfTokenHash).toBe(before.csrfTokenHash);
    expect(after.lastSeenAt).toEqual(before.lastSeenAt);
    const absolute = await login(app);
    const absoluteBefore = await row(absolute.cookie);
    await observer.getRepository(SessionEntity).update(
      { id: absoluteBefore.id },
      {
        absoluteExpiresAt: new Date(Date.now() - 1),
        idleExpiresAt: new Date(Date.now() - 1),
      },
    );
    const absoluteExpired = await request(app.getHttpServer())
      .get('/api/v1/auth/me')
      .set('Cookie', absolute.cookie)
      .expect(401);
    expect(rawCookie(absoluteExpired)).toContain('__Host-session=;');
    const absoluteAfter = await row(absolute.cookie);
    expect(absoluteAfter.csrfTokenHash).toBe(absoluteBefore.csrfTokenHash);
    expect(absoluteAfter.lastSeenAt).toEqual(absoluteBefore.lastSeenAt);
    const bootstrapResponse = await request(app.getHttpServer())
      .get('/api/v1/auth/csrf')
      .expect(200);
    expect(csrf(bootstrapResponse)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  async function row(sessionCookie: string): Promise<SessionView> {
    const value = await observer
      .getRepository(SessionEntity)
      .findOneByOrFail({ tokenHash: hash(cookieValue(sessionCookie)) });
    return {
      id: value.id,
      userId: value.userId,
      csrfTokenHash: value.csrfTokenHash,
      state: value.state,
      lastSeenAt: value.lastSeenAt,
      idleExpiresAt: value.idleExpiresAt,
      absoluteExpiresAt: value.absoluteExpiresAt,
      revokedAt: value.revokedAt,
    };
  }
});

async function login(
  app: INestApplication,
): Promise<{ readonly cookie: string; readonly email: string }> {
  const email = `lifecycle-${randomBytes(8).toString('hex')}@example.test`;
  const registration = await bootstrap(app);
  await request(app.getHttpServer())
    .post('/api/v1/auth/register')
    .set('Origin', ORIGIN)
    .set('Cookie', registration.cookie)
    .set('X-CSRF-Token', registration.csrfToken)
    .send({ email, password: PASSWORD })
    .expect(201);
  const preLogin = await bootstrap(app);
  const response = await request(app.getHttpServer())
    .post('/api/v1/auth/login')
    .set('Origin', ORIGIN)
    .set('Cookie', preLogin.cookie)
    .set('X-CSRF-Token', preLogin.csrfToken)
    .send({ email, password: PASSWORD })
    .expect(200);
  return { cookie: cookie(response), email };
}
async function bootstrap(app: INestApplication): Promise<Receipt> {
  const response = await request(app.getHttpServer()).get('/api/v1/auth/csrf').expect(200);
  return { cookie: cookie(response), csrfToken: csrf(response) };
}
async function activeCsrf(app: INestApplication, value: string): Promise<string> {
  return csrf(
    await request(app.getHttpServer()).get('/api/v1/auth/csrf').set('Cookie', value).expect(200),
  );
}
function hash(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
function cookieValue(value: string): string {
  return value.slice('__Host-session='.length);
}
function csrf(response: Response): string {
  const value = response.body?.data?.csrfToken;
  if (typeof value !== 'string') throw new Error('Expected CSRF token.');
  return value;
}
function cookie(response: Response): string {
  const value = rawCookie(response).split(';')[0];
  if (value === undefined || !value.startsWith('__Host-session='))
    throw new Error('Expected identity cookie.');
  return value;
}
function rawCookie(response: Response): string {
  const values = response.headers['set-cookie'];
  if (!Array.isArray(values) || typeof values[0] !== 'string')
    throw new Error('Expected Set-Cookie header.');
  return values[0];
}
function savedEnvironment(): Map<string, string | undefined> {
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
function setEnvironment(plan: IsolatedPostgresPlan): void {
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
function restoreEnvironment(values: Map<string, string | undefined>): void {
  for (const [key, value] of values) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}
function loopbackPort(): Promise<number> {
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
