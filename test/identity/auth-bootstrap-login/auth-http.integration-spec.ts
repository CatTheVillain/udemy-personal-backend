import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';

import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import request, { Response } from 'supertest';
import { DataSource } from 'typeorm';

import { AppModule } from '../../../src/app.module';
import { IdentityAuthConfig } from '../../../src/modules/identity/application/identity-auth.config';
import { ScryptPasswordHasher } from '../../../src/modules/identity/application/password-hasher';
import { createThrottleKey } from '../../../src/modules/identity/application/throttle-key';
import { LoginThrottleEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/login-throttle.entity';
import { RegistrationThrottleEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/registration-throttle.entity';
import { SessionEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/session.entity';
import { UserEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/user.entity';
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
const PASSWORD = 'literal valid password';

describe('Identity HTTP registration and login', () => {
  let app: INestApplication;
  let observer: DataSource;
  let plan: IsolatedPostgresPlan;
  let cleanup: (() => Promise<void>) | undefined;
  let previousEnvironment: Map<string, string | undefined>;

  beforeAll(async () => {
    previousEnvironment = new Map(
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
    for (const [key, value] of previousEnvironment) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  it('creates an ordinary account without authentication and consumes only its pre-auth session', async () => {
    const bootstrap = await bootstrapCsrf(app);
    const registration = await request(app.getHttpServer())
      .post('/api/v1/auth/register')
      .set('Origin', ORIGIN)
      .set('Cookie', bootstrap.cookie)
      .set('X-CSRF-Token', bootstrap.csrfToken)
      .send({ email: ' Student@Example.Test ', password: PASSWORD })
      .expect(201);

    expect(registration.body).toEqual({ data: { registered: true } });
    expect(readRawSetCookie(registration)).toContain('__Host-session=;');
    const users = await observer.getRepository(UserEntity).find();
    expect(users).toHaveLength(1);
    expect(users[0]?.normalizedEmail).toBe('student@example.test');
    const sessions = await observer.getRepository(SessionEntity).find();
    expect(sessions).toHaveLength(1);
    expect(sessions[0]).toMatchObject({ userId: null, state: 'revoked' });
  });

  it('clears malformed or ambiguous own cookies without silently creating a pre-auth session', async () => {
    const before = await observer.getRepository(SessionEntity).count();
    for (const cookie of ['__Host-session', '__Host-session=first; __Host-session=second']) {
      const response = await request(app.getHttpServer())
        .get('/api/v1/auth/csrf')
        .set('Cookie', cookie)
        .expect(401);
      expect(response.body.code).toBe('AUTHENTICATION_REQUIRED');
      expect(readRawSetCookie(response)).toContain('__Host-session=;');
    }
    expect(await observer.getRepository(SessionEntity).count()).toBe(before);

    const ordinaryCookie = await request(app.getHttpServer())
      .get('/api/v1/auth/csrf')
      .set('Cookie', 'theme=dark')
      .expect(200);
    expect(ordinaryCookie.body.data.csrfToken).toEqual(expect.any(String));
  });

  it('returns exact public conflict and rate-limit codes', async () => {
    const first = await bootstrapCsrf(app);
    await request(app.getHttpServer())
      .post('/api/v1/auth/register')
      .set('Origin', ORIGIN)
      .set('Cookie', first.cookie)
      .set('X-CSRF-Token', first.csrfToken)
      .send({ email: 'duplicate@example.test', password: PASSWORD })
      .expect(201);
    const duplicate = await bootstrapCsrf(app);
    const duplicateResponse = await request(app.getHttpServer())
      .post('/api/v1/auth/register')
      .set('Origin', ORIGIN)
      .set('Cookie', duplicate.cookie)
      .set('X-CSRF-Token', duplicate.csrfToken)
      .send({ email: 'duplicate@example.test', password: PASSWORD })
      .expect(409);
    expect(duplicateResponse.body.code).toBe('RESOURCE_CONFLICT');

    for (let attempt = 0; attempt < 3; attempt += 1) {
      const bootstrap = await bootstrapCsrf(app);
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('Origin', ORIGIN)
        .set('Cookie', bootstrap.cookie)
        .set('X-CSRF-Token', bootstrap.csrfToken)
        .send({ email: 'limited@example.test', password: PASSWORD })
        .expect(attempt === 0 ? 201 : 409);
    }
    const limited = await bootstrapCsrf(app);
    const limitedResponse = await request(app.getHttpServer())
      .post('/api/v1/auth/register')
      .set('Origin', ORIGIN)
      .set('Cookie', limited.cookie)
      .set('X-CSRF-Token', limited.csrfToken)
      .send({ email: 'limited@example.test', password: PASSWORD })
      .expect(429);
    expect(limitedResponse.body.code).toBe('registration_rate_limited');
  });

  it('serializes same canonical-email registration to one account, one conflict, and two durable admissions', async () => {
    const first = await bootstrapCsrf(app);
    const second = await bootstrapCsrf(app);
    const responses = await Promise.all([
      request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('Origin', ORIGIN)
        .set('Cookie', first.cookie)
        .set('X-CSRF-Token', first.csrfToken)
        .send({ email: ' Parallel@Example.Test ', password: PASSWORD })
        .then((response) => response),
      request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('Origin', ORIGIN)
        .set('Cookie', second.cookie)
        .set('X-CSRF-Token', second.csrfToken)
        .send({ email: 'parallel@example.test', password: PASSWORD })
        .then((response) => response),
    ]);
    expect(responses.map((response) => response.status).sort()).toEqual([201, 409]);
    expect(
      await observer
        .getRepository(UserEntity)
        .countBy({ normalizedEmail: 'parallel@example.test' }),
    ).toBe(1);
    const key = createThrottleKey(
      IdentityAuthConfig.from(process.env),
      'registration',
      'parallel@example.test',
      '127.0.0.1',
    );
    if (key === null) throw new Error('Expected loopback registration throttle key.');
    expect(
      await observer.getRepository(RegistrationThrottleEntity).findOneByOrFail({ keyHash: key }),
    ).toMatchObject({ attemptCount: 2 });
    for (const receipt of [
      { bootstrap: first, response: responses[0] },
      { bootstrap: second, response: responses[1] },
    ]) {
      if (receipt.response === undefined)
        throw new Error('Missing concurrent registration response.');
      const session = await observer.getRepository(SessionEntity).findOneByOrFail({
        tokenHash: sha256(cookieValue(receipt.bootstrap.cookie)),
      });
      if (receipt.response.status === 201) {
        expect(session).toMatchObject({ state: 'revoked', revokedAt: expect.any(Date) });
      } else {
        expect(session).toMatchObject({ state: 'pre_auth', revokedAt: null });
      }
    }
  });

  it('uses canonical email and socket address for durable registration keys despite forwarded headers', async () => {
    const requests = await Promise.all(
      [
        { email: ' Socket@Example.Test ', forwarded: '203.0.113.1' },
        { email: 'socket@example.test', forwarded: '198.51.100.2' },
        { email: 'socket@example.test ', forwarded: '192.0.2.3' },
      ].map(async ({ email, forwarded }) => {
        const bootstrap = await bootstrapCsrf(app);
        return request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .set('Origin', ORIGIN)
          .set('Cookie', bootstrap.cookie)
          .set('X-CSRF-Token', bootstrap.csrfToken)
          .set('Forwarded', `for=${forwarded}`)
          .set('X-Forwarded-For', forwarded)
          .send({ email, password: PASSWORD })
          .then((response) => response);
      }),
    );
    expect(requests.map((response) => response.status).sort()).toEqual([201, 409, 409]);
    const key = createThrottleKey(
      IdentityAuthConfig.from(process.env),
      'registration',
      'socket@example.test',
      '127.0.0.1',
    );
    if (key === null) throw new Error('Expected loopback registration throttle key.');
    expect(
      await observer.getRepository(RegistrationThrottleEntity).findOneByOrFail({ keyHash: key }),
    ).toMatchObject({ attemptCount: 3 });
  });

  it('persists the literal HTTP password without Unicode normalization', async () => {
    const password = 'literal e\u0301 password ١٢٣';
    const bootstrap = await bootstrapCsrf(app);
    await request(app.getHttpServer())
      .post('/api/v1/auth/register')
      .set('Origin', ORIGIN)
      .set('Cookie', bootstrap.cookie)
      .set('X-CSRF-Token', bootstrap.csrfToken)
      .send({ email: 'literal-password@example.test', password })
      .expect(201);
    const user = await observer.getRepository(UserEntity).findOneByOrFail({
      normalizedEmail: 'literal-password@example.test',
    });
    const hasher = new ScryptPasswordHasher();
    await expect(hasher.verify(password, user.passwordHash)).resolves.toBe(true);
    await expect(hasher.verify('literal é password ١٢٣', user.passwordHash)).resolves.toBe(false);
  });

  it('uses generic credentials errors, admits five failures, and allows valid login to reset its own key', async () => {
    const registration = await bootstrapCsrf(app);
    await request(app.getHttpServer())
      .post('/api/v1/auth/register')
      .set('Origin', ORIGIN)
      .set('Cookie', registration.cookie)
      .set('X-CSRF-Token', registration.csrfToken)
      .send({ email: 'login@example.test', password: PASSWORD })
      .expect(201);

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const bootstrap = await bootstrapCsrf(app);
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/login')
        .set('Origin', ORIGIN)
        .set('Cookie', bootstrap.cookie)
        .set('X-CSRF-Token', bootstrap.csrfToken)
        .send({ email: 'login@example.test', password: 'wrong literal password' })
        .expect(401);
      expect(response.body.code).toBe('credentials_invalid');
    }
    const atLimit = await bootstrapCsrf(app);
    const atLimitResponse = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .set('Origin', ORIGIN)
      .set('Cookie', atLimit.cookie)
      .set('X-CSRF-Token', atLimit.csrfToken)
      .send({ email: 'login@example.test', password: 'wrong literal password' })
      .expect(429);
    expect(atLimitResponse.body.code).toBe('login_rate_limited');

    const valid = await bootstrapCsrf(app);
    const validResponse = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .set('Origin', ORIGIN)
      .set('Cookie', valid.cookie)
      .set('X-CSRF-Token', valid.csrfToken)
      .send({ email: 'login@example.test', password: PASSWORD })
      .expect(200);
    expect(validResponse.body).toEqual({ data: { authenticated: true } });
    const throttles = await observer.getRepository(LoginThrottleEntity).find();
    expect(throttles.filter((throttle) => throttle.failureCount !== 0)).toHaveLength(0);

    const firstFailureAfterReset = new Date();
    const afterReset = await bootstrapCsrf(app);
    await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .set('Origin', ORIGIN)
      .set('Cookie', afterReset.cookie)
      .set('X-CSRF-Token', afterReset.csrfToken)
      .send({ email: 'login@example.test', password: 'wrong literal password' })
      .expect(401);
    const restartedWindow = await observer
      .getRepository(LoginThrottleEntity)
      .findOneByOrFail({ failureCount: 1 });
    expect(restartedWindow.windowStartedAt.getTime()).toBeGreaterThanOrEqual(
      firstFailureAfterReset.getTime(),
    );
    expect(restartedWindow.expiresAt.getTime() - restartedWindow.windowStartedAt.getTime()).toBe(
      15 * 60 * 1000,
    );
  });
});

type BootstrapReceipt = { readonly cookie: string; readonly csrfToken: string };

async function bootstrapCsrf(app: INestApplication): Promise<BootstrapReceipt> {
  const response = await request(app.getHttpServer()).get('/api/v1/auth/csrf').expect(200);
  const token = response.body?.data?.csrfToken;
  if (typeof token !== 'string') throw new Error('CSRF bootstrap did not return a token.');
  return { cookie: readSetCookie(response), csrfToken: token };
}

function readSetCookie(response: Response): string {
  return readRawSetCookie(response).split(';')[0] ?? '';
}

function cookieValue(cookie: string): string {
  const value = cookie.slice('__Host-session='.length);
  if (value.length === 0) throw new Error('Missing session cookie value.');
  return value;
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function readRawSetCookie(response: Response): string {
  const value = response.headers['set-cookie'];
  if (!Array.isArray(value) || typeof value[0] !== 'string')
    throw new Error('Expected identity cookie.');
  return value[0];
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
