import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';

import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import request, { Response } from 'supertest';
import { DataSource } from 'typeorm';

import { AppModule } from '../../../src/app.module';
import { IdentityAuthConfig } from '../../../src/modules/identity/application/identity-auth.config';
import { ScryptPasswordHasher } from '../../../src/modules/identity/application/password-hasher';
import { PasswordWorkLimiter } from '../../../src/modules/identity/application/password-work-limiter';
import { createThrottleKey } from '../../../src/modules/identity/application/throttle-key';
import { RegistrationThrottleEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/registration-throttle.entity';
import { SessionEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/session.entity';
import { TypeOrmUserRepository } from '../../../src/modules/identity/infrastructure/persistence/repositories/typeorm-user.repository';
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

describe('Identity password-work HTTP admission', () => {
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
    observer = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
    await observer.initialize();
  });

  beforeEach(async () => {
    app = await NestFactory.create(AppModule, { abortOnError: false, logger: false });
    configureApplication(app);
    await app.init();
  });

  afterEach(async () => {
    if (app !== undefined) await app.close();
  });

  afterAll(async () => {
    if (observer?.isInitialized) await observer.destroy();
    if (cleanup !== undefined) await cleanup();
    for (const [key, value] of previousEnvironment) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  it('preserves stale-CSRF precedence and exposes shared source admission outcomes', async () => {
    const first = await bootstrapCsrf(app);
    const held = deferred<void>();
    const enteredKdf = deferred<void>();
    const dummySpy = jest
      .spyOn(ScryptPasswordHasher.prototype, 'verifyDummy')
      .mockImplementation(async () => {
        enteredKdf.resolve();
        await held.promise;
      });
    try {
      const firstRequest = login(app, first, 'held@example.test').then((response) => response);
      await enteredKdf.promise;

      const stale = await bootstrapCsrf(app);
      await request(app.getHttpServer())
        .get('/api/v1/auth/csrf')
        .set('Cookie', stale.cookie)
        .expect(200);
      const staleResponse = await login(app, stale, 'stale@example.test');
      expect(staleResponse.status).toBe(403);
      expect(staleResponse.body.code).toBe('CSRF_INVALID');

      const busy = await bootstrapCsrf(app);
      const busyResponse = await register(app, busy, 'busy@example.test');
      expect(busyResponse.status).toBe(503);
      expect(busyResponse.body.code).toBe('password_work_busy');
      expect(busyResponse.headers['retry-after']).toBe('1');
      expect(busyResponse.headers['access-control-expose-headers']).toContain('Retry-After');
      expect(busyResponse.headers['access-control-allow-credentials']).toBe('true');
      expect(
        await observer.getRepository(SessionEntity).findOneByOrFail({
          tokenHash: sessionHash(busy.cookie),
        }),
      ).toMatchObject({ state: 'pre_auth', revokedAt: null });

      held.resolve();
      expect((await firstRequest).status).toBe(401);
      dummySpy.mockRestore();

      for (let attempt = 0; attempt < 8; attempt += 1) {
        const bootstrap = await bootstrapCsrf(app);
        expect((await login(app, bootstrap, `login-${attempt}@example.test`)).status).toBe(401);
      }
      const tenth = await bootstrapCsrf(app);
      expect((await register(app, tenth, 'tenth@example.test')).status).toBe(201);

      const limited = await bootstrapCsrf(app);
      const limitedResponse = await login(app, limited, 'limited@example.test');
      expect(limitedResponse.status).toBe(429);
      expect(limitedResponse.body.code).toBe('password_work_rate_limited');
      expect(Number(limitedResponse.headers['retry-after'])).toBeGreaterThanOrEqual(1);
      expect(Number(limitedResponse.headers['retry-after'])).toBeLessThanOrEqual(60);
      expect(limitedResponse.headers['access-control-expose-headers']).toContain('Retry-After');
    } finally {
      held.resolve();
      dummySpy.mockRestore();
    }
  });

  it('keeps a started source debit after post-KDF persistence failure and releases capacity', async () => {
    const failing = await bootstrapCsrf(app);
    const enteredPersistence = deferred<void>();
    const rejectPersistence = deferred<void>();
    const insertSpy = jest
      .spyOn(TypeOrmUserRepository.prototype, 'insertIfAbsent')
      .mockImplementationOnce(async (): Promise<boolean> => {
        enteredPersistence.resolve();
        await rejectPersistence.promise;
        throw new Error('synthetic persistence failure');
      });
    try {
      const failedRequest = register(app, failing, 'rollback@example.test');
      await enteredPersistence.promise;

      const parallel = await bootstrapCsrf(app);
      expect((await register(app, parallel, 'parallel-after-kdf@example.test')).status).toBe(201);

      rejectPersistence.resolve();
      expect((await failedRequest).status).toBe(500);
      const failedKey = createThrottleKey(
        IdentityAuthConfig.from(process.env),
        'registration',
        'rollback@example.test',
        '127.0.0.1',
      );
      if (failedKey === null) throw new Error('Expected loopback throttle key.');
      expect(
        await observer.getRepository(RegistrationThrottleEntity).findOneBy({ keyHash: failedKey }),
      ).toBeNull();
      expect(
        await observer.getRepository(SessionEntity).findOneByOrFail({
          tokenHash: sessionHash(failing.cookie),
        }),
      ).toMatchObject({ state: 'pre_auth', revokedAt: null });

      for (let attempt = 0; attempt < 8; attempt += 1) {
        const retry = await bootstrapCsrf(app);
        expect((await login(app, retry, `after-error-${attempt}@example.test`)).status).toBe(401);
      }
      const limited = await bootstrapCsrf(app);
      const response = await login(app, limited, 'after-error-limited@example.test');
      expect(response.status).toBe(429);
      expect(response.body.code).toBe('password_work_rate_limited');
    } finally {
      rejectPersistence.resolve();
      insertSpy.mockRestore();
    }
  });

  it('keeps a started source debit after password failure while rolling back registration state', async () => {
    const bootstrap = await bootstrapCsrf(app);
    const hashSpy = jest
      .spyOn(ScryptPasswordHasher.prototype, 'hash')
      .mockRejectedValueOnce(new Error('synthetic hash failure'));
    try {
      expect((await register(app, bootstrap, 'hash-failure@example.test')).status).toBe(500);
      const failedKey = createThrottleKey(
        IdentityAuthConfig.from(process.env),
        'registration',
        'hash-failure@example.test',
        '127.0.0.1',
      );
      if (failedKey === null) throw new Error('Expected loopback throttle key.');
      expect(
        await observer.getRepository(RegistrationThrottleEntity).findOneBy({ keyHash: failedKey }),
      ).toBeNull();
      expect(
        await observer.getRepository(SessionEntity).findOneByOrFail({
          tokenHash: sessionHash(bootstrap.cookie),
        }),
      ).toMatchObject({ state: 'pre_auth', revokedAt: null });

      hashSpy.mockRestore();
      expect((await register(app, bootstrap, 'hash-failure@example.test')).status).toBe(201);

      for (let attempt = 0; attempt < 8; attempt += 1) {
        const retry = await bootstrapCsrf(app);
        expect((await login(app, retry, `after-hash-error-${attempt}@example.test`)).status).toBe(
          401,
        );
      }
      const limited = await bootstrapCsrf(app);
      const response = await login(app, limited, 'after-hash-error-limited@example.test');
      expect(response.status).toBe(429);
      expect(response.body.code).toBe('password_work_rate_limited');
    } finally {
      hashSpy.mockRestore();
    }
  });

  it('maps a full local source map to 503 without KDF or pre-auth consumption', async () => {
    const bootstrap = await bootstrapCsrf(app);
    const admissionSpy = jest
      .spyOn(PasswordWorkLimiter.prototype, 'tryStart')
      .mockReturnValue({ kind: 'unavailable', retryAfterSeconds: 60 });
    const hashSpy = jest.spyOn(ScryptPasswordHasher.prototype, 'hash');
    try {
      const response = await register(app, bootstrap, 'full-map@example.test');
      expect(response.status).toBe(503);
      expect(response.body.code).toBe('password_work_unavailable');
      expect(response.headers['retry-after']).toBe('60');
      expect(hashSpy).not.toHaveBeenCalled();
      expect(
        await observer.getRepository(SessionEntity).findOneByOrFail({
          tokenHash: sessionHash(bootstrap.cookie),
        }),
      ).toMatchObject({ state: 'pre_auth', revokedAt: null });
    } finally {
      hashSpy.mockRestore();
      admissionSpy.mockRestore();
    }
  });
});

type Bootstrap = { readonly cookie: string; readonly csrfToken: string };
type Deferred<Value> = { readonly promise: Promise<Value>; resolve(value: Value): void };

function deferred<Value>(): Deferred<Value> {
  let resolvePromise: ((value: Value) => void) | undefined;
  const promise = new Promise<Value>((resolve) => {
    resolvePromise = resolve;
  });
  return {
    promise,
    resolve: (value: Value): void => {
      if (resolvePromise === undefined) throw new Error('Deferred promise is unavailable.');
      resolvePromise(value);
    },
  };
}

async function bootstrapCsrf(app: INestApplication): Promise<Bootstrap> {
  const response = await request(app.getHttpServer()).get('/api/v1/auth/csrf').expect(200);
  const csrfToken = response.body?.data?.csrfToken;
  if (typeof csrfToken !== 'string') throw new Error('Missing CSRF token.');
  const cookie = response.headers['set-cookie'];
  if (!Array.isArray(cookie) || typeof cookie[0] !== 'string')
    throw new Error('Missing session cookie.');
  return { cookie: cookie[0].split(';')[0] ?? '', csrfToken };
}

function login(app: INestApplication, bootstrap: Bootstrap, email: string): Promise<Response> {
  return request(app.getHttpServer())
    .post('/api/v1/auth/login')
    .set('Origin', ORIGIN)
    .set('Cookie', bootstrap.cookie)
    .set('X-CSRF-Token', bootstrap.csrfToken)
    .send({ email, password: PASSWORD })
    .then((response) => response);
}

function register(app: INestApplication, bootstrap: Bootstrap, email: string): Promise<Response> {
  return request(app.getHttpServer())
    .post('/api/v1/auth/register')
    .set('Origin', ORIGIN)
    .set('Cookie', bootstrap.cookie)
    .set('X-CSRF-Token', bootstrap.csrfToken)
    .send({ email, password: PASSWORD })
    .then((response) => response);
}

function sessionHash(cookie: string): string {
  const value = cookie.slice('__Host-session='.length);
  if (value.length === 0) throw new Error('Missing session value.');
  return createHash('sha256').update(value, 'utf8').digest('hex');
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
