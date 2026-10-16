import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';

import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import request, { Response } from 'supertest';
import { DataSource } from 'typeorm';

import { AppModule } from '../../../src/app.module';
import { IdentityAuthConfig } from '../../../src/modules/identity/application/identity-auth.config';
import { ScryptPasswordHasher } from '../../../src/modules/identity/application/password-hasher';
import { PasswordWorkLimiter } from '../../../src/modules/identity/application/password-work-limiter';
import { createThrottleKey } from '../../../src/modules/identity/application/throttle-key';
import { RegistrationThrottleEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/registration-throttle.entity';
import { LoginThrottleEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/login-throttle.entity';
import { SessionEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/session.entity';
import { UserEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/user.entity';
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
let bootstrapApp: INestApplication;
let bootstrapAdmissions = 0;
const overflowBootstrapApps: INestApplication[] = [];

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
    bootstrapApp = app;
    bootstrapAdmissions = 0;
  });

  afterEach(async () => {
    for (const overflowApp of overflowBootstrapApps.splice(0)) await overflowApp.close();
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
    const enteredDummyVerification = deferred<void>();
    const verifyDummy = ScryptPasswordHasher.prototype.verifyDummy;
    const hashSpy = jest.spyOn(ScryptPasswordHasher.prototype, 'hash');
    const dummySpy = jest
      .spyOn(ScryptPasswordHasher.prototype, 'verifyDummy')
      .mockImplementation(async function (
        this: ScryptPasswordHasher,
        password: string,
      ): Promise<void> {
        enteredDummyVerification.resolve();
        await verifyDummy.call(this, password);
      });
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
      const parallelEmail = 'parallel-after-kdf@example.test';
      const parallelResponse = await register(app, parallel, parallelEmail);
      expect(parallelResponse.status).toBe(503);
      expect(parallelResponse.body.code).toBe('throttle_busy');
      expect(parallelResponse.headers['retry-after']).toBe('1');
      expect(parallelResponse.headers['access-control-expose-headers']).toContain('Retry-After');
      expect(
        await observer.getRepository(SessionEntity).findOneByOrFail({
          tokenHash: sessionHash(parallel.cookie),
        }),
      ).toMatchObject({ state: 'pre_auth', revokedAt: null });
      const parallelKey = createThrottleKey(
        IdentityAuthConfig.from(process.env),
        'registration',
        parallelEmail,
        '127.0.0.1',
      );
      if (parallelKey === null) throw new Error('Expected loopback throttle key.');
      expect(
        await observer
          .getRepository(RegistrationThrottleEntity)
          .findOneBy({ keyHash: parallelKey }),
      ).toBeNull();
      expect(hashSpy).toHaveBeenCalledTimes(1);

      const heldPeriodLogin = await bootstrapCsrf(app);
      const heldPeriodLoginRequest = login(app, heldPeriodLogin, 'held-period@example.test');
      await enteredDummyVerification.promise;
      expect((await heldPeriodLoginRequest).status).toBe(401);
      expect(dummySpy).toHaveBeenCalledTimes(1);

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
      expect(hashSpy).toHaveBeenCalledTimes(1);
      expect(dummySpy).toHaveBeenCalledTimes(9);
    } finally {
      rejectPersistence.resolve();
      insertSpy.mockRestore();
      dummySpy.mockRestore();
      hashSpy.mockRestore();
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

  it('maps a real scoped scrypt registration callback failure safely and rolls it back', async () => {
    const marker = 'SCF-registration-callback-marker';
    await app.close();
    let scoped: ScopedScryptFailureApplication | undefined;
    try {
      scoped = await createScopedScryptFailureApplication(marker);
      app = scoped.app;
      bootstrapApp = app;
      bootstrapAdmissions = 0;
      const bootstrap = await bootstrapCsrf(app);
      const email = 'scf-registration@example.test';
      const throttleKey = requiredThrottleKey('registration', email);
      const authenticatedBefore = await observer
        .getRepository(SessionEntity)
        .countBy({ state: 'authenticated' });
      const failed = await register(app, bootstrap, email);
      expectSafeInternalError(failed, marker);
      expect(scoped.calls()).toBe(1);
      expect(
        await observer.getRepository(UserEntity).findOneBy({ normalizedEmail: email }),
      ).toBeNull();
      expect(
        await observer
          .getRepository(RegistrationThrottleEntity)
          .findOneBy({ keyHash: throttleKey }),
      ).toBeNull();
      await expectPreAuth(observer, bootstrap);
      expect(await observer.getRepository(SessionEntity).countBy({ state: 'authenticated' })).toBe(
        authenticatedBefore,
      );

      expect((await register(app, bootstrap, email)).status).toBe(201);
      expect(scoped.calls()).toBe(2);
    } finally {
      scoped?.restore();
    }
  });

  it('maps a real scoped scrypt known-user callback failure safely and releases password work', async () => {
    const email = 'scf-known-user@example.test';
    const setup = await bootstrapCsrf(app);
    expect((await register(app, setup, email)).status).toBe(201);
    await app.close();
    const marker = 'SCF-known-user-callback-marker';
    let scoped: ScopedScryptFailureApplication | undefined;
    try {
      scoped = await createScopedScryptFailureApplication(marker);
      app = scoped.app;
      bootstrapApp = app;
      bootstrapAdmissions = 0;
      const bootstrap = await bootstrapCsrf(app);
      const throttleKey = requiredThrottleKey('login', email);
      const authenticatedBefore = await observer
        .getRepository(SessionEntity)
        .countBy({ state: 'authenticated' });
      const failed = await login(app, bootstrap, email);
      expectSafeInternalError(failed, marker);
      expect(scoped.calls()).toBe(1);
      expect(
        await observer.getRepository(LoginThrottleEntity).findOneBy({ keyHash: throttleKey }),
      ).toBeNull();
      await expectPreAuth(observer, bootstrap);
      expect(await observer.getRepository(SessionEntity).countBy({ state: 'authenticated' })).toBe(
        authenticatedBefore,
      );

      expect((await login(app, bootstrap, email)).status).toBe(200);
      expect(scoped.calls()).toBe(2);
    } finally {
      scoped?.restore();
    }
  });

  it('maps a real scoped scrypt unknown-user callback failure safely and retries as credentials invalid', async () => {
    const marker = 'SCF-unknown-user-callback-marker';
    await app.close();
    let scoped: ScopedScryptFailureApplication | undefined;
    try {
      scoped = await createScopedScryptFailureApplication(marker);
      app = scoped.app;
      bootstrapApp = app;
      bootstrapAdmissions = 0;
      const bootstrap = await bootstrapCsrf(app);
      const email = 'scf-unknown-user@example.test';
      const throttleKey = requiredThrottleKey('login', email);
      const authenticatedBefore = await observer
        .getRepository(SessionEntity)
        .countBy({ state: 'authenticated' });
      const failed = await login(app, bootstrap, email);
      expectSafeInternalError(failed, marker);
      expect(scoped.calls()).toBe(1);
      expect(
        await observer.getRepository(UserEntity).findOneBy({ normalizedEmail: email }),
      ).toBeNull();
      expect(
        await observer.getRepository(LoginThrottleEntity).findOneBy({ keyHash: throttleKey }),
      ).toBeNull();
      await expectPreAuth(observer, bootstrap);
      expect(await observer.getRepository(SessionEntity).countBy({ state: 'authenticated' })).toBe(
        authenticatedBefore,
      );

      const retry = await login(app, bootstrap, email);
      expect(retry.status).toBe(401);
      expect(retry.body.code).toBe('credentials_invalid');
      expect(scoped.calls()).toBe(2);
    } finally {
      scoped?.restore();
    }
  });
});

type Bootstrap = { readonly cookie: string; readonly csrfToken: string };
type Deferred<Value> = { readonly promise: Promise<Value>; resolve(value: Value): void };
type ScopedThrottlePurpose = 'login' | 'registration';

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

async function bootstrapCsrf(_app: INestApplication): Promise<Bootstrap> {
  if (bootstrapAdmissions === 10) {
    bootstrapApp = await NestFactory.create(AppModule, { abortOnError: false, logger: false });
    configureApplication(bootstrapApp);
    await bootstrapApp.init();
    overflowBootstrapApps.push(bootstrapApp);
    bootstrapAdmissions = 0;
  }
  const response = await request(bootstrapApp.getHttpServer()).get('/api/v1/auth/csrf').expect(200);
  bootstrapAdmissions += 1;
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

type ScryptArguments = Parameters<typeof import('node:crypto').scrypt>;

interface ScopedScryptFailureApplication {
  readonly app: INestApplication;
  calls(): number;
  restore(): void;
}

async function createScopedScryptFailureApplication(
  marker: string,
): Promise<ScopedScryptFailureApplication> {
  let calls = 0;
  let IsolatedHasher: typeof ScryptPasswordHasher | undefined;
  let scopedApp: INestApplication | undefined;
  jest.resetModules();
  jest.doMock('node:crypto', () => {
    const actual = jest.requireActual<typeof import('node:crypto')>('node:crypto');
    function controlledScrypt(...arguments_: ScryptArguments): void {
      calls += 1;
      if (calls > 1) {
        actual.scrypt(...arguments_);
        return;
      }
      const callback = arguments_.at(-1);
      if (typeof callback !== 'function') throw new Error('Expected scrypt callback.');
      queueMicrotask(() => callback(new Error(marker), Buffer.alloc(64)));
    }
    return { ...actual, scrypt: controlledScrypt };
  });
  try {
    await jest.isolateModulesAsync(async () => {
      const isolated = await import('../../../src/modules/identity/application/password-hasher');
      IsolatedHasher = isolated.ScryptPasswordHasher;
    });
    if (IsolatedHasher === undefined) throw new Error('Isolated hasher was unavailable.');
    const module = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(ScryptPasswordHasher)
      .useValue(new IsolatedHasher())
      .compile();
    scopedApp = module.createNestApplication();
    configureApplication(scopedApp);
    await scopedApp.init();
    return {
      app: scopedApp,
      calls: (): number => calls,
      restore: (): void => {
        jest.dontMock('node:crypto');
        jest.resetModules();
      },
    };
  } catch (error: unknown) {
    if (scopedApp !== undefined) await scopedApp.close();
    jest.dontMock('node:crypto');
    jest.resetModules();
    throw error;
  }
}

function expectSafeInternalError(response: Response, marker: string): void {
  expect(response.status).toBe(500);
  expect(response.headers['content-type']).toContain('application/problem+json');
  expect(response.body.code).toBe('INTERNAL_ERROR');
  expect(response.body.detail).toBe('An unexpected error occurred.');
  expect(JSON.stringify(response.body)).not.toContain(marker);
}

function requiredThrottleKey(purpose: ScopedThrottlePurpose, email: string): string {
  const key = createThrottleKey(IdentityAuthConfig.from(process.env), purpose, email, '127.0.0.1');
  if (key === null) throw new Error('Expected loopback throttle key.');
  return key;
}

async function expectPreAuth(observer: DataSource, bootstrap: Bootstrap): Promise<void> {
  expect(
    await observer
      .getRepository(SessionEntity)
      .findOneByOrFail({ tokenHash: sessionHash(bootstrap.cookie) }),
  ).toMatchObject({ state: 'pre_auth', revokedAt: null });
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
