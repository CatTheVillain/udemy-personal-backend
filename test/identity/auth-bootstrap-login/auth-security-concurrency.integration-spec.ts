import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';

import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import request, { Response } from 'supertest';
import { DataSource, QueryRunner } from 'typeorm';

import { AppModule } from '../../../src/app.module';
import { IdentityAuthConfig } from '../../../src/modules/identity/application/identity-auth.config';
import {
  IDENTITY_CLOCK,
  IdentityClock,
} from '../../../src/modules/identity/application/identity-clock';
import { ScryptPasswordHasher } from '../../../src/modules/identity/application/password-hasher';
import { createThrottleKey } from '../../../src/modules/identity/application/throttle-key';
import { LoginThrottleEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/login-throttle.entity';
import { RegistrationThrottleEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/registration-throttle.entity';
import { SessionEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/session.entity';
import { UserEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/user.entity';
import { TypeOrmLoginThrottleRepository } from '../../../src/modules/identity/infrastructure/persistence/repositories/typeorm-login-throttle.repository';
import { TypeOrmRegistrationThrottleRepository } from '../../../src/modules/identity/infrastructure/persistence/repositories/typeorm-registration-throttle.repository';
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

describe('Identity stale-CSRF transaction recheck', () => {
  let app: INestApplication;
  let observer: DataSource;
  let plan: IsolatedPostgresPlan;
  let cleanup: (() => Promise<void>) | undefined;
  let previous: Map<string, string | undefined>;

  beforeAll(async () => {
    previous = new Map(
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
      createIsolatedPostgresEnvironment(randomBytes(32).toString('hex'), await loopbackPort()),
    );
    const run = await startIsolatedPostgres(plan);
    cleanup = (): Promise<void> => run.cleanup();
    await run.migrate({ createDataSource: createIdentityDataSource });
    configureEnvironment(plan);
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
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  it.each(['register', 'login'] as const)(
    'returns CSRF_INVALID without user side effects when GET rotates between %s guard and lock',
    async (endpoint) => {
      if (endpoint === 'login') await registerAccount(app, 'race@example.test');
      const bootstrap = await bootstrapCsrf(app);
      const session = await observer.getRepository(SessionEntity).findOneByOrFail({
        tokenHash: sha256(bootstrap.cookieValue),
      });
      const runner = observer.createQueryRunner();
      const userRead = jest.spyOn(TypeOrmUserRepository.prototype, 'findByNormalizedEmail');
      const userInsert = jest.spyOn(TypeOrmUserRepository.prototype, 'insertIfAbsent');
      const legacyUserInsert = jest.spyOn(TypeOrmUserRepository.prototype, 'insert');
      const hash = jest.spyOn(ScryptPasswordHasher.prototype, 'hash');
      const verify = jest.spyOn(ScryptPasswordHasher.prototype, 'verify');
      const dummy = jest.spyOn(ScryptPasswordHasher.prototype, 'verifyDummy');
      const registration = jest.spyOn(
        TypeOrmRegistrationThrottleRepository.prototype,
        'consumeAttempt',
      );
      const login = jest.spyOn(TypeOrmLoginThrottleRepository.prototype, 'acquireForLogin');
      const loginFailure = jest.spyOn(TypeOrmLoginThrottleRepository.prototype, 'consumeFailure');
      const loginReset = jest.spyOn(TypeOrmLoginThrottleRepository.prototype, 'resetFailures');
      await runner.connect();
      await runner.startTransaction();
      try {
        await runner.query(
          `SELECT id FROM "${plan.schemaName}".identity_sessions WHERE id = $1 FOR UPDATE`,
          [session.id],
        );
        const rotation = request(app.getHttpServer())
          .get('/api/v1/auth/csrf')
          .set('Cookie', bootstrap.cookie)
          .expect(200)
          .then((response) => response);
        await waitForWaitingTransactions(observer, plan, 'identity_sessions', 1);
        const mutation = request(app.getHttpServer())
          .post(`/api/v1/auth/${endpoint}`)
          .set('Origin', ORIGIN)
          .set('Cookie', bootstrap.cookie)
          .set('X-CSRF-Token', bootstrap.csrfToken)
          .send({ email: 'race@example.test', password: PASSWORD })
          .then((response) => response);
        const waiters = await waitForWaitingTransactions(observer, plan, 'identity_sessions', 2);
        expect(new Set(waiters.map((waiter) => waiter.pid)).size).toBe(2);
        await runner.commitTransaction();
        await rotation;
        const response = await mutation;
        expect(response.status).toBe(403);
        expect(response.body.code).toBe('CSRF_INVALID');
        expect(readRawSetCookie(response)).toBeUndefined();
        const stored = await observer
          .getRepository(SessionEntity)
          .findOneByOrFail({ id: session.id });
        expect(stored.state).toBe('pre_auth');
        expect(stored.revokedAt).toBeNull();
        expect(userRead).not.toHaveBeenCalled();
        expect(userInsert).not.toHaveBeenCalled();
        expect(legacyUserInsert).not.toHaveBeenCalled();
        expect(hash).not.toHaveBeenCalled();
        expect(verify).not.toHaveBeenCalled();
        expect(dummy).not.toHaveBeenCalled();
        expect(registration).not.toHaveBeenCalled();
        expect(login).not.toHaveBeenCalled();
        expect(loginFailure).not.toHaveBeenCalled();
        expect(loginReset).not.toHaveBeenCalled();
        if (endpoint === 'register') {
          expect(
            await observer
              .getRepository(UserEntity)
              .countBy({ normalizedEmail: 'race@example.test' }),
          ).toBe(0);
        }
      } finally {
        userRead.mockRestore();
        userInsert.mockRestore();
        legacyUserInsert.mockRestore();
        hash.mockRestore();
        verify.mockRestore();
        dummy.mockRestore();
        registration.mockRestore();
        login.mockRestore();
        loginFailure.mockRestore();
        loginReset.mockRestore();
        if (runner.isTransactionActive) await runner.rollbackTransaction();
        await runner.release();
      }
    },
  );

  it('renews elapsed throttle windows and resets only the successful login key', async () => {
    const clock = app.get<IdentityClock>(IDENTITY_CLOCK);
    let now = new Date('2026-10-12T12:00:00.000Z');
    const clockSpy = jest.spyOn(clock, 'now').mockImplementation(() => now);
    const firstEmail = `window-a-${randomBytes(5).toString('hex')}@example.test`;
    const secondEmail = `window-b-${randomBytes(5).toString('hex')}@example.test`;
    try {
      await registerAccount(app, firstEmail);
      await registerAccount(app, secondEmail);
      for (const email of [firstEmail, secondEmail]) {
        const bootstrap = await bootstrapCsrf(app);
        await loginRequest(app, bootstrap, email, 'wrong literal password').then((response) =>
          expect(response.status).toBe(401),
        );
      }
      const valid = await bootstrapCsrf(app);
      await loginRequest(app, valid, firstEmail, PASSWORD).then((response) =>
        expect(response.status).toBe(200),
      );
      const config = IdentityAuthConfig.from(process.env);
      const firstLoginKey = throttleKey(config, 'login', firstEmail);
      const secondLoginKey = throttleKey(config, 'login', secondEmail);
      const firstRegistrationKey = throttleKey(config, 'registration', firstEmail);
      expect(
        await observer
          .getRepository(LoginThrottleEntity)
          .findOneByOrFail({ keyHash: firstLoginKey }),
      ).toMatchObject({ failureCount: 0 });
      expect(
        await observer
          .getRepository(LoginThrottleEntity)
          .findOneByOrFail({ keyHash: secondLoginKey }),
      ).toMatchObject({ failureCount: 1 });
      expect(
        await observer
          .getRepository(RegistrationThrottleEntity)
          .findOneByOrFail({ keyHash: firstRegistrationKey }),
      ).toMatchObject({ attemptCount: 1 });

      now = new Date(now.getTime() + 15 * 60 * 1000 + 1);
      const duplicate = await bootstrapCsrf(app);
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('Origin', ORIGIN)
        .set('Cookie', duplicate.cookie)
        .set('X-CSRF-Token', duplicate.csrfToken)
        .send({ email: firstEmail, password: PASSWORD })
        .expect(409);
      const newRegistrationWindow = await observer
        .getRepository(RegistrationThrottleEntity)
        .findOneByOrFail({ keyHash: firstRegistrationKey });
      expect(newRegistrationWindow).toMatchObject({ attemptCount: 1, windowStartedAt: now });
      expect(newRegistrationWindow.expiresAt.getTime() - now.getTime()).toBe(15 * 60 * 1000);

      const expiredLogin = await bootstrapCsrf(app);
      await loginRequest(app, expiredLogin, firstEmail, 'wrong literal password').then((response) =>
        expect(response.status).toBe(401),
      );
      const newLoginWindow = await observer
        .getRepository(LoginThrottleEntity)
        .findOneByOrFail({ keyHash: firstLoginKey });
      expect(newLoginWindow).toMatchObject({ failureCount: 1, windowStartedAt: now });
      expect(newLoginWindow.expiresAt.getTime() - now.getTime()).toBe(15 * 60 * 1000);
    } finally {
      clockSpy.mockRestore();
    }
  });

  it.each(['register', 'login'] as const)(
    'clears an expired pre-auth session after %s waits for its exact row lock without side effects',
    async (endpoint) => {
      const bootstrap = await bootstrapCsrf(app);
      const session = await observer
        .getRepository(SessionEntity)
        .findOneByOrFail({ tokenHash: sha256(bootstrap.cookieValue) });
      const now = new Date();
      let currentNow = now;
      const clock = app.get<IdentityClock>(IDENTITY_CLOCK);
      const clockSpy = jest.spyOn(clock, 'now').mockImplementation(() => currentNow);
      const userRead = jest.spyOn(TypeOrmUserRepository.prototype, 'findByNormalizedEmail');
      const userInsert = jest.spyOn(TypeOrmUserRepository.prototype, 'insertIfAbsent');
      const legacyUserInsert = jest.spyOn(TypeOrmUserRepository.prototype, 'insert');
      const hash = jest.spyOn(ScryptPasswordHasher.prototype, 'hash');
      const verify = jest.spyOn(ScryptPasswordHasher.prototype, 'verify');
      const registration = jest.spyOn(
        TypeOrmRegistrationThrottleRepository.prototype,
        'consumeAttempt',
      );
      const login = jest.spyOn(TypeOrmLoginThrottleRepository.prototype, 'acquireForLogin');
      const loginFailure = jest.spyOn(TypeOrmLoginThrottleRepository.prototype, 'consumeFailure');
      const loginReset = jest.spyOn(TypeOrmLoginThrottleRepository.prototype, 'resetFailures');
      const runner = observer.createQueryRunner();
      const sessionsBefore = await observer.getRepository(SessionEntity).count();
      await runner.connect();
      await runner.startTransaction();
      try {
        await runner.query(
          `SELECT id FROM "${plan.schemaName}".identity_sessions WHERE id = $1 FOR UPDATE`,
          [session.id],
        );
        const pending = request(app.getHttpServer())
          .post(`/api/v1/auth/${endpoint}`)
          .set('Origin', ORIGIN)
          .set('Cookie', bootstrap.cookie)
          .set('X-CSRF-Token', bootstrap.csrfToken)
          .send({ email: 'expiry@example.test', password: PASSWORD })
          .then((response) => response);
        const waiters = await waitForWaitingTransactions(observer, plan, 'identity_sessions', 1);
        expect(new Set(waiters.map((waiter) => waiter.pid)).size).toBe(1);
        expect(waiters.every((waiter) => waiter.query.includes('identity_sessions'))).toBe(true);
        currentNow = new Date(now.getTime() + 11 * 60 * 1000);
        await runner.commitTransaction();
        const response = await pending;
        expect(response.status).toBe(401);
        expect(response.body.code).toBe('AUTHENTICATION_REQUIRED');
        expect(readRawSetCookie(response)).toContain('__Host-session=;');
        expect(await observer.getRepository(SessionEntity).count()).toBe(sessionsBefore);
        expect(
          await observer.getRepository(SessionEntity).findOneByOrFail({ id: session.id }),
        ).toMatchObject({
          state: 'pre_auth',
          revokedAt: null,
        });
        expect(userRead).not.toHaveBeenCalled();
        expect(userInsert).not.toHaveBeenCalled();
        expect(legacyUserInsert).not.toHaveBeenCalled();
        expect(hash).not.toHaveBeenCalled();
        expect(verify).not.toHaveBeenCalled();
        expect(registration).not.toHaveBeenCalled();
        expect(login).not.toHaveBeenCalled();
        expect(loginFailure).not.toHaveBeenCalled();
        expect(loginReset).not.toHaveBeenCalled();
      } finally {
        clockSpy.mockRestore();
        userRead.mockRestore();
        userInsert.mockRestore();
        legacyUserInsert.mockRestore();
        hash.mockRestore();
        verify.mockRestore();
        registration.mockRestore();
        login.mockRestore();
        loginFailure.mockRestore();
        loginReset.mockRestore();
        if (runner.isTransactionActive) await runner.rollbackTransaction();
        await runner.release();
      }
    },
  );

  it('serializes six simultaneous invalid logins to five credentials errors and one limit', async () => {
    await registerAccount(app, 'parallel@example.test');
    const attempts = await Promise.all(Array.from({ length: 6 }, () => bootstrapCsrf(app)));
    const responses = await Promise.all(
      attempts.map((attempt) =>
        request(app.getHttpServer())
          .post('/api/v1/auth/login')
          .set('Origin', ORIGIN)
          .set('Cookie', attempt.cookie)
          .set('X-CSRF-Token', attempt.csrfToken)
          .send({ email: 'parallel@example.test', password: 'wrong literal password' })
          .then((response) => response),
      ),
    );
    expect(responses.filter((response) => response.status === 401)).toHaveLength(5);
    expect(responses.filter((response) => response.status === 429)).toHaveLength(1);
    expect(
      responses
        .filter((response) => response.status === 401)
        .every((response) => response.body.code === 'credentials_invalid'),
    ).toBe(true);
    expect(responses.find((response) => response.status === 429)?.body.code).toBe(
      'login_rate_limited',
    );
    const key = throttleKey(IdentityAuthConfig.from(process.env), 'login', 'parallel@example.test');
    const throttle = await observer
      .getRepository(LoginThrottleEntity)
      .findOneByOrFail({ keyHash: key });
    expect(throttle.failureCount).toBe(5);
  });

  it('proves the exact SQL lock observer exposes a test-only unsafe double update', async () => {
    const bootstrap = await bootstrapCsrf(app);
    const session = await observer.getRepository(SessionEntity).findOneByOrFail({
      tokenHash: sha256(bootstrap.cookieValue),
    });
    const holder = observer.createQueryRunner();
    const first = observer.createQueryRunner();
    const second = observer.createQueryRunner();
    await Promise.all([holder.connect(), first.connect(), second.connect()]);
    await Promise.all([
      holder.startTransaction(),
      first.startTransaction(),
      second.startTransaction(),
    ]);
    try {
      await holder.query(
        `SELECT id FROM "${plan.schemaName}".identity_sessions WHERE id = $1 FOR UPDATE`,
        [session.id],
      );
      const firstUnsafe = unsafeUnconditionalRevoke(first, plan.schemaName, session.id);
      await waitForWaitingTransactions(observer, plan, 'identity_sessions', 1);
      const secondUnsafe = unsafeUnconditionalRevoke(second, plan.schemaName, session.id);
      const waiters = await waitForWaitingTransactions(observer, plan, 'identity_sessions', 2);
      expect(new Set(waiters.map((waiter) => waiter.pid)).size).toBe(2);
      expect(waiters.every((waiter) => waiter.query.includes('identity_sessions'))).toBe(true);
      await holder.commitTransaction();
      await expect(firstUnsafe).resolves.toBe(1);
      await first.commitTransaction();
      await expect(secondUnsafe).resolves.toBe(1);
      await second.commitTransaction();
    } finally {
      for (const runner of [holder, first, second]) {
        if (runner.isTransactionActive) await runner.rollbackTransaction();
        await runner.release();
      }
    }
  });

  it.each(['register', 'login'] as const)(
    'stops invalid Origin or CSRF input before %s password, user, or limiter work',
    async (endpoint) => {
      const hash = jest.spyOn(ScryptPasswordHasher.prototype, 'hash');
      const verify = jest.spyOn(ScryptPasswordHasher.prototype, 'verify');
      const dummy = jest.spyOn(ScryptPasswordHasher.prototype, 'verifyDummy');
      const userRead = jest.spyOn(TypeOrmUserRepository.prototype, 'findByNormalizedEmail');
      const userInsert = jest.spyOn(TypeOrmUserRepository.prototype, 'insertIfAbsent');
      const legacyUserInsert = jest.spyOn(TypeOrmUserRepository.prototype, 'insert');
      const registration = jest.spyOn(
        TypeOrmRegistrationThrottleRepository.prototype,
        'consumeAttempt',
      );
      const login = jest.spyOn(TypeOrmLoginThrottleRepository.prototype, 'acquireForLogin');
      const loginFailure = jest.spyOn(TypeOrmLoginThrottleRepository.prototype, 'consumeFailure');
      const loginReset = jest.spyOn(TypeOrmLoginThrottleRepository.prototype, 'resetFailures');
      const usersBefore = await observer.getRepository(UserEntity).count();
      try {
        const missingOrigin = await bootstrapCsrf(app);
        await request(app.getHttpServer())
          .post(`/api/v1/auth/${endpoint}`)
          .set('Cookie', missingOrigin.cookie)
          .set('X-CSRF-Token', missingOrigin.csrfToken)
          .send({ email: 'guard@example.test', password: PASSWORD })
          .expect(403);
        const disallowedOrigin = await bootstrapCsrf(app);
        await request(app.getHttpServer())
          .post(`/api/v1/auth/${endpoint}`)
          .set('Origin', 'https://untrusted.example')
          .set('Cookie', disallowedOrigin.cookie)
          .set('X-CSRF-Token', disallowedOrigin.csrfToken)
          .send({ email: 'guard@example.test', password: PASSWORD })
          .expect(403);
        const missingHeader = await bootstrapCsrf(app);
        await request(app.getHttpServer())
          .post(`/api/v1/auth/${endpoint}`)
          .set('Origin', ORIGIN)
          .set('Cookie', missingHeader.cookie)
          .send({
            email: 'guard@example.test',
            password: PASSWORD,
            csrfToken: missingHeader.csrfToken,
          })
          .expect(403);
        const wrongHeader = await bootstrapCsrf(app);
        await request(app.getHttpServer())
          .post(`/api/v1/auth/${endpoint}`)
          .set('Origin', ORIGIN)
          .set('Cookie', wrongHeader.cookie)
          .set('X-CSRF-Token', randomBytes(32).toString('base64url'))
          .send({ email: 'guard@example.test', password: PASSWORD })
          .expect(403);
        const alternateHeader = await bootstrapCsrf(app);
        await request(app.getHttpServer())
          .post(`/api/v1/auth/${endpoint}?csrfToken=${alternateHeader.csrfToken}`)
          .set('Origin', ORIGIN)
          .set('Cookie', alternateHeader.cookie)
          .set('X-Alternate-CSRF-Token', alternateHeader.csrfToken)
          .send({ email: 'guard@example.test', password: PASSWORD })
          .expect(403);
        expect(await observer.getRepository(UserEntity).count()).toBe(usersBefore);
        expect(hash).not.toHaveBeenCalled();
        expect(verify).not.toHaveBeenCalled();
        expect(dummy).not.toHaveBeenCalled();
        expect(userRead).not.toHaveBeenCalled();
        expect(userInsert).not.toHaveBeenCalled();
        expect(legacyUserInsert).not.toHaveBeenCalled();
        expect(registration).not.toHaveBeenCalled();
        expect(login).not.toHaveBeenCalled();
        expect(loginFailure).not.toHaveBeenCalled();
        expect(loginReset).not.toHaveBeenCalled();
      } finally {
        hash.mockRestore();
        verify.mockRestore();
        dummy.mockRestore();
        userRead.mockRestore();
        userInsert.mockRestore();
        legacyUserInsert.mockRestore();
        registration.mockRestore();
        login.mockRestore();
        loginFailure.mockRestore();
        loginReset.mockRestore();
      }
    },
  );

  it.each(['register', 'login'] as const)(
    'rejects hostile server-owned body fields after a valid %s guard without application work',
    async (endpoint) => {
      const bootstrap = await bootstrapCsrf(app);
      const userRead = jest.spyOn(TypeOrmUserRepository.prototype, 'findByNormalizedEmail');
      const userInsert = jest.spyOn(TypeOrmUserRepository.prototype, 'insertIfAbsent');
      const legacyUserInsert = jest.spyOn(TypeOrmUserRepository.prototype, 'insert');
      const hash = jest.spyOn(ScryptPasswordHasher.prototype, 'hash');
      const verify = jest.spyOn(ScryptPasswordHasher.prototype, 'verify');
      const dummy = jest.spyOn(ScryptPasswordHasher.prototype, 'verifyDummy');
      const registration = jest.spyOn(
        TypeOrmRegistrationThrottleRepository.prototype,
        'consumeAttempt',
      );
      const login = jest.spyOn(TypeOrmLoginThrottleRepository.prototype, 'acquireForLogin');
      const loginFailure = jest.spyOn(TypeOrmLoginThrottleRepository.prototype, 'consumeFailure');
      const loginReset = jest.spyOn(TypeOrmLoginThrottleRepository.prototype, 'resetFailures');
      try {
        await request(app.getHttpServer())
          .post(`/api/v1/auth/${endpoint}`)
          .set('Origin', ORIGIN)
          .set('Cookie', bootstrap.cookie)
          .set('X-CSRF-Token', bootstrap.csrfToken)
          .send({
            email: 'hostile@example.test',
            password: PASSWORD,
            id: 'server-owned-id',
            role: 'admin',
            capability: 'all',
            createdAt: '2000-01-01T00:00:00.000Z',
            updatedAt: '2000-01-01T00:00:00.000Z',
          })
          .expect(400);
        expect(userRead).not.toHaveBeenCalled();
        expect(userInsert).not.toHaveBeenCalled();
        expect(legacyUserInsert).not.toHaveBeenCalled();
        expect(hash).not.toHaveBeenCalled();
        expect(verify).not.toHaveBeenCalled();
        expect(dummy).not.toHaveBeenCalled();
        expect(registration).not.toHaveBeenCalled();
        expect(login).not.toHaveBeenCalled();
        expect(loginFailure).not.toHaveBeenCalled();
        expect(loginReset).not.toHaveBeenCalled();
      } finally {
        userRead.mockRestore();
        userInsert.mockRestore();
        legacyUserInsert.mockRestore();
        hash.mockRestore();
        verify.mockRestore();
        dummy.mockRestore();
        registration.mockRestore();
        login.mockRestore();
        loginFailure.mockRestore();
        loginReset.mockRestore();
      }
    },
  );

  it.each([
    {
      firstPassword: 'wrong literal password',
      expectedFailures: 0,
      firstStatus: 401,
      secondStatus: 200,
    },
    { firstPassword: PASSWORD, expectedFailures: 1, firstStatus: 200, secondStatus: 401 },
  ])(
    'serializes valid and invalid login order with durable expected failures',
    async ({ firstPassword, expectedFailures, firstStatus, secondStatus }) => {
      const email = `order-${randomBytes(6).toString('hex')}@example.test`;
      await registerAccount(app, email);
      const seed = await bootstrapCsrf(app);
      await request(app.getHttpServer())
        .post('/api/v1/auth/login')
        .set('Origin', ORIGIN)
        .set('Cookie', seed.cookie)
        .set('X-CSRF-Token', seed.csrfToken)
        .send({ email, password: 'wrong literal password' })
        .expect(401);
      const reset = await bootstrapCsrf(app);
      await request(app.getHttpServer())
        .post('/api/v1/auth/login')
        .set('Origin', ORIGIN)
        .set('Cookie', reset.cookie)
        .set('X-CSRF-Token', reset.csrfToken)
        .send({ email, password: PASSWORD })
        .expect(200);
      const key = createThrottleKey(
        IdentityAuthConfig.from(process.env),
        'login',
        email,
        '127.0.0.1',
      );
      if (key === null) throw new Error('Expected loopback throttle key.');
      const throttle = await observer
        .getRepository(LoginThrottleEntity)
        .findOneByOrFail({ keyHash: key });
      const runner = observer.createQueryRunner();
      await runner.connect();
      await runner.startTransaction();
      try {
        await runner.query(
          `SELECT id FROM "${plan.schemaName}".identity_login_throttles WHERE id = $1 FOR UPDATE`,
          [throttle.id],
        );
        const first = await bootstrapCsrf(app);
        const second = await bootstrapCsrf(app);
        const firstRequest = loginRequest(app, first, email, firstPassword);
        await waitForWaitingTransactions(observer, plan, 'identity_login_throttles', 1);
        const secondPassword = firstPassword === PASSWORD ? 'wrong literal password' : PASSWORD;
        const secondRequest = loginRequest(app, second, email, secondPassword);
        const waiters = await waitForWaitingTransactions(
          observer,
          plan,
          'identity_login_throttles',
          2,
        );
        expect(new Set(waiters.map((waiter) => waiter.pid)).size).toBe(2);
        expect(waiters.every((waiter) => waiter.query.includes('identity_login_throttles'))).toBe(
          true,
        );
        await runner.commitTransaction();
        const [firstResponse, secondResponse] = await Promise.all([firstRequest, secondRequest]);
        expect(firstResponse.status).toBe(firstStatus);
        expect(secondResponse.status).toBe(secondStatus);
        expect(
          (await observer.getRepository(LoginThrottleEntity).findOneByOrFail({ keyHash: key }))
            .failureCount,
        ).toBe(expectedFailures);
        const responses = [
          { bootstrap: first, response: firstResponse },
          { bootstrap: second, response: secondResponse },
        ];
        for (const receipt of responses) {
          const preAuth = await observer.getRepository(SessionEntity).findOneByOrFail({
            tokenHash: sha256(receipt.bootstrap.cookieValue),
          });
          if (receipt.response.status === 200) {
            expect(preAuth.state).toBe('revoked');
            const fresh = await observer.getRepository(SessionEntity).findOneByOrFail({
              tokenHash: sha256(firstCookie(receipt.response).slice('__Host-session='.length)),
            });
            expect(fresh).toMatchObject({ state: 'authenticated', revokedAt: null });
            expect(fresh.idleExpiresAt.getTime() - fresh.createdAt.getTime()).toBe(
              8 * 60 * 60 * 1000,
            );
            expect(fresh.absoluteExpiresAt.getTime() - fresh.createdAt.getTime()).toBe(
              24 * 60 * 60 * 1000,
            );
          } else {
            expect(preAuth).toMatchObject({ state: 'pre_auth', revokedAt: null });
          }
        }
      } finally {
        if (runner.isTransactionActive) await runner.rollbackTransaction();
        await runner.release();
      }
    },
  );
});

type Bootstrap = {
  readonly cookie: string;
  readonly cookieValue: string;
  readonly csrfToken: string;
};

async function bootstrapCsrf(app: INestApplication): Promise<Bootstrap> {
  const response = await request(app.getHttpServer()).get('/api/v1/auth/csrf').expect(200);
  const cookie = firstCookie(response);
  const csrfToken = response.body?.data?.csrfToken;
  if (typeof csrfToken !== 'string') throw new Error('Missing CSRF token.');
  return { cookie, cookieValue: cookie.slice('__Host-session='.length), csrfToken };
}

async function registerAccount(app: INestApplication, email: string): Promise<void> {
  const bootstrap = await bootstrapCsrf(app);
  await request(app.getHttpServer())
    .post('/api/v1/auth/register')
    .set('Origin', ORIGIN)
    .set('Cookie', bootstrap.cookie)
    .set('X-CSRF-Token', bootstrap.csrfToken)
    .send({ email, password: PASSWORD })
    .expect(201);
}

function loginRequest(
  app: INestApplication,
  bootstrap: Bootstrap,
  email: string,
  password: string,
): Promise<Response> {
  return request(app.getHttpServer())
    .post('/api/v1/auth/login')
    .set('Origin', ORIGIN)
    .set('Cookie', bootstrap.cookie)
    .set('X-CSRF-Token', bootstrap.csrfToken)
    .send({ email, password })
    .then((response) => response);
}

async function waitForWaitingTransactions(
  source: DataSource,
  plan: IsolatedPostgresPlan,
  table: string,
  minimum: number,
): Promise<readonly WaitingQueryReceipt[]> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const rows = await source.query(
      `SELECT pid, query FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock' AND query ILIKE $2`,
      [plan.databaseName, `%${table}%`],
    );
    const receipts = readWaitingQueryReceipts(rows);
    if (receipts.length >= minimum) return receipts;
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('Race barrier did not reach the expected database lock.');
}

type WaitingQueryReceipt = { readonly pid: number; readonly query: string };
type LocalThrottlePurpose = 'login' | 'registration';

function readWaitingQueryReceipts(value: unknown): readonly WaitingQueryReceipt[] {
  if (!Array.isArray(value)) throw new Error('Unexpected lock-observer result.');
  const receipts: WaitingQueryReceipt[] = [];
  for (const row of value) {
    if (typeof row !== 'object' || row === null || Array.isArray(row)) {
      throw new Error('Unexpected lock-observer row.');
    }
    const candidate = row as Record<string, unknown>;
    if (typeof candidate.pid !== 'number' || typeof candidate.query !== 'string') {
      throw new Error('Unexpected lock-observer receipt.');
    }
    receipts.push({ pid: candidate.pid, query: candidate.query });
  }
  return receipts;
}

function firstCookie(response: Response): string {
  const value = response.headers['set-cookie'];
  if (!Array.isArray(value) || typeof value[0] !== 'string')
    throw new Error('Missing session cookie.');
  return value[0].split(';')[0] ?? '';
}

function readRawSetCookie(response: Response): string | undefined {
  const value = response.headers['set-cookie'];
  return Array.isArray(value) && typeof value[0] === 'string' ? value[0] : undefined;
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function throttleKey(
  config: IdentityAuthConfig,
  purpose: LocalThrottlePurpose,
  email: string,
): string {
  const key = createThrottleKey(config, purpose, email, '127.0.0.1');
  if (key === null) throw new Error('Expected loopback throttle key.');
  return key;
}

async function unsafeUnconditionalRevoke(
  runner: QueryRunner,
  schema: string,
  id: string,
): Promise<number> {
  const rows = await runner.query(
    `WITH updated AS (UPDATE "${schema}".identity_sessions SET state = 'revoked', revoked_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING id) SELECT count(*)::int AS affected FROM updated`,
    [id],
  );
  if (!Array.isArray(rows) || rows.length !== 1)
    throw new Error('Unexpected unsafe control result.');
  const [row] = rows;
  if (typeof row !== 'object' || row === null || Array.isArray(row)) {
    throw new Error('Unexpected unsafe control row.');
  }
  const affected = (row as Record<string, unknown>).affected;
  if (typeof affected !== 'number') throw new Error('Unexpected unsafe control count.');
  return affected;
}

function configureEnvironment(plan: IsolatedPostgresPlan): void {
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

function loopbackPort(): Promise<number> {
  return new Promise((resolvePort, rejectPort) => {
    const server = createServer();
    server.once('error', rejectPort);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string')
        return server.close(() => rejectPort(new Error('No loopback port.')));
      return server.close((error) =>
        error === undefined ? resolvePort(address.port) : rejectPort(error),
      );
    });
  });
}
