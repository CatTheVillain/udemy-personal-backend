import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';

import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { Test } from '@nestjs/testing';
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
const BOOTSTRAP_ADVISORY_LOCK_KEY = 734_111_002;
const BOOTSTRAP_POPULATION_CAP = 10_000;

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

  it('uses the default provider and a scoped real-hasher override through the full Nest path', async () => {
    const defaultBootstrap = await bootstrapCsrf(app);
    await registerRequest(
      app,
      defaultBootstrap,
      `default-${randomBytes(6).toString('hex')}@example.test`,
    ).then((response) => expect(response.status).toBe(201));

    const scoped = await createScopedBarrierApplication();
    try {
      const scopedBootstrap = await bootstrapCsrf(scoped.app);
      const pending = registerRequest(
        scoped.app,
        scopedBootstrap,
        `scoped-${randomBytes(6).toString('hex')}@example.test`,
      );
      await expect(scoped.methodEntered).resolves.toBe('hash');
      scoped.releaseStart();
      await expect(scoped.realKdfCompleted).resolves.toBeUndefined();
      scoped.releaseReturn();
      await pending.then((response) => expect(response.status).toBe(201));
    } finally {
      await scoped.close();
    }
  });

  it('requires SQL-current final registration after a real hash has completed', async () => {
    const scoped = await createScopedBarrierApplication();
    try {
      const bootstrap = await bootstrapCsrf(scoped.app);
      const session = await observer.getRepository(SessionEntity).findOneByOrFail({
        tokenHash: sha256(bootstrap.cookieValue),
      });
      await observer.query(
        `UPDATE "${plan.schemaName}".identity_sessions SET idle_expires_at = clock_timestamp() + INTERVAL '2 seconds', absolute_expires_at = clock_timestamp() + INTERVAL '3 seconds' WHERE id = $1`,
        [session.id],
      );

      const email = `post-kdf-expiry-${randomBytes(6).toString('hex')}@example.test`;
      const pending = registerRequest(scoped.app, bootstrap, email);
      await expect(scoped.methodEntered).resolves.toBe('hash');
      scoped.releaseStart();
      await expect(scoped.realKdfCompleted).resolves.toBeUndefined();
      await waitForSessionExpiry(observer, plan, session.id);
      scoped.releaseReturn();

      const response = await pending;
      expect(response.status).toBe(401);
      expect(response.body.code).toBe('AUTHENTICATION_REQUIRED');
      expect(readRawSetCookie(response)).toContain('__Host-session=;');
      expect(await observer.getRepository(UserEntity).countBy({ normalizedEmail: email })).toBe(0);
      expect(
        await observer.getRepository(SessionEntity).findOneByOrFail({ id: session.id }),
      ).toMatchObject({ state: 'pre_auth', revokedAt: null });
    } finally {
      await scoped.close();
    }
  });

  it('rolls back an expired valid-login reset and completes a current real verification', async () => {
    const email = `valid-login-expiry-${randomBytes(6).toString('hex')}@example.test`;
    await registerAccount(app, email);
    const seed = await bootstrapCsrf(app);
    await loginRequest(app, seed, email, 'wrong literal password').then((response) =>
      expect(response.status).toBe(401),
    );
    const loginKey = throttleKey(IdentityAuthConfig.from(process.env), 'login', email);
    const scoped = await createScopedBarrierApplication();
    try {
      const bootstrap = await bootstrapCsrf(scoped.app);
      const session = await observer.getRepository(SessionEntity).findOneByOrFail({
        tokenHash: sha256(bootstrap.cookieValue),
      });
      await observer.query(
        `UPDATE "${plan.schemaName}".identity_sessions SET idle_expires_at = clock_timestamp() + INTERVAL '2 seconds', absolute_expires_at = clock_timestamp() + INTERVAL '3 seconds' WHERE id = $1`,
        [session.id],
      );

      const pending = loginRequest(scoped.app, bootstrap, email, PASSWORD);
      await expect(scoped.methodEntered).resolves.toBe('verify');
      scoped.releaseStart();
      await expect(scoped.realKdfCompleted).resolves.toBeUndefined();
      await waitForSessionExpiry(observer, plan, session.id);
      scoped.releaseReturn();

      const response = await pending;
      expect(response.status).toBe(401);
      expect(response.body.code).toBe('AUTHENTICATION_REQUIRED');
      expect(readRawSetCookie(response)).toContain('__Host-session=;');
      expect(
        await observer.getRepository(LoginThrottleEntity).findOneByOrFail({ keyHash: loginKey }),
      ).toMatchObject({ failureCount: 1 });
      expect(
        await observer.getRepository(SessionEntity).findOneByOrFail({ id: session.id }),
      ).toMatchObject({ state: 'pre_auth', revokedAt: null });
    } finally {
      await scoped.close();
    }

    const current = await createScopedBarrierApplication();
    try {
      const bootstrap = await bootstrapCsrf(current.app);
      const pending = loginRequest(current.app, bootstrap, email, PASSWORD);
      await expect(current.methodEntered).resolves.toBe('verify');
      current.releaseStart();
      await expect(current.realKdfCompleted).resolves.toBeUndefined();
      current.releaseReturn();
      await pending.then((response) => expect(response.status).toBe(200));
      expect(
        await observer.getRepository(LoginThrottleEntity).findOneByOrFail({ keyHash: loginKey }),
      ).toMatchObject({ failureCount: 0 });
    } finally {
      await current.close();
    }
  });

  it.each([
    { emailPrefix: 'wrong-known-expiry', expectedMethod: 'verify' as const, known: true },
    { emailPrefix: 'unknown-expiry', expectedMethod: 'verifyDummy' as const, known: false },
  ])(
    'rolls back an expired post-KDF $expectedMethod failure and retains a current pre-auth retry',
    async ({ emailPrefix, expectedMethod, known }) => {
      const email = `${emailPrefix}-${randomBytes(6).toString('hex')}@example.test`;
      if (known) await registerAccount(app, email);
      const loginKey = throttleKey(IdentityAuthConfig.from(process.env), 'login', email);
      const scoped = await createScopedBarrierApplication();
      try {
        const expiredBootstrap = await bootstrapCsrf(scoped.app);
        const expiredSession = await observer.getRepository(SessionEntity).findOneByOrFail({
          tokenHash: sha256(expiredBootstrap.cookieValue),
        });
        await observer.query(
          `UPDATE "${plan.schemaName}".identity_sessions SET idle_expires_at = clock_timestamp() + INTERVAL '2 seconds', absolute_expires_at = clock_timestamp() + INTERVAL '3 seconds' WHERE id = $1`,
          [expiredSession.id],
        );

        const expiredPending = loginRequest(
          scoped.app,
          expiredBootstrap,
          email,
          'wrong literal password',
        );
        await expect(scoped.methodEntered).resolves.toBe(expectedMethod);
        scoped.releaseStart();
        await expect(scoped.realKdfCompleted).resolves.toBeUndefined();
        await waitForSessionExpiry(observer, plan, expiredSession.id);
        scoped.releaseReturn();

        const expiredResponse = await expiredPending;
        expect(expiredResponse.status).toBe(401);
        expect(expiredResponse.body.code).toBe('AUTHENTICATION_REQUIRED');
        expect(readRawSetCookie(expiredResponse)).toContain('__Host-session=;');
        expect(
          await observer.getRepository(LoginThrottleEntity).findOneBy({ keyHash: loginKey }),
        ).toBeNull();
        expect(
          await observer.getRepository(SessionEntity).findOneByOrFail({ id: expiredSession.id }),
        ).toMatchObject({ state: 'pre_auth', revokedAt: null });

        const currentBootstrap = await bootstrapCsrf(scoped.app);
        const currentResponse = await loginRequest(
          scoped.app,
          currentBootstrap,
          email,
          'wrong literal password',
        );
        expect(currentResponse.status).toBe(401);
        expect(currentResponse.body.code).toBe('credentials_invalid');
        expect(currentResponse.headers['set-cookie']).toBeUndefined();
        expect(
          await observer.getRepository(SessionEntity).findOneByOrFail({
            tokenHash: sha256(currentBootstrap.cookieValue),
          }),
        ).toMatchObject({ state: 'pre_auth', revokedAt: null });
        await loginRequest(scoped.app, currentBootstrap, email, 'wrong literal password').then(
          (response) => {
            expect(response.status).toBe(401);
            expect(response.body.code).toBe('credentials_invalid');
            expect(response.headers['set-cookie']).toBeUndefined();
          },
        );
      } finally {
        await scoped.close();
      }
    },
  );

  it('keeps an initial registration overflow from adding a key until a later request starts below cap', async () => {
    const baseline = await countRegistrationThrottles(observer, plan.schemaName);
    const activeIds = await seedRegistrationThrottles(
      observer,
      Math.max(0, 10_000 - baseline),
      'active',
    );
    const expiredIds = await seedRegistrationThrottles(observer, 1, 'expired');
    const email = `overflow-${randomBytes(6).toString('hex')}@example.test`;
    try {
      const first = await bootstrapCsrf(app);
      const firstResponse = await registerRequest(app, first, email);

      expect(firstResponse.status).toBe(503);
      expect(firstResponse.body.code).toBe('throttle_capacity_unavailable');
      expect(firstResponse.headers['retry-after']).toBe('60');
      expect(await countRegistrationThrottles(observer, plan.schemaName)).toBeLessThanOrEqual(
        10_000,
      );
    } finally {
      await observer
        .getRepository(RegistrationThrottleEntity)
        .delete([...activeIds, ...expiredIds]);
      await observer.getRepository(RegistrationThrottleEntity).delete({
        keyHash: throttleKey(IdentityAuthConfig.from(process.env), 'registration', email),
      });
    }
  });

  it('cleans an eligible exact-cap row before admitting the first-seen registration key', async () => {
    const baseline = await countRegistrationThrottles(observer, plan.schemaName);
    const activeIds = await seedRegistrationThrottles(
      observer,
      Math.max(0, 9_999 - baseline),
      'active',
    );
    const expiredIds = await seedRegistrationThrottles(observer, 1, 'expired');
    const email = `exact-cap-${randomBytes(6).toString('hex')}@example.test`;
    try {
      const bootstrap = await bootstrapCsrf(app);
      await registerRequest(app, bootstrap, email).then((response) =>
        expect(response.status).toBe(201),
      );
      expect(await countRegistrationThrottles(observer, plan.schemaName)).toBe(10_000);
      const [expiredId] = expiredIds;
      if (expiredId === undefined) throw new Error('Missing exact-cap expired throttle row.');
      expect(
        await observer.getRepository(RegistrationThrottleEntity).countBy({ id: expiredId }),
      ).toBe(0);
    } finally {
      await observer
        .getRepository(RegistrationThrottleEntity)
        .delete([...activeIds, ...expiredIds]);
      await observer.getRepository(RegistrationThrottleEntity).delete({
        keyHash: throttleKey(IdentityAuthConfig.from(process.env), 'registration', email),
      });
    }
  });

  it('keeps login-table active overflow, cleans exact-cap eligibility, and admits only after a later below-cap probe', async () => {
    const overflowBaseline = await countLoginThrottles(observer, plan.schemaName);
    const activeOverflow = await seedLoginThrottles(
      observer,
      Math.max(0, 10_001 - overflowBaseline),
      'active',
    );
    const overflowEmail = `login-active-overflow-${randomBytes(6).toString('hex')}@example.test`;
    try {
      const overflow = await bootstrapCsrf(app);
      const overflowResponse = await loginRequest(
        app,
        overflow,
        overflowEmail,
        'wrong literal password',
      );
      expect(overflowResponse.status).toBe(503);
      expect(overflowResponse.body.code).toBe('throttle_capacity_unavailable');
      expect(overflowResponse.headers['retry-after']).toBe('60');
      expect(await countLoginThrottles(observer, plan.schemaName)).toBe(10_001);
      expect(
        await observer.getRepository(LoginThrottleEntity).findOneBy({
          keyHash: throttleKey(IdentityAuthConfig.from(process.env), 'login', overflowEmail),
        }),
      ).toBeNull();
    } finally {
      await observer.getRepository(LoginThrottleEntity).delete([...activeOverflow]);
    }

    const exactBaseline = await countLoginThrottles(observer, plan.schemaName);
    const exactActive = await seedLoginThrottles(
      observer,
      Math.max(0, 9_999 - exactBaseline),
      'active',
    );
    const eligible = await seedLoginThrottles(observer, 2, 'expired');
    const firstEmail = `login-overflow-first-${randomBytes(6).toString('hex')}@example.test`;
    const laterEmail = `login-overflow-later-${randomBytes(6).toString('hex')}@example.test`;
    try {
      const first = await bootstrapCsrf(app);
      const firstResponse = await loginRequest(app, first, firstEmail, 'wrong literal password');
      expect(firstResponse.status).toBe(503);
      expect(firstResponse.body.code).toBe('throttle_capacity_unavailable');
      expect(await countLoginThrottles(observer, plan.schemaName)).toBe(9_999);
      expect(
        await observer.getRepository(LoginThrottleEntity).findOneBy({
          keyHash: throttleKey(IdentityAuthConfig.from(process.env), 'login', firstEmail),
        }),
      ).toBeNull();

      const later = await bootstrapCsrf(app);
      const laterResponse = await loginRequest(app, later, laterEmail, 'wrong literal password');
      expect(laterResponse.status).toBe(401);
      expect(laterResponse.body.code).toBe('credentials_invalid');
      expect(await countLoginThrottles(observer, plan.schemaName)).toBe(10_000);
    } finally {
      await observer.getRepository(LoginThrottleEntity).delete([...exactActive, ...eligible]);
      await observer.getRepository(LoginThrottleEntity).delete({
        keyHash: throttleKey(IdentityAuthConfig.from(process.env), 'login', firstEmail),
      });
      await observer.getRepository(LoginThrottleEntity).delete({
        keyHash: throttleKey(IdentityAuthConfig.from(process.env), 'login', laterEmail),
      });
    }
  });

  it('refuses a login first-seen key at exact cap when no row is SQL-eligible for cleanup', async () => {
    const baseline = await countLoginThrottles(observer, plan.schemaName);
    const active = await seedLoginThrottles(observer, Math.max(0, 10_000 - baseline), 'active');
    const email = `login-exact-cap-${randomBytes(6).toString('hex')}@example.test`;
    try {
      const bootstrap = await bootstrapCsrf(app);
      const response = await loginRequest(app, bootstrap, email, 'wrong literal password');
      expect(response.status).toBe(503);
      expect(response.body.code).toBe('throttle_capacity_unavailable');
      expect(response.headers['retry-after']).toBe('60');
      expect(await countLoginThrottles(observer, plan.schemaName)).toBe(10_000);
      expect(
        await observer.getRepository(LoginThrottleEntity).findOneBy({
          keyHash: throttleKey(IdentityAuthConfig.from(process.env), 'login', email),
        }),
      ).toBeNull();
    } finally {
      await observer.getRepository(LoginThrottleEntity).delete([...active]);
    }
  });

  it('rejects a second first-seen registration while the first transaction holds its real KDF', async () => {
    const scoped = await createScopedBarrierApplication();
    const firstEmail = `lock-first-${randomBytes(6).toString('hex')}@example.test`;
    const secondEmail = `lock-second-${randomBytes(6).toString('hex')}@example.test`;
    let firstRequest: Promise<Response> | undefined;
    try {
      const firstBootstrap = await bootstrapCsrf(scoped.app);
      firstRequest = registerRequest(scoped.app, firstBootstrap, firstEmail);
      await expect(scoped.methodEntered).resolves.toBe('hash');
      scoped.releaseStart();
      await expect(scoped.realKdfCompleted).resolves.toBeUndefined();

      const secondBootstrap = await bootstrapCsrf(scoped.app);
      const secondResponse = await Promise.race([
        registerRequest(scoped.app, secondBootstrap, secondEmail),
        new Promise<never>((_resolve, reject) =>
          setTimeout(() => reject(new Error('Second first-seen registration waited.')), 5_000),
        ),
      ]);
      expect(secondResponse.status).toBe(503);
      expect(secondResponse.body.code).toBe('throttle_busy');
      expect(
        await observer.getRepository(RegistrationThrottleEntity).findOneBy({
          keyHash: throttleKey(IdentityAuthConfig.from(process.env), 'registration', secondEmail),
        }),
      ).toBeNull();

      scoped.releaseReturn();
      await firstRequest.then((response) => expect(response.status).toBe(201));
    } finally {
      scoped.releaseReturn();
      if (firstRequest !== undefined) await firstRequest.catch(() => undefined);
      await scoped.close();
    }
  });

  it('rejects a second first-seen login key while the first transaction holds its real KDF', async () => {
    const firstEmail = `login-lock-first-${randomBytes(6).toString('hex')}@example.test`;
    const secondEmail = `login-lock-second-${randomBytes(6).toString('hex')}@example.test`;
    await registerAccount(app, firstEmail);
    await registerAccount(app, secondEmail);
    const scoped = await createScopedBarrierApplication();
    let firstRequest: Promise<Response> | undefined;
    try {
      const firstBootstrap = await bootstrapCsrf(scoped.app);
      firstRequest = loginRequest(scoped.app, firstBootstrap, firstEmail, PASSWORD);
      await expect(scoped.methodEntered).resolves.toBe('verify');
      scoped.releaseStart();
      await expect(scoped.realKdfCompleted).resolves.toBeUndefined();

      const secondBootstrap = await bootstrapCsrf(scoped.app);
      const secondResponse = await Promise.race([
        loginRequest(scoped.app, secondBootstrap, secondEmail, PASSWORD),
        new Promise<never>((_resolve, reject) =>
          setTimeout(() => reject(new Error('Second first-seen login waited.')), 5_000),
        ),
      ]);
      expect(secondResponse.status).toBe(503);
      expect(secondResponse.body.code).toBe('throttle_busy');
      expect(secondResponse.headers['retry-after']).toBe('1');
      expect(
        await observer.getRepository(LoginThrottleEntity).findOneBy({
          keyHash: throttleKey(IdentityAuthConfig.from(process.env), 'login', secondEmail),
        }),
      ).toBeNull();

      scoped.releaseReturn();
      await firstRequest.then((response) => expect(response.status).toBe(200));
    } finally {
      scoped.releaseReturn();
      if (firstRequest !== undefined) await firstRequest.catch(() => undefined);
      await scoped.close();
    }
  });

  it.each(['registration', 'login'] as const)(
    'commits eligible %s throttle cleanup before ordinary capacity refusal',
    async (purpose) => {
      const baseline =
        purpose === 'registration'
          ? await countRegistrationThrottles(observer, plan.schemaName)
          : await countLoginThrottles(observer, plan.schemaName);
      const activeCount = 10_000 - baseline;
      if (activeCount < 0) throw new Error('Unexpected throttle baseline above the capacity.');
      const activeIds =
        purpose === 'registration'
          ? await seedRegistrationThrottles(observer, activeCount, 'active')
          : await seedLoginThrottles(observer, activeCount, 'active');
      const eligibleIds =
        purpose === 'registration'
          ? await seedRegistrationThrottles(observer, 1, 'expired')
          : await seedLoginThrottles(observer, 1, 'expired');
      const [eligibleId] = eligibleIds;
      if (eligibleId === undefined) throw new Error('Missing eligible throttle row.');
      const email = `${purpose}-cleanup-${randomBytes(6).toString('hex')}@example.test`;
      const key = throttleKey(IdentityAuthConfig.from(process.env), purpose, email);
      try {
        const bootstrap = await bootstrapCsrf(app);
        const response =
          purpose === 'registration'
            ? await registerRequest(app, bootstrap, email)
            : await loginRequest(app, bootstrap, email, 'wrong literal password');
        expect(response.status).toBe(503);
        expect(response.body.code).toBe('throttle_capacity_unavailable');
        expect(response.headers['retry-after']).toBe('60');
        if (purpose === 'registration') {
          expect(
            await observer.getRepository(RegistrationThrottleEntity).findOneBy({ id: eligibleId }),
          ).toBeNull();
          expect(
            await observer.getRepository(RegistrationThrottleEntity).findOneBy({ keyHash: key }),
          ).toBeNull();
          expect(await countRegistrationThrottles(observer, plan.schemaName)).toBe(10_000);
        } else {
          expect(
            await observer.getRepository(LoginThrottleEntity).findOneBy({ id: eligibleId }),
          ).toBeNull();
          expect(
            await observer.getRepository(LoginThrottleEntity).findOneBy({ keyHash: key }),
          ).toBeNull();
          expect(await countLoginThrottles(observer, plan.schemaName)).toBe(10_000);
        }
      } finally {
        if (purpose === 'registration') {
          await observer
            .getRepository(RegistrationThrottleEntity)
            .delete([...activeIds, ...eligibleIds]);
          await observer.getRepository(RegistrationThrottleEntity).delete({ keyHash: key });
        } else {
          await observer.getRepository(LoginThrottleEntity).delete([...activeIds, ...eligibleIds]);
          await observer.getRepository(LoginThrottleEntity).delete({ keyHash: key });
        }
      }
    },
  );

  it.each(['registration', 'login'] as const)(
    'rolls back the new %s throttle key and restores its specific eligible row after real KDF expiry',
    async (purpose) => {
      const baseline =
        purpose === 'registration'
          ? await countRegistrationThrottles(observer, plan.schemaName)
          : await countLoginThrottles(observer, plan.schemaName);
      const activeCount = 9_999 - baseline;
      if (activeCount < 0)
        throw new Error('Unexpected throttle baseline above the rollback setup.');
      const activeIds =
        purpose === 'registration'
          ? await seedRegistrationThrottles(observer, activeCount, 'active')
          : await seedLoginThrottles(observer, activeCount, 'active');
      const eligibleIds =
        purpose === 'registration'
          ? await seedRegistrationThrottles(observer, 1, 'expired')
          : await seedLoginThrottles(observer, 1, 'expired');
      const [eligibleId] = eligibleIds;
      if (eligibleId === undefined) throw new Error('Missing rollback-eligible throttle row.');
      const email = `${purpose}-rollback-${randomBytes(6).toString('hex')}@example.test`;
      const key = throttleKey(IdentityAuthConfig.from(process.env), purpose, email);
      const usersBefore = await observer.getRepository(UserEntity).count();
      const scoped = await createScopedBarrierApplication();
      try {
        const bootstrap = await bootstrapCsrf(scoped.app);
        const session = await observer.getRepository(SessionEntity).findOneByOrFail({
          tokenHash: sha256(bootstrap.cookieValue),
        });
        await observer.query(
          `UPDATE "${plan.schemaName}".identity_sessions SET idle_expires_at = clock_timestamp() + INTERVAL '2 seconds', absolute_expires_at = clock_timestamp() + INTERVAL '3 seconds' WHERE id = $1`,
          [session.id],
        );
        const pending =
          purpose === 'registration'
            ? registerRequest(scoped.app, bootstrap, email)
            : loginRequest(scoped.app, bootstrap, email, 'wrong literal password');
        await expect(scoped.methodEntered).resolves.toBe(
          purpose === 'registration' ? 'hash' : 'verifyDummy',
        );
        scoped.releaseStart();
        await expect(scoped.realKdfCompleted).resolves.toBeUndefined();
        await waitForSessionExpiry(observer, plan, session.id);
        scoped.releaseReturn();

        const response = await pending;
        expect(response.status).toBe(401);
        expect(response.body.code).toBe('AUTHENTICATION_REQUIRED');
        expect(readRawSetCookie(response)).toContain('__Host-session=;');
        expect(await observer.getRepository(UserEntity).count()).toBe(usersBefore);
        expect(
          await observer.getRepository(SessionEntity).findOneByOrFail({ id: session.id }),
        ).toMatchObject({ state: 'pre_auth', revokedAt: null });
        if (purpose === 'registration') {
          expect(
            await observer.getRepository(RegistrationThrottleEntity).findOneBy({ id: eligibleId }),
          ).not.toBeNull();
          expect(
            await observer.getRepository(RegistrationThrottleEntity).findOneBy({ keyHash: key }),
          ).toBeNull();
          expect(await countRegistrationThrottles(observer, plan.schemaName)).toBe(10_000);
        } else {
          expect(
            await observer.getRepository(LoginThrottleEntity).findOneBy({ id: eligibleId }),
          ).not.toBeNull();
          expect(
            await observer.getRepository(LoginThrottleEntity).findOneBy({ keyHash: key }),
          ).toBeNull();
          expect(await countLoginThrottles(observer, plan.schemaName)).toBe(10_000);
        }
      } finally {
        await scoped.close();
        if (purpose === 'registration') {
          await observer
            .getRepository(RegistrationThrottleEntity)
            .delete([...activeIds, ...eligibleIds]);
          await observer.getRepository(RegistrationThrottleEntity).delete({ keyHash: key });
        } else {
          await observer.getRepository(LoginThrottleEntity).delete([...activeIds, ...eligibleIds]);
          await observer.getRepository(LoginThrottleEntity).delete({ keyHash: key });
        }
      }
    },
  );

  it('renews elapsed throttle windows and resets only the successful login key', async () => {
    const clock = app.get<IdentityClock>(IDENTITY_CLOCK);
    let now = new Date();
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
    const seededInvalid = await bootstrapCsrf(app);
    await loginRequest(app, seededInvalid, 'parallel@example.test', 'wrong literal password').then(
      (response) => expect(response.status).toBe(401),
    );
    const seededValid = await bootstrapCsrf(app);
    await loginRequest(app, seededValid, 'parallel@example.test', PASSWORD).then((response) =>
      expect(response.status).toBe(200),
    );
    const attempts: Bootstrap[] = [];
    for (let index = 0; index < 6; index += 1) {
      attempts.push(await bootstrapCsrf(app));
    }
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

  it('returns bootstrap busy without waiting while another connection owns the advisory lock', async () => {
    const holder = observer.createQueryRunner();
    await holder.connect();
    await holder.startTransaction();
    try {
      await holder.query('SELECT pg_advisory_xact_lock($1)', [BOOTSTRAP_ADVISORY_LOCK_KEY]);
      const response = await Promise.race([
        request(app.getHttpServer())
          .get('/api/v1/auth/csrf')
          .set('Origin', ORIGIN)
          .then((value) => value),
        new Promise<never>((_resolve, reject) =>
          setTimeout(() => reject(new Error('Bootstrap advisory admission waited.')), 1_000),
        ),
      ]);

      expect(response.status).toBe(503);
      expect(response.body.code).toBe('csrf_bootstrap_busy');
      expect(response.headers['retry-after']).toBe('1');
      expect(response.headers['access-control-expose-headers']).toContain('Retry-After');
      expect(response.headers['set-cookie']).toBeUndefined();
      expect(response.headers['content-type']).toContain('application/problem+json');
    } finally {
      if (holder.isTransactionActive) await holder.rollbackTransaction();
      await holder.release();
    }
  });

  it('skips a separately locked eligible row while deleting another bounded cleanup candidate', async () => {
    const held = await insertTerminalPreAuthSession(observer, 'expired');
    const removable = await insertTerminalPreAuthSession(observer, 'revoked');
    const holder = observer.createQueryRunner();
    await holder.connect();
    await holder.startTransaction();
    try {
      await holder.query(
        `SELECT id FROM "${plan.schemaName}".identity_sessions WHERE id = $1 FOR UPDATE`,
        [held.id],
      );
      const response = await request(app.getHttpServer()).get('/api/v1/auth/csrf').expect(200);

      expect(response.headers['set-cookie']).toBeDefined();
      expect(await observer.getRepository(SessionEntity).findOneBy({ id: held.id })).not.toBeNull();
      expect(
        await observer.getRepository(SessionEntity).findOneBy({ id: removable.id }),
      ).toBeNull();
    } finally {
      if (holder.isTransactionActive) await holder.rollbackTransaction();
      await holder.release();
      await observer.getRepository(SessionEntity).delete(held.id);
    }
  });

  it('commits eligible cleanup before reporting retained bootstrap capacity exhaustion', async () => {
    const eligible = await insertTerminalPreAuthSession(observer, 'expired');
    const before = await countBootstrapPopulation(observer, plan.schemaName);
    const eligibleBefore = await countBootstrapCleanupEligibility(observer, plan.schemaName);
    const insertedIds = await insertActivePreAuthPopulation(
      observer,
      BOOTSTRAP_POPULATION_CAP + eligibleBefore - before,
    );
    try {
      expect(await countBootstrapPopulation(observer, plan.schemaName)).toBe(
        BOOTSTRAP_POPULATION_CAP + eligibleBefore,
      );

      const response = await request(app.getHttpServer()).get('/api/v1/auth/csrf').expect(503);

      expect(response.body.code).toBe('csrf_bootstrap_capacity_unavailable');
      expect(response.headers['retry-after']).toBe('60');
      expect(response.headers['set-cookie']).toBeUndefined();
      expect(await observer.getRepository(SessionEntity).findOneBy({ id: eligible.id })).toBeNull();
      const after = await countBootstrapPopulation(observer, plan.schemaName);
      expect(after).toBeGreaterThanOrEqual(BOOTSTRAP_POPULATION_CAP);
      expect(after).toBeLessThan(before + insertedIds.length);
    } finally {
      await observer.getRepository(SessionEntity).delete(insertedIds);
      await observer.getRepository(SessionEntity).delete(eligible.id);
    }
  });

  it('rolls back cleanup when the bootstrap insert fails in PostgreSQL', async () => {
    const eligible = await insertTerminalPreAuthSession(observer, 'expired');
    const trigger = `fail_bootstrap_insert_${randomBytes(6).toString('hex')}`;
    const functionName = `${trigger}_function`;
    try {
      await observer.query(
        `CREATE FUNCTION "${plan.schemaName}"."${functionName}"() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'bootstrap insert test failure'; END; $$`,
      );
      await observer.query(
        `CREATE TRIGGER "${trigger}" BEFORE INSERT ON "${plan.schemaName}".identity_sessions FOR EACH ROW EXECUTE FUNCTION "${plan.schemaName}"."${functionName}"()`,
      );

      await request(app.getHttpServer()).get('/api/v1/auth/csrf').expect(500);

      expect(
        await observer.getRepository(SessionEntity).findOneBy({ id: eligible.id }),
      ).not.toBeNull();
    } finally {
      await observer.query(
        `DROP TRIGGER IF EXISTS "${trigger}" ON "${plan.schemaName}".identity_sessions`,
      );
      await observer.query(`DROP FUNCTION IF EXISTS "${plan.schemaName}"."${functionName}"()`);
    }
  });

  it('uses bounded indexed cleanup branches and a limited bootstrap population probe', async () => {
    const activeIds = await insertActivePreAuthPopulation(observer, 10_002);
    const expired = await insertTerminalPreAuthSession(observer, 'expired');
    const revoked = await insertTerminalPreAuthSession(observer, 'revoked');
    try {
      await observer.query(`ANALYZE "${plan.schemaName}".identity_sessions`);
      const expiredPlan = await explain(
        observer,
        `SELECT id FROM "${plan.schemaName}".identity_sessions WHERE state = 'pre_auth' AND absolute_expires_at <= CURRENT_TIMESTAMP ORDER BY absolute_expires_at, id LIMIT 256`,
      );
      const revokedPlan = await explain(
        observer,
        `SELECT id FROM "${plan.schemaName}".identity_sessions WHERE state = 'revoked' AND user_id IS NULL ORDER BY revoked_at, id LIMIT 256`,
      );
      const populationPlan = await explain(
        observer,
        `SELECT count(*) FROM (SELECT 1 FROM "${plan.schemaName}".identity_sessions WHERE state = 'pre_auth' OR (state = 'revoked' AND user_id IS NULL) LIMIT 10001) AS capped_population`,
      );

      expect(expiredPlan).toContain('Limit');
      expect(expiredPlan).toContain('idx_identity_session_pre_auth_expiry');
      expect(revokedPlan).toContain('Limit');
      expect(revokedPlan).toContain('idx_identity_session_revoked_pre_auth');
      expect(populationPlan).toContain('Limit');
      expect(populationPlan).toContain('10001');
    } finally {
      await observer.getRepository(SessionEntity).delete(activeIds);
      await observer.getRepository(SessionEntity).delete([expired.id, revoked.id]);
    }
  });
});

type Bootstrap = {
  readonly cookie: string;
  readonly cookieValue: string;
  readonly csrfToken: string;
};

type ScopedHasherMethod = 'hash' | 'verify' | 'verifyDummy';
type ThrottleSeedState = 'active' | 'expired';

interface ScopedBarrierApplication {
  readonly app: INestApplication;
  readonly methodEntered: Promise<ScopedHasherMethod>;
  readonly realKdfCompleted: Promise<void>;
  releaseReturn(): void;
  releaseStart(): void;
  close(): Promise<void>;
}

interface DeferredGate {
  readonly promise: Promise<void>;
  release(): void;
}

async function createScopedBarrierApplication(): Promise<ScopedBarrierApplication> {
  const startGate = deferredGate();
  const returnGate = deferredGate();
  const realHasher = new ScryptPasswordHasher();
  let resolveEntered: (method: ScopedHasherMethod) => void;
  let resolveCompleted: () => void;
  let rejectCompleted: (reason: unknown) => void;
  const methodEntered = new Promise<ScopedHasherMethod>((resolve) => {
    resolveEntered = resolve;
  });
  const realKdfCompleted = new Promise<void>((resolve, reject) => {
    resolveCompleted = resolve;
    rejectCompleted = reject;
  });
  let callCount = 0;

  async function run<T>(method: ScopedHasherMethod, operation: () => Promise<T>): Promise<T> {
    callCount += 1;
    if (callCount > 1) return operation();
    resolveEntered!(method);
    await startGate.promise;
    try {
      const result = await operation();
      resolveCompleted!();
      await returnGate.promise;
      return result;
    } catch (error: unknown) {
      rejectCompleted!(error);
      await returnGate.promise;
      throw error;
    }
  }

  const barrierHasher = {
    hash: (password: string): Promise<string> => run('hash', () => realHasher.hash(password)),
    verify: (password: string, record: string): Promise<boolean> =>
      run('verify', () => realHasher.verify(password, record)),
    verifyDummy: (password: string): Promise<void> =>
      run('verifyDummy', () => realHasher.verifyDummy(password)),
  };
  const module = await Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(ScryptPasswordHasher)
    .useValue(barrierHasher)
    .compile();
  const scopedApp = module.createNestApplication();
  configureApplication(scopedApp);
  await scopedApp.init();

  return {
    app: scopedApp,
    methodEntered,
    realKdfCompleted,
    releaseReturn: returnGate.release,
    releaseStart: startGate.release,
    close: async (): Promise<void> => {
      startGate.release();
      returnGate.release();
      await scopedApp.close();
    },
  };
}

function deferredGate(): DeferredGate {
  let released = false;
  let resolveGate: () => void;
  const promise = new Promise<void>((resolve) => {
    resolveGate = resolve;
  });
  return {
    promise,
    release: (): void => {
      if (released) return;
      released = true;
      resolveGate!();
    },
  };
}

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

function registerRequest(
  app: INestApplication,
  bootstrap: Bootstrap,
  email: string,
): Promise<Response> {
  return request(app.getHttpServer())
    .post('/api/v1/auth/register')
    .set('Origin', ORIGIN)
    .set('Cookie', bootstrap.cookie)
    .set('X-CSRF-Token', bootstrap.csrfToken)
    .send({ email, password: PASSWORD })
    .then((response) => response);
}

async function waitForSessionExpiry(
  source: DataSource,
  plan: IsolatedPostgresPlan,
  sessionId: string,
): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const rows = await source.query(
      `SELECT clock_timestamp() >= absolute_expires_at AS expired FROM "${plan.schemaName}".identity_sessions WHERE id = $1`,
      [sessionId],
    );
    const [row] = rows as readonly unknown[];
    if (
      typeof row === 'object' &&
      row !== null &&
      !Array.isArray(row) &&
      (row as Record<string, unknown>).expired === true
    ) {
      return;
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('Observer did not cross the preseeded PostgreSQL expiry.');
}

async function seedRegistrationThrottles(
  source: DataSource,
  count: number,
  state: ThrottleSeedState,
): Promise<readonly string[]> {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + (state === 'active' ? 15 : -15) * 60 * 1000);
  const windowStartedAt = new Date(now.getTime() + (state === 'active' ? 0 : -30) * 60 * 1000);
  const ids: string[] = [];
  for (let offset = 0; offset < count; offset += 500) {
    const batchSize = Math.min(500, count - offset);
    const rows = Array.from({ length: batchSize }, () => {
      const id = randomUUID();
      ids.push(id);
      return {
        id,
        keyHash: randomBytes(32).toString('hex'),
        windowStartedAt,
        expiresAt,
        attemptCount: 1,
      };
    });
    await source.getRepository(RegistrationThrottleEntity).insert(rows);
  }
  return ids;
}

async function countRegistrationThrottles(source: DataSource, schema: string): Promise<number> {
  const rows = await source.query(
    `SELECT count(*)::int AS count FROM "${schema}".identity_registration_throttles`,
  );
  const [row] = rows as readonly unknown[];
  if (typeof row !== 'object' || row === null || Array.isArray(row)) {
    throw new Error('Unexpected registration throttle count row.');
  }
  const count = (row as Record<string, unknown>).count;
  if (typeof count !== 'number') throw new Error('Unexpected registration throttle count.');
  return count;
}

async function seedLoginThrottles(
  source: DataSource,
  count: number,
  state: ThrottleSeedState,
): Promise<readonly string[]> {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + (state === 'active' ? 15 : -15) * 60 * 1000);
  const windowStartedAt = new Date(now.getTime() + (state === 'active' ? 0 : -30) * 60 * 1000);
  const ids: string[] = [];
  for (let offset = 0; offset < count; offset += 500) {
    const batchSize = Math.min(500, count - offset);
    const rows = Array.from({ length: batchSize }, () => {
      const id = randomUUID();
      ids.push(id);
      return {
        id,
        keyHash: randomBytes(32).toString('hex'),
        windowStartedAt,
        expiresAt,
        failureCount: 0,
      };
    });
    await source.getRepository(LoginThrottleEntity).insert(rows);
  }
  return ids;
}

async function countLoginThrottles(source: DataSource, schema: string): Promise<number> {
  const rows = await source.query(
    `SELECT count(*)::int AS count FROM "${schema}".identity_login_throttles`,
  );
  const [row] = rows as readonly unknown[];
  if (typeof row !== 'object' || row === null || Array.isArray(row)) {
    throw new Error('Unexpected login throttle count row.');
  }
  const count = (row as Record<string, unknown>).count;
  if (typeof count !== 'number') throw new Error('Unexpected login throttle count.');
  return count;
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

type TerminalPreAuthState = 'expired' | 'revoked';

async function insertTerminalPreAuthSession(
  source: DataSource,
  state: TerminalPreAuthState,
): Promise<SessionEntity> {
  const now = new Date();
  const expired = state === 'expired';
  return source.getRepository(SessionEntity).save({
    id: randomUUID(),
    userId: null,
    tokenHash: randomBytes(32).toString('hex'),
    csrfTokenHash: randomBytes(32).toString('hex'),
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

async function insertActivePreAuthPopulation(source: DataSource, count: number): Promise<string[]> {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 10 * 60 * 1000);
  const ids: string[] = [];
  for (let offset = 0; offset < count; offset += 500) {
    const batchSize = Math.min(500, count - offset);
    const rows = Array.from({ length: batchSize }, () => {
      const id = randomUUID();
      ids.push(id);
      return {
        id,
        userId: null,
        tokenHash: randomBytes(32).toString('hex'),
        csrfTokenHash: randomBytes(32).toString('hex'),
        state: 'pre_auth' as const,
        createdAt: now,
        lastSeenAt: now,
        absoluteExpiresAt: expiresAt,
        idleExpiresAt: expiresAt,
        revokedAt: null,
      };
    });
    await source.getRepository(SessionEntity).insert(rows);
  }
  return ids;
}

async function countBootstrapPopulation(source: DataSource, schema: string): Promise<number> {
  const rows = await source.query(
    `SELECT count(*)::int AS count FROM "${schema}".identity_sessions WHERE state = 'pre_auth' OR (state = 'revoked' AND user_id IS NULL)`,
  );
  const [row] = rows as readonly unknown[];
  if (typeof row !== 'object' || row === null || Array.isArray(row)) {
    throw new Error('Unexpected bootstrap population count.');
  }
  const value = (row as Record<string, unknown>).count;
  if (typeof value !== 'number') throw new Error('Unexpected bootstrap population count value.');
  return value;
}

async function countBootstrapCleanupEligibility(
  source: DataSource,
  schema: string,
): Promise<number> {
  const rows = await source.query(
    `SELECT count(*)::int AS count FROM "${schema}".identity_sessions WHERE (state = 'pre_auth' AND absolute_expires_at <= CURRENT_TIMESTAMP) OR (state = 'revoked' AND user_id IS NULL)`,
  );
  const [row] = rows as readonly unknown[];
  if (typeof row !== 'object' || row === null || Array.isArray(row)) {
    throw new Error('Unexpected bootstrap cleanup eligibility count.');
  }
  const value = (row as Record<string, unknown>).count;
  if (typeof value !== 'number')
    throw new Error('Unexpected bootstrap cleanup eligibility count value.');
  return value;
}

async function explain(source: DataSource, statement: string): Promise<string> {
  const rows = await source.query(`EXPLAIN ${statement}`);
  if (!Array.isArray(rows)) throw new Error('Unexpected PostgreSQL EXPLAIN rows.');
  const lines = rows.map((row) => {
    if (typeof row !== 'object' || row === null || Array.isArray(row)) {
      throw new Error('Unexpected PostgreSQL EXPLAIN row.');
    }
    const value = (row as Record<string, unknown>)['QUERY PLAN'];
    if (typeof value !== 'string') throw new Error('Unexpected PostgreSQL EXPLAIN value.');
    return value;
  });
  return lines.join('\n');
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
