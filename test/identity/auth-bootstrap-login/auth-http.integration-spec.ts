import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';

import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, OpenAPIObject, SwaggerModule } from '@nestjs/swagger';
import request, { Response } from 'supertest';
import { DataSource } from 'typeorm';

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

  it('returns public busy for a contested first-seen registration key without creating a second admission', async () => {
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
    expect(responses.map((response) => response.status).sort()).toEqual([201, 503]);
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
    ).toMatchObject({ attemptCount: 1 });
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
        expect(receipt.response.body.code).toBe('throttle_busy');
        expect(receipt.response.headers['retry-after']).toBe('1');
        expect(receipt.response.headers['content-type']).toContain('application/problem+json');
        expect(receipt.response.headers['access-control-expose-headers']).toContain('Retry-After');
        expect(session).toMatchObject({ state: 'pre_auth', revokedAt: null });
      }
    }
  });

  it('uses canonical email and socket address for one first-seen registration admission despite forwarded headers', async () => {
    const attempts = [
      { email: ' Socket@Example.Test ', forwarded: '203.0.113.1' },
      { email: 'socket@example.test', forwarded: '198.51.100.2' },
      { email: 'socket@example.test ', forwarded: '192.0.2.3' },
    ];
    const bootstraps: BootstrapReceipt[] = [];
    for (const _attempt of attempts) bootstraps.push(await bootstrapCsrf(app));
    const requests = await Promise.all(
      attempts.map(({ email, forwarded }, index) => {
        const bootstrap = bootstraps[index];
        if (bootstrap === undefined) throw new Error('Missing concurrent registration bootstrap.');
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
    expect(requests.map((response) => response.status).sort()).toEqual([201, 503, 503]);
    const key = createThrottleKey(
      IdentityAuthConfig.from(process.env),
      'registration',
      'socket@example.test',
      '127.0.0.1',
    );
    if (key === null) throw new Error('Expected loopback registration throttle key.');
    expect(
      await observer.getRepository(RegistrationThrottleEntity).findOneByOrFail({ keyHash: key }),
    ).toMatchObject({ attemptCount: 1 });
    for (const response of requests.filter((response) => response.status === 503)) {
      expect(response.body.code).toBe('throttle_busy');
      expect(response.headers['retry-after']).toBe('1');
      expect(response.headers['content-type']).toContain('application/problem+json');
      expect(response.headers['access-control-expose-headers']).toContain('Retry-After');
    }
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

  it('uses generic credentials errors and rejects even valid credentials after five failures', async () => {
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
      .expect(429);
    expect(validResponse.body.code).toBe('login_rate_limited');
    const throttles = await observer.getRepository(LoginThrottleEntity).find();
    expect(throttles.filter((throttle) => throttle.failureCount === 5)).toHaveLength(1);
    expect(
      await observer.getRepository(SessionEntity).findOneByOrFail({
        tokenHash: sha256(cookieValue(valid.cookie)),
      }),
    ).toMatchObject({ state: 'pre_auth', revokedAt: null });
  });

  it.each([
    { purpose: 'registration' as const, count: 3, retryAfterSeconds: 2 },
    { purpose: 'login' as const, count: 5, retryAfterSeconds: 1 },
  ])(
    'returns the durable $purpose retry window without confusing password-work rejection',
    async ({ purpose, count, retryAfterSeconds }) => {
      const now = new Date('2031-01-01T00:00:00.000Z');
      const clock = app.get<IdentityClock>(IDENTITY_CLOCK);
      const clockSpy = jest.spyOn(clock, 'now').mockReturnValue(now);
      const email = `durable-retry-${purpose}-${randomBytes(6).toString('hex')}@example.test`;
      const key = createThrottleKey(
        IdentityAuthConfig.from(process.env),
        purpose,
        email,
        '127.0.0.1',
      );
      if (key === null) throw new Error('Expected loopback durable throttle key.');
      const expiresAt = new Date(now.getTime() + (retryAfterSeconds === 1 ? 1 : 1001));
      const repository =
        purpose === 'registration'
          ? observer.getRepository(RegistrationThrottleEntity)
          : observer.getRepository(LoginThrottleEntity);
      try {
        await repository.insert(
          purpose === 'registration'
            ? {
                id: randomUUID(),
                keyHash: key,
                windowStartedAt: now,
                expiresAt,
                attemptCount: count,
              }
            : {
                id: randomUUID(),
                keyHash: key,
                windowStartedAt: now,
                expiresAt,
                failureCount: count,
              },
        );
        const bootstrap = await bootstrapCsrf(app);
        const limited = await request(app.getHttpServer())
          .post(`/api/v1/auth/${purpose === 'registration' ? 'register' : 'login'}`)
          .set('Origin', ORIGIN)
          .set('Cookie', bootstrap.cookie)
          .set('X-CSRF-Token', bootstrap.csrfToken)
          .send({ email, password: 'wrong literal password' });

        expect(limited.status).toBe(429);
        expect(limited.body.code).toBe(
          purpose === 'registration' ? 'registration_rate_limited' : 'login_rate_limited',
        );
        expect(limited.body.code).not.toBe('password_work_rate_limited');

        await repository.update(
          { keyHash: key },
          {
            windowStartedAt: new Date(now.getTime() - 15 * 60 * 1000 - 1),
            expiresAt: new Date(now.getTime() - 1),
          },
        );
        const expiredWindowBootstrap = await bootstrapCsrf(app);
        const admitted = await request(app.getHttpServer())
          .post(`/api/v1/auth/${purpose === 'registration' ? 'register' : 'login'}`)
          .set('Origin', ORIGIN)
          .set('Cookie', expiredWindowBootstrap.cookie)
          .set('X-CSRF-Token', expiredWindowBootstrap.csrfToken)
          .send({ email, password: 'wrong literal password' });
        expect(admitted.status).toBe(purpose === 'registration' ? 201 : 401);
        if (purpose === 'login') expect(admitted.body.code).toBe('credentials_invalid');
        expect(limited.headers['retry-after']).toBe(String(retryAfterSeconds));
      } finally {
        clockSpy.mockRestore();
        await repository.delete({ keyHash: key });
      }
    },
  );

  it('publishes every auth Problem Details response with its exact media type, description, and headers', () => {
    const document: OpenAPIObject = SwaggerModule.createDocument(
      app,
      new DocumentBuilder().setTitle('Udemy Personal Backend').build(),
    );
    const expected = [
      {
        path: '/api/v1/auth/csrf',
        method: 'get' as const,
        status: '401',
        description:
          'Invalid, expired, revoked, or logged-out supplied session; clears the supplied cookie.',
        headers: ['Set-Cookie'],
      },
      {
        path: '/api/v1/auth/csrf',
        method: 'get' as const,
        status: '403',
        description: 'Disallowed origin',
        headers: [],
      },
      {
        path: '/api/v1/auth/csrf',
        method: 'get' as const,
        status: '429',
        description: 'CSRF bootstrap source quota is exhausted (csrf_bootstrap_rate_limited).',
        headers: ['Retry-After'],
      },
      {
        path: '/api/v1/auth/csrf',
        method: 'get' as const,
        status: '503',
        description:
          'CSRF bootstrap admission is temporarily unavailable (csrf_bootstrap_unavailable, csrf_bootstrap_busy, or csrf_bootstrap_capacity_unavailable).',
        headers: ['Retry-After'],
      },
      {
        path: '/api/v1/auth/register',
        method: 'post' as const,
        status: '400',
        description: 'Invalid request body',
        headers: [],
      },
      {
        path: '/api/v1/auth/register',
        method: 'post' as const,
        status: '401',
        description: 'Invalid pre-auth session; clears the supplied cookie.',
        headers: ['Set-Cookie'],
      },
      {
        path: '/api/v1/auth/register',
        method: 'post' as const,
        status: '403',
        description: 'Origin or CSRF validation failed',
        headers: [],
      },
      {
        path: '/api/v1/auth/register',
        method: 'post' as const,
        status: '409',
        description: 'The email is already registered',
        headers: [],
      },
      {
        path: '/api/v1/auth/register',
        method: 'post' as const,
        status: '429',
        description: 'Registration or password-work throttle is exhausted',
        headers: ['Retry-After'],
      },
      {
        path: '/api/v1/auth/register',
        method: 'post' as const,
        status: '503',
        description: 'Password-work or durable throttle capacity is temporarily unavailable',
        headers: ['Retry-After'],
      },
      {
        path: '/api/v1/auth/login',
        method: 'post' as const,
        status: '400',
        description: 'Invalid request body',
        headers: [],
      },
      {
        path: '/api/v1/auth/login',
        method: 'post' as const,
        status: '401',
        description:
          'Credentials are invalid or pre-auth is invalid. The cookie is cleared only for invalid pre-auth.',
        headers: ['Set-Cookie'],
      },
      {
        path: '/api/v1/auth/login',
        method: 'post' as const,
        status: '403',
        description: 'Origin or CSRF validation failed',
        headers: [],
      },
      {
        path: '/api/v1/auth/login',
        method: 'post' as const,
        status: '429',
        description: 'Login or password-work throttle is exhausted',
        headers: ['Retry-After'],
      },
      {
        path: '/api/v1/auth/login',
        method: 'post' as const,
        status: '503',
        description: 'Password-work or durable throttle capacity is temporarily unavailable',
        headers: ['Retry-After'],
      },
    ] as const;

    for (const expectedResponse of expected) {
      const operation = document.paths[expectedResponse.path]?.[expectedResponse.method];
      const response = operation?.responses[expectedResponse.status];
      if (response === undefined || '$ref' in response) {
        throw new Error(
          `Missing inline ${expectedResponse.status} response for ${expectedResponse.path}.`,
        );
      }
      expect(response.description).toBe(expectedResponse.description);
      expect(response.content?.['application/problem+json']?.schema).toEqual({
        $ref: '#/components/schemas/ProblemDetailsDto',
      });
      expect(response.content?.['application/json']).toBeUndefined();
      expect(Object.keys(response.headers ?? {}).sort()).toEqual(
        [...expectedResponse.headers].sort(),
      );
      for (const headerName of expectedResponse.headers) {
        const header = response.headers?.[headerName];
        if (header === undefined || '$ref' in header) {
          throw new Error(
            `Missing ${headerName} header for ${expectedResponse.path} ${expectedResponse.status}.`,
          );
        }
        expect(header.schema).toMatchObject({ type: 'string' });
      }
    }
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
