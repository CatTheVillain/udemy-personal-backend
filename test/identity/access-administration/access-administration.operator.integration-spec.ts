import { execFile } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';
import { promisify } from 'node:util';

import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import request, { Response } from 'supertest';
import { DataSource } from 'typeorm';

import { AppModule } from '../../../src/app.module';
import { UserEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/user.entity';
import { configureApplication } from '../../../src/main';
import { createIdentityDataSource } from '../../../src/modules/identity/infrastructure/persistence/composition/identity-database-options';
import {
  assertStartedIsolatedPostgresRun,
  createIsolatedPostgresDatabaseOptions,
  createIsolatedPostgresEnvironment,
  createIsolatedPostgresPlan,
  IsolatedPostgresPlan,
  IsolatedPostgresRun,
  startIsolatedPostgres,
} from '../../support/isolated-postgres-harness';

const executeFile = promisify(execFile);
const ORIGIN = 'http://127.0.0.1:4173';
const PASSWORD = 'operator-test-password';
const D1_KEYS = [
  'IDENTITY_ACCESS_BOOTSTRAP_CREDENTIAL',
  'IDENTITY_ACCESS_RECOVERY_CREDENTIAL',
  'IDENTITY_ACCESS_OPERATOR_CREDENTIAL',
] as const;
const ENVIRONMENT_KEYS = [
  'DATABASE_HOST',
  'DATABASE_PORT',
  'DATABASE_USERNAME',
  'DATABASE_PASSWORD',
  'DATABASE_NAME',
  'DATABASE_SCHEMA',
  'IDENTITY_THROTTLE_HMAC_SECRET',
  'NODE_ENV',
  'CORS_ALLOWED_ORIGINS',
  ...D1_KEYS,
] as const;

type EnvironmentKey =
  | 'DATABASE_HOST'
  | 'DATABASE_PORT'
  | 'DATABASE_USERNAME'
  | 'DATABASE_PASSWORD'
  | 'DATABASE_NAME'
  | 'DATABASE_SCHEMA'
  | 'IDENTITY_THROTTLE_HMAC_SECRET'
  | 'NODE_ENV'
  | 'CORS_ALLOWED_ORIGINS'
  | 'IDENTITY_ACCESS_BOOTSTRAP_CREDENTIAL'
  | 'IDENTITY_ACCESS_RECOVERY_CREDENTIAL'
  | 'IDENTITY_ACCESS_OPERATOR_CREDENTIAL';
type OperatorPurpose = 'bootstrap' | 'recovery';
type OperatorRun = { readonly code: number; readonly output: string };
type LoginReceipt = { readonly cookie: string; readonly email: string };

describe('Identity access administration operator composition', () => {
  let plan: IsolatedPostgresPlan;
  let run: IsolatedPostgresRun;
  let observer: DataSource;

  beforeAll(async () => {
    plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(randomBytes(32).toString('hex'), await loopbackPort()),
    );
    run = await startIsolatedPostgres(plan);
    await run.migrate({ createDataSource: createIdentityDataSource });
    await assertStartedIsolatedPostgresRun(plan);
    observer = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
    await observer.initialize();
  });

  afterAll(async () => {
    try {
      if (observer.isInitialized) await observer.destroy();
    } finally {
      await run.cleanup();
    }
  });

  it('runs bootstrap through the production subprocess, rejects malformed credentials safely, and never exposes an HTTP capability route', async () => {
    const bootstrap = credential();
    const recovery = credential();
    const targetUserId = await insertUser(observer, 'operator-bootstrap@example.test');
    const commandId = randomUUID();
    const environment = operatorEnvironment(plan, bootstrap, recovery, bootstrap);

    const completed = await runOperator(
      validArguments('bootstrap', targetUserId, commandId),
      environment,
    );
    expect(completed).toEqual({ code: 0, output: 'access_administration_completed\n' });
    await expectAdministrator(observer, plan, targetUserId);

    const wrongCredential = credential();
    const rejected = await runOperator(
      validArguments('bootstrap', randomUUID(), randomUUID()),
      operatorEnvironment(plan, bootstrap, recovery, wrongCredential),
    );
    expect(rejected).toEqual({ code: 3, output: 'access_administration_unauthorized\n' });
    expect(rejected.output).not.toContain(wrongCredential);

    const missingInvocation = await runOperator(
      validArguments('bootstrap', randomUUID(), randomUUID()),
      operatorEnvironment(plan, bootstrap, recovery),
    );
    expect(missingInvocation).toEqual({
      code: 2,
      output: 'access_administration_invocation_invalid\n',
    });

    const malformed = await runOperator(
      [...validArguments('bootstrap', randomUUID(), randomUUID()), '--purpose', 'bootstrap'],
      operatorEnvironment(plan, bootstrap, recovery, bootstrap),
    );
    expect(malformed).toEqual({ code: 2, output: 'access_administration_invocation_invalid\n' });

    const unknown = await runOperator(
      [...validArguments('bootstrap', randomUUID(), randomUUID()), '--not-a-command', 'value'],
      operatorEnvironment(plan, bootstrap, recovery, bootstrap),
    );
    expect(unknown).toEqual({ code: 2, output: 'access_administration_invocation_invalid\n' });

    const missingExpected = operatorEnvironment(plan, bootstrap, recovery, bootstrap);
    delete missingExpected.IDENTITY_ACCESS_BOOTSTRAP_CREDENTIAL;
    const unavailableMissingExpected = await runOperator(
      validArguments('bootstrap', randomUUID(), randomUUID()),
      missingExpected,
    );
    expect(unavailableMissingExpected).toEqual({
      code: 2,
      output: 'access_administration_operator_unavailable\n',
    });

    const malformedExpected = operatorEnvironment(plan, 'short', recovery, bootstrap);
    const unavailableMalformedExpected = await runOperator(
      validArguments('bootstrap', randomUUID(), randomUUID()),
      malformedExpected,
    );
    expect(unavailableMalformedExpected).toEqual({
      code: 2,
      output: 'access_administration_operator_unavailable\n',
    });

    const unavailableEqualExpected = await runOperator(
      validArguments('bootstrap', randomUUID(), randomUUID()),
      operatorEnvironment(plan, bootstrap, bootstrap, bootstrap),
    );
    expect(unavailableEqualExpected).toEqual({
      code: 2,
      output: 'access_administration_operator_unavailable\n',
    });
  });

  it('starts the normal AppModule without D1 configuration and exposes no capability write route', async () => {
    const previous = captureEnvironment();
    applyApplicationEnvironment(plan);
    try {
      const app = await NestFactory.create(AppModule, { abortOnError: false, logger: false });
      try {
        configureApplication(app);
        await app.init();

        const document = await request(app.getHttpServer()).get('/api/v1/docs-json').expect(200);
        const paths = Object.keys(document.body.paths as Record<string, unknown>);
        expect(paths.some((path) => /capabilit|access|admin/i.test(path))).toBe(false);

        const login = await registerAndLogin(app);
        const response = await request(app.getHttpServer())
          .get('/api/v1/auth/me')
          .set('Cookie', login.cookie)
          .expect(200);
        expect(response.headers['cache-control']).toBe('no-store');
        expect(response.headers['set-cookie']).toBeUndefined();
        expect(response.body).toEqual({
          data: { id: expect.any(String), email: login.email, access: { capabilities: [] } },
        });
        expect(Object.keys(response.body.data).sort()).toEqual(['access', 'email', 'id']);
        expect(response.text).not.toMatch(
          /administrator|content_moderator|instructor|csrf|token|password/i,
        );
      } finally {
        await app.close();
      }
    } finally {
      restoreEnvironment(previous);
    }
  });
});

describe('Identity access administration recovery operator binding', () => {
  it('accepts a distinct recovery credential only for recovery on a fresh zero-administrator database', async () => {
    const plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(randomBytes(32).toString('hex'), await loopbackPort()),
    );
    const run = await startIsolatedPostgres(plan);
    let observer: DataSource | undefined;
    try {
      await run.migrate({ createDataSource: createIdentityDataSource });
      await assertStartedIsolatedPostgresRun(plan);
      observer = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
      await observer.initialize();
      const targetUserId = await insertUser(observer, 'operator-recovery@example.test');
      const bootstrap = credential();
      const recovery = credential();

      const mismatched = await runOperator(
        validArguments('recovery', targetUserId, randomUUID()),
        operatorEnvironment(plan, bootstrap, recovery, bootstrap),
      );
      expect(mismatched).toEqual({ code: 3, output: 'access_administration_unauthorized\n' });

      const completed = await runOperator(
        validArguments('recovery', targetUserId, randomUUID()),
        operatorEnvironment(plan, bootstrap, recovery, recovery),
      );
      expect(completed).toEqual({ code: 0, output: 'access_administration_completed\n' });
      const rows = await observer.query(
        `SELECT capability FROM "${plan.schemaName}"."identity_access_capabilities" WHERE user_id = $1 AND active = true`,
        [targetUserId],
      );
      expect(rows).toEqual([{ capability: 'administrator' }]);
    } finally {
      try {
        if (observer?.isInitialized) await observer.destroy();
      } finally {
        await run.cleanup();
      }
    }
  });
});

async function runOperator(
  argv: readonly string[],
  environment: NodeJS.ProcessEnv,
): Promise<OperatorRun> {
  try {
    const result = await executeFile(
      process.execPath,
      ['-r', 'ts-node/register', 'src/access-administration.ts', ...argv],
      { cwd: process.cwd(), env: environment, timeout: 60_000, windowsHide: true },
    );
    return { code: 0, output: `${result.stdout}${result.stderr}` };
  } catch (error: unknown) {
    if (!isExecFailure(error)) throw error;
    return { code: error.code, output: `${error.stdout}${error.stderr}` };
  }
}

function isExecFailure(error: unknown): error is {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
} {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof error.code === 'number' &&
    'stdout' in error &&
    typeof error.stdout === 'string' &&
    'stderr' in error &&
    typeof error.stderr === 'string'
  );
}

function validArguments(
  purpose: OperatorPurpose,
  targetUserId: string,
  commandId: string,
): string[] {
  return [
    '--purpose',
    purpose,
    '--target-user-id',
    targetUserId,
    '--command-id',
    commandId,
    '--reason',
    'independent operator integration proof',
    '--reference',
    'BE-BFI005-TE-OPERATOR-20261018-T1',
    '--credential-env',
    'IDENTITY_ACCESS_OPERATOR_CREDENTIAL',
  ];
}

function operatorEnvironment(
  plan: IsolatedPostgresPlan,
  bootstrap: string,
  recovery: string,
  invocation?: string,
): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {
    ...applicationEnvironment(plan),
    IDENTITY_ACCESS_BOOTSTRAP_CREDENTIAL: bootstrap,
    IDENTITY_ACCESS_RECOVERY_CREDENTIAL: recovery,
  };
  if (invocation !== undefined) environment.IDENTITY_ACCESS_OPERATOR_CREDENTIAL = invocation;
  return environment;
}

function applicationEnvironment(plan: IsolatedPostgresPlan): NodeJS.ProcessEnv {
  return {
    ...process.env,
    NODE_ENV: 'test',
    CORS_ALLOWED_ORIGINS: ORIGIN,
    IDENTITY_THROTTLE_HMAC_SECRET: credential(),
    DATABASE_HOST: plan.environment.IDENTITY_TEST_POSTGRES_HOST,
    DATABASE_PORT: plan.environment.IDENTITY_TEST_POSTGRES_PORT,
    DATABASE_USERNAME: plan.environment.IDENTITY_TEST_DATABASE_USER,
    DATABASE_PASSWORD: plan.environment.IDENTITY_TEST_DATABASE_PASSWORD,
    DATABASE_NAME: plan.databaseName,
    DATABASE_SCHEMA: plan.schemaName,
  };
}

function captureEnvironment(): Map<EnvironmentKey, string | undefined> {
  return new Map(ENVIRONMENT_KEYS.map((key) => [key, process.env[key]]));
}

function applyApplicationEnvironment(plan: IsolatedPostgresPlan): void {
  const environment = applicationEnvironment(plan);
  for (const key of ENVIRONMENT_KEYS) {
    if (isD1EnvironmentKey(key)) delete process.env[key];
    else process.env[key] = environment[key];
  }
}

function isD1EnvironmentKey(key: EnvironmentKey): boolean {
  return (
    key === 'IDENTITY_ACCESS_BOOTSTRAP_CREDENTIAL' ||
    key === 'IDENTITY_ACCESS_RECOVERY_CREDENTIAL' ||
    key === 'IDENTITY_ACCESS_OPERATOR_CREDENTIAL'
  );
}

function restoreEnvironment(previous: Map<EnvironmentKey, string | undefined>): void {
  for (const [key, value] of previous) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

async function insertUser(observer: DataSource, normalizedEmail: string): Promise<string> {
  const id = randomUUID();
  const now = new Date();
  const entity = new UserEntity();
  entity.id = id;
  entity.normalizedEmail = normalizedEmail;
  entity.passwordHash = 'operator-test-only-hash';
  entity.createdAt = now;
  entity.updatedAt = now;
  await observer.getRepository(UserEntity).save(entity);
  return id;
}

async function expectAdministrator(
  observer: DataSource,
  plan: IsolatedPostgresPlan,
  targetUserId: string,
): Promise<void> {
  const rows = await observer.query(
    `SELECT capability FROM "${plan.schemaName}"."identity_access_capabilities" WHERE user_id = $1 AND active = true`,
    [targetUserId],
  );
  expect(rows).toEqual([{ capability: 'administrator' }]);
}

async function registerAndLogin(app: INestApplication): Promise<LoginReceipt> {
  const email = `operator-app-${randomBytes(8).toString('hex')}@example.test`;
  const registration = await bootstrap(app);
  await request(app.getHttpServer())
    .post('/api/v1/auth/register')
    .set('Origin', ORIGIN)
    .set('Cookie', registration.cookie)
    .set('X-CSRF-Token', registration.csrfToken)
    .send({ email, password: PASSWORD })
    .expect(201);
  const preLogin = await bootstrap(app);
  const login = await request(app.getHttpServer())
    .post('/api/v1/auth/login')
    .set('Origin', ORIGIN)
    .set('Cookie', preLogin.cookie)
    .set('X-CSRF-Token', preLogin.csrfToken)
    .send({ email, password: PASSWORD })
    .expect(200);
  return { cookie: cookie(login), email };
}

async function bootstrap(
  app: INestApplication,
): Promise<{ readonly cookie: string; readonly csrfToken: string }> {
  const response = await request(app.getHttpServer()).get('/api/v1/auth/csrf').expect(200);
  const csrfToken = response.body?.data?.csrfToken;
  if (typeof csrfToken !== 'string') throw new Error('Expected CSRF token.');
  return { cookie: cookie(response), csrfToken };
}

function cookie(response: Response): string {
  const values = response.headers['set-cookie'];
  if (!Array.isArray(values) || typeof values[0] !== 'string')
    throw new Error('Expected session cookie.');
  const value = values[0].split(';')[0];
  if (value === undefined || !value.startsWith('__Host-session='))
    throw new Error('Invalid session cookie.');
  return value;
}

function credential(): string {
  return randomBytes(32).toString('base64url');
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
