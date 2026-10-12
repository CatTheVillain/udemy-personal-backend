import { randomBytes, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createServer } from 'node:net';
import { promisify } from 'node:util';

import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import request from 'supertest';
import { DataSource } from 'typeorm';

import { AppModule } from '../../src/app.module';
import {
  IDENTITY_TRANSACTION_PORT,
  IdentityTransactionPort,
} from '../../src/modules/identity/application/ports/identity.ports';
import { UserEntity } from '../../src/modules/identity/infrastructure/persistence/entities/user.entity';
import { createIdentityDataSource } from '../../src/shared/database/identity-database-options';
import { configureApplication } from '../../src/main';
import {
  assertStartedIsolatedPostgresRun,
  createIsolatedPostgresDatabaseOptions,
  createIsolatedPostgresEnvironment,
  createIsolatedPostgresPlan,
  IsolatedPostgresPlan,
  startIsolatedPostgres,
} from '../support/isolated-postgres-harness';

const DATABASE_KEYS = [
  'DATABASE_HOST',
  'DATABASE_PORT',
  'DATABASE_USERNAME',
  'DATABASE_PASSWORD',
  'DATABASE_NAME',
  'DATABASE_SCHEMA',
] as const;
const IDENTITY_AUTH_KEYS = ['IDENTITY_THROTTLE_HMAC_SECRET'] as const;
const APPLICATION_KEYS = [...DATABASE_KEYS, ...IDENTITY_AUTH_KEYS] as const;
const executeFile = promisify(execFile);
type DatabaseKey =
  | 'DATABASE_HOST'
  | 'DATABASE_PORT'
  | 'DATABASE_USERNAME'
  | 'DATABASE_PASSWORD'
  | 'DATABASE_NAME'
  | 'DATABASE_SCHEMA';
type ApplicationKey = DatabaseKey | 'IDENTITY_THROTTLE_HMAC_SECRET';
type ClosableApplication = Pick<INestApplication, 'close'>;
type DestroyableDataSource = Pick<DataSource, 'destroy' | 'isInitialized'>;

describe('Identity AppModule database composition', () => {
  it('fails missing database configuration before TypeORM opens a connection', async () => {
    const previous = captureDatabaseEnvironment();
    const initialize = jest.spyOn(DataSource.prototype, 'initialize');
    try {
      clearDatabaseEnvironment();
      await expect(
        NestFactory.create(AppModule, { abortOnError: false, logger: false }),
      ).rejects.toThrow('Invalid database configuration.');
      expect(initialize).not.toHaveBeenCalled();
    } finally {
      initialize.mockRestore();
      restoreDatabaseEnvironment(previous);
    }
  });

  it('closes the app even when initialized observer cleanup fails', async () => {
    const observer: DestroyableDataSource = {
      destroy: jest.fn().mockRejectedValue(new Error('observer cleanup failed')),
      isInitialized: true,
    };
    const app: ClosableApplication = { close: jest.fn().mockResolvedValue(undefined) };

    await expect(closeApplicationResources(observer, app)).rejects.toThrow(
      'observer cleanup failed',
    );
    expect(observer.destroy).toHaveBeenCalledTimes(1);
    expect(app.close).toHaveBeenCalledTimes(1);
  });

  it('composes AppModule with an isolated database and resolves the named transaction port', async () => {
    const plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(
        randomBytes(32).toString('hex'),
        await selectLoopbackPort(),
      ),
    );
    const run = await startIsolatedPostgres(plan);
    try {
      await run.migrate({ createDataSource: createIdentityDataSource });
      await assertStartedIsolatedPostgresRun(plan);
      await withDatabaseEnvironment(plan, async () => {
        await runStockMigrationCli(plan);
        const app = await NestFactory.create(AppModule, { abortOnError: false, logger: false });
        const observer = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
        try {
          configureApplication(app);
          await app.init();
          await request(app.getHttpServer())
            .get('/api/v1/hello')
            .expect(200)
            .expect({ data: { message: 'Hello World!' } });
          await observer.initialize();
          const version = await readPostgresVersion(observer);
          expect(version.number).toBe('180004');
          expect(version.full).toContain('18.4');
          const transaction = app.get<IdentityTransactionPort>(IDENTITY_TRANSACTION_PORT);
          const now = new Date();
          const userId = randomUUID();
          await transaction.run({
            execute: async (scope) => {
              await scope.users.insert({
                id: userId,
                normalizedEmail: 'app-module@example.test',
                passwordHash: 'test-only-hash',
                createdAt: now,
                updatedAt: now,
              });
            },
          });
          const stored = await observer.getRepository(UserEntity).findOneByOrFail({ id: userId });
          expect(stored).toMatchObject({
            id: userId,
            normalizedEmail: 'app-module@example.test',
            passwordHash: 'test-only-hash',
            createdAt: now,
            updatedAt: now,
          });
        } finally {
          await closeApplicationResources(observer, app);
        }
      });
    } finally {
      await run.cleanup();
    }
  });
});

function captureDatabaseEnvironment(): Map<ApplicationKey, string | undefined> {
  return new Map(APPLICATION_KEYS.map((key) => [key, process.env[key]]));
}

function clearDatabaseEnvironment(): void {
  for (const key of DATABASE_KEYS) delete process.env[key];
  process.env.IDENTITY_THROTTLE_HMAC_SECRET = randomBytes(32).toString('base64url');
}

function restoreDatabaseEnvironment(previous: Map<ApplicationKey, string | undefined>): void {
  for (const key of APPLICATION_KEYS) {
    const value = previous.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

async function withDatabaseEnvironment(
  plan: IsolatedPostgresPlan,
  action: () => Promise<void>,
): Promise<void> {
  const previous = captureDatabaseEnvironment();
  try {
    process.env.DATABASE_HOST = plan.environment.IDENTITY_TEST_POSTGRES_HOST;
    process.env.DATABASE_PORT = plan.environment.IDENTITY_TEST_POSTGRES_PORT;
    process.env.DATABASE_USERNAME = plan.environment.IDENTITY_TEST_DATABASE_USER;
    process.env.DATABASE_PASSWORD = plan.environment.IDENTITY_TEST_DATABASE_PASSWORD;
    process.env.DATABASE_NAME = plan.databaseName;
    process.env.DATABASE_SCHEMA = plan.schemaName;
    process.env.IDENTITY_THROTTLE_HMAC_SECRET = randomBytes(32).toString('base64url');
    await action();
  } finally {
    restoreDatabaseEnvironment(previous);
  }
}

async function closeApplicationResources(
  observer: DestroyableDataSource,
  app: ClosableApplication,
): Promise<void> {
  const results = await Promise.allSettled([closeObserver(observer), app.close()]);
  const failures = results.flatMap((result) =>
    result.status === 'rejected' ? [result.reason] : [],
  );
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, 'Application cleanup failed.');
}

async function closeObserver(observer: DestroyableDataSource): Promise<void> {
  if (observer.isInitialized) await observer.destroy();
}

async function runStockMigrationCli(plan: IsolatedPostgresPlan): Promise<void> {
  const environment = {
    ...process.env,
    DATABASE_HOST: plan.environment.IDENTITY_TEST_POSTGRES_HOST,
    DATABASE_PORT: plan.environment.IDENTITY_TEST_POSTGRES_PORT,
    DATABASE_USERNAME: plan.environment.IDENTITY_TEST_DATABASE_USER,
    DATABASE_PASSWORD: plan.environment.IDENTITY_TEST_DATABASE_PASSWORD,
    DATABASE_NAME: plan.databaseName,
    DATABASE_SCHEMA: plan.schemaName,
  };
  try {
    await executeFile(
      process.execPath,
      [
        'node_modules/typeorm/cli-ts-node-commonjs.js',
        'migration:run',
        '-d',
        'src/modules/identity/infrastructure/persistence/identity-data-source.ts',
      ],
      { cwd: process.cwd(), env: environment, timeout: 60_000, windowsHide: true },
    );
  } catch {
    throw new Error('Stock identity migration CLI failed for the isolated test run.');
  }
}

type PostgresVersionReceipt = {
  readonly full: string;
  readonly number: string;
};

async function readPostgresVersion(source: DataSource): Promise<PostgresVersionReceipt> {
  const rows = await source.query(
    "SELECT current_setting('server_version') AS full, current_setting('server_version_num') AS number",
  );
  if (!Array.isArray(rows) || rows.length !== 1) {
    throw new Error('Unexpected PostgreSQL version result.');
  }
  const row = rows[0];
  if (typeof row !== 'object' || row === null || Array.isArray(row)) {
    throw new Error('Unexpected PostgreSQL version row.');
  }
  const receipt = row as Record<string, unknown>;
  if (typeof receipt.full !== 'string' || typeof receipt.number !== 'string') {
    throw new Error('Unexpected PostgreSQL version value.');
  }
  return { full: receipt.full, number: receipt.number };
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
