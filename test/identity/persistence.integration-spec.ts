import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';

import { DataSource } from 'typeorm';

import { IdentityTransactionScope } from '../../src/modules/identity/application/ports/identity.ports';
import {
  LoginThrottle,
  RegistrationThrottle,
  Session,
  User,
} from '../../src/modules/identity/domain/identity.types';
import { UserEntity } from '../../src/modules/identity/infrastructure/persistence/entities/user.entity';
import { TypeOrmIdentityTransactionAdapter } from '../../src/modules/identity/infrastructure/persistence/typeorm-identity-transaction.adapter';
import { createIdentityDataSource } from '../../src/shared/database/identity-database-options';
import {
  assertSafeCleanupScope,
  assertStartedIsolatedPostgresRun,
  createIsolatedPostgresDatabaseOptions,
  createIsolatedPostgresEnvironment,
  createIsolatedPostgresPlan,
  IsolatedPostgresEnvironment,
  IsolatedPostgresPlan,
  IsolatedPostgresResource,
  prepareIsolatedPostgresRun,
  startIsolatedPostgres,
} from '../support/isolated-postgres-harness';
import {
  createOwnedResource,
  IsolatedPostgresPreflightSpy,
} from '../fixtures/isolated-postgres.fixture';

const RUN_ID = 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0';
const IDENTITY_CONSTRAINT_NAMES = [
  'uq_identity_user_normalized_email',
  'chk_identity_user_normalized_email',
  'uq_identity_session_token_hash',
  'chk_identity_session_lifecycle',
  'chk_identity_session_expiry',
  'chk_identity_session_hashes',
  'uq_identity_registration_throttle_key_window',
  'chk_identity_registration_throttle_window',
  'uq_identity_login_throttle_key_window',
  'chk_identity_login_throttle_window',
] as const;

describe('Identity isolated PostgreSQL harness controls', () => {
  it('rejects a non-test environment before inspection or a possible service effect', async () => {
    const environment = createIsolatedPostgresEnvironment(RUN_ID, 45_321);
    const unsafeEnvironment = replaceEnvironment(environment, { NODE_ENV: 'production' });
    const operations = new IsolatedPostgresPreflightSpy([]);

    await expect(prepareIsolatedPostgresRun(unsafeEnvironment, operations)).rejects.toThrow(
      'Unsafe isolated PostgreSQL configuration: NODE_ENV.',
    );
    expect(operations.inspections).toBe(0);
  });

  it('rejects a shared database name before inspection or a possible service effect', async () => {
    const environment = createIsolatedPostgresEnvironment(RUN_ID, 45_322);
    const unsafeEnvironment = replaceEnvironment(environment, {
      IDENTITY_TEST_DATABASE: 'postgres',
    });
    const operations = new IsolatedPostgresPreflightSpy([]);

    await expect(prepareIsolatedPostgresRun(unsafeEnvironment, operations)).rejects.toThrow(
      'Unsafe isolated PostgreSQL configuration: IDENTITY_TEST_DATABASE.',
    );
    expect(operations.inspections).toBe(0);
  });

  it('rejects unsafe generated identity fields and weak credentials before inspection', async () => {
    const environment = createIsolatedPostgresEnvironment(RUN_ID, 45_327);
    const unsafeEnvironments: readonly IsolatedPostgresEnvironment[] = [
      replaceEnvironment(environment, { IDENTITY_TEST_RUN_ID: 'unsafe' }),
      replaceEnvironment(environment, { IDENTITY_TEST_POSTGRES_HOST: 'localhost' }),
      replaceEnvironment(environment, { IDENTITY_TEST_DATABASE_USER: 'shared_user' }),
      replaceEnvironment(environment, { IDENTITY_TEST_SCHEMA: 'public' }),
      replaceEnvironment(environment, { COMPOSE_PROJECT_NAME: 'shared-project' }),
      replaceEnvironment(environment, { IDENTITY_TEST_NETWORK: 'shared-network' }),
      replaceEnvironment(environment, { IDENTITY_TEST_VOLUME: 'shared-volume' }),
      replaceEnvironment(environment, { IDENTITY_TEST_DATABASE_PASSWORD: 'weak' }),
    ];

    for (const unsafeEnvironment of unsafeEnvironments) {
      const operations = new IsolatedPostgresPreflightSpy([]);

      await expect(prepareIsolatedPostgresRun(unsafeEnvironment, operations)).rejects.toThrow();
      expect(operations.inspections).toBe(0);
    }
  });

  it('rejects an existing generated resource before any later startup step', async () => {
    const environment = createIsolatedPostgresEnvironment(RUN_ID, 45_323);
    const plan = createIsolatedPostgresPlan(environment);
    const collision = createOwnedResource(plan, 'volume');
    const operations = new IsolatedPostgresPreflightSpy([collision]);

    await expect(prepareIsolatedPostgresRun(environment, operations)).rejects.toThrow(
      'Refusing isolated PostgreSQL startup because a generated resource already exists.',
    );
    expect(operations.inspections).toBe(1);
  });

  it('accepts only the generated loopback resource plan when no collision is observed', async () => {
    const environment = createIsolatedPostgresEnvironment(RUN_ID, 45_324);
    const operations = new IsolatedPostgresPreflightSpy([]);

    const plan = await prepareIsolatedPostgresRun(environment, operations);

    expect(plan.environment.IDENTITY_TEST_POSTGRES_HOST).toBe('127.0.0.1');
    expect(plan.environment.NODE_ENV).toBe('test');
    expect(plan.databaseName).toBe(plan.environment.IDENTITY_TEST_DATABASE);
    expect(plan.schemaName).toBe(plan.environment.IDENTITY_TEST_SCHEMA);
    expect(operations.inspections).toBe(1);
  });

  it('permits cleanup only for the complete exact labeled resource set', () => {
    const plan = createIsolatedPostgresPlan(createIsolatedPostgresEnvironment(RUN_ID, 45_325));
    const ownedResources = createOwnedResources(plan);

    expect(() => assertSafeCleanupScope(plan, ownedResources)).not.toThrow();
  });

  it('rejects cleanup when a resource is not owned by the current run', () => {
    const plan = createIsolatedPostgresPlan(createIsolatedPostgresEnvironment(RUN_ID, 45_326));
    const ownedResources = createOwnedResources(plan);
    const unsafeResources = ownedResources.map((resource) => corruptContainerLabel(resource));

    expect(() => assertSafeCleanupScope(plan, unsafeResources)).toThrow(
      'Refusing cleanup outside the exact isolated PostgreSQL run.',
    );
  });

  it('rejects duplicate, incomplete, and extra cleanup resource sets', () => {
    const plan = createIsolatedPostgresPlan(createIsolatedPostgresEnvironment(RUN_ID, 45_328));
    const container = createOwnedResource(plan, 'container');
    const network = createOwnedResource(plan, 'network');
    const volume = createOwnedResource(plan, 'volume');

    expect(() => assertSafeCleanupScope(plan, [container, container, volume])).toThrow();
    expect(() => assertSafeCleanupScope(plan, [container, network])).toThrow();
    expect(() => assertSafeCleanupScope(plan, [container, network, volume, container])).toThrow();
  });
});

describe('Identity persistence migration behavior', () => {
  it('rejects a duplicate normalized email after the forward migration', async () => {
    const environment = createIsolatedPostgresEnvironment(
      randomBytes(32).toString('hex'),
      await selectLoopbackPort(),
    );
    const plan = createIsolatedPostgresPlan(environment);
    const run = await startIsolatedPostgres(plan);

    try {
      await run.migrate({ createDataSource: createIdentityDataSource });
      await assertStartedIsolatedPostgresRun(plan);
      const source = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
      await source.initialize();
      try {
        const constraints = await source.query(
          'SELECT conname FROM pg_constraint WHERE connamespace = $1::regnamespace ORDER BY conname',
          [plan.schemaName],
        );
        expect(constraints.map(readConstraintName)).toEqual(
          expect.arrayContaining(IDENTITY_CONSTRAINT_NAMES),
        );
        const users = source.getRepository(UserEntity);
        await users.insert(createUserEntity('student@example.test'));
        await expect(users.insert(createUserEntity('student@example.test'))).rejects.toMatchObject({
          code: '23505',
        });
      } finally {
        await source.destroy();
      }
    } finally {
      await run.cleanup();
    }
  });

  it('enforces every named identity invariant against paired valid and malformed rows', async () => {
    const plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(
        randomBytes(32).toString('hex'),
        await selectLoopbackPort(),
      ),
    );
    const run = await startIsolatedPostgres(plan);
    try {
      await run.migrate({ createDataSource: createIdentityDataSource });
      const source = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
      await source.initialize();
      try {
        const now = new Date();
        const later = new Date(now.getTime() + 60_000);
        const session = createSessionRow(now, later);
        await insertUserRow(source, plan.schemaName, randomUUID(), 'student@example.test', now);
        await expectConstraintViolation(
          () => insertUserRow(source, plan.schemaName, randomUUID(), 'student@example.test', now),
          '23505',
          'uq_identity_user_normalized_email',
        );
        await expectConstraintViolation(
          () => insertUserRow(source, plan.schemaName, randomUUID(), ' Student@example.test', now),
          '23514',
          'chk_identity_user_normalized_email',
        );
        await expectConstraintViolation(
          () => insertUserRow(source, plan.schemaName, randomUUID(), 'Student@example.test', now),
          '23514',
          'chk_identity_user_normalized_email',
        );
        await expectConstraintViolation(
          () => insertUserRow(source, plan.schemaName, randomUUID(), '', now),
          '23514',
          'chk_identity_user_normalized_email',
        );
        await insertSessionRow(source, plan.schemaName, session);
        await expectConstraintViolation(
          () =>
            insertSessionRow(source, plan.schemaName, {
              ...createSessionRow(now, later),
              tokenHash: session.tokenHash,
            }),
          '23505',
          'uq_identity_session_token_hash',
        );
        await expectConstraintViolation(
          () =>
            insertSessionRow(source, plan.schemaName, {
              ...createSessionRow(now, later),
              userId: randomUUID(),
            }),
          '23514',
          'chk_identity_session_lifecycle',
        );
        await expectConstraintViolation(
          () =>
            insertSessionRow(source, plan.schemaName, {
              ...createSessionRow(now, later),
              revokedAt: now,
            }),
          '23514',
          'chk_identity_session_lifecycle',
        );
        await expectConstraintViolation(
          () =>
            insertSessionRow(source, plan.schemaName, {
              ...createSessionRow(now, later),
              state: 'authenticated',
            }),
          '23514',
          'chk_identity_session_lifecycle',
        );
        await expectConstraintViolation(
          () =>
            insertSessionRow(source, plan.schemaName, {
              ...createSessionRow(now, later),
              state: 'unknown',
            }),
          '23514',
          'chk_identity_session_lifecycle',
        );
        await expectConstraintViolation(
          () =>
            insertSessionRow(source, plan.schemaName, {
              ...createSessionRow(now, later),
              lastSeenAt: later,
            }),
          '23514',
          'chk_identity_session_expiry',
        );
        await expectConstraintViolation(
          () =>
            insertSessionRow(source, plan.schemaName, {
              ...createSessionRow(now, later),
              createdAt: new Date(now.getTime() + 1),
            }),
          '23514',
          'chk_identity_session_expiry',
        );
        await expectConstraintViolation(
          () =>
            insertSessionRow(source, plan.schemaName, {
              ...createSessionRow(now, later),
              idleExpiresAt: new Date(later.getTime() + 1),
            }),
          '23514',
          'chk_identity_session_expiry',
        );
        await expectConstraintViolation(
          () =>
            insertSessionRow(source, plan.schemaName, {
              ...createSessionRow(now, later),
              tokenHash: 'z'.repeat(64),
            }),
          '23514',
          'chk_identity_session_hashes',
        );
        await expectConstraintViolation(
          () =>
            insertSessionRow(source, plan.schemaName, {
              ...createSessionRow(now, later),
              csrfTokenHash: 'z'.repeat(64),
            }),
          '23514',
          'chk_identity_session_hashes',
        );
        const registration = createThrottleRow(now, later, 'c'.repeat(64), 0);
        await insertRegistrationThrottleRow(source, plan.schemaName, registration);
        await expectConstraintViolation(
          () =>
            insertRegistrationThrottleRow(source, plan.schemaName, {
              ...createThrottleRow(now, later, registration.keyHash, 0),
              windowStartedAt: registration.windowStartedAt,
            }),
          '23505',
          'uq_identity_registration_throttle_key_window',
        );
        await expectConstraintViolation(
          () =>
            insertRegistrationThrottleRow(
              source,
              plan.schemaName,
              createThrottleRow(now, later, 'z'.repeat(64), 0),
            ),
          '23514',
          'chk_identity_registration_throttle_window',
        );
        await expectConstraintViolation(
          () =>
            insertRegistrationThrottleRow(
              source,
              plan.schemaName,
              createThrottleRow(now, later, 'e'.repeat(64), -1),
            ),
          '23514',
          'chk_identity_registration_throttle_window',
        );
        await expectConstraintViolation(
          () =>
            insertRegistrationThrottleRow(
              source,
              plan.schemaName,
              createThrottleRow(now, now, 'f'.repeat(64), 0),
            ),
          '23514',
          'chk_identity_registration_throttle_window',
        );
        const login = createThrottleRow(now, later, 'd'.repeat(64), 0);
        await insertLoginThrottleRow(source, plan.schemaName, login);
        await expectConstraintViolation(
          () =>
            insertLoginThrottleRow(source, plan.schemaName, {
              ...createThrottleRow(now, later, login.keyHash, 0),
              windowStartedAt: login.windowStartedAt,
            }),
          '23505',
          'uq_identity_login_throttle_key_window',
        );
        await expectConstraintViolation(
          () =>
            insertLoginThrottleRow(
              source,
              plan.schemaName,
              createThrottleRow(now, later, 'z'.repeat(64), 0),
            ),
          '23514',
          'chk_identity_login_throttle_window',
        );
        await expectConstraintViolation(
          () =>
            insertLoginThrottleRow(
              source,
              plan.schemaName,
              createThrottleRow(now, later, 'e'.repeat(64), -1),
            ),
          '23514',
          'chk_identity_login_throttle_window',
        );
        await expectConstraintViolation(
          () =>
            insertLoginThrottleRow(
              source,
              plan.schemaName,
              createThrottleRow(now, now, 'f'.repeat(64), 0),
            ),
          '23514',
          'chk_identity_login_throttle_window',
        );
      } finally {
        await source.destroy();
      }
    } finally {
      await run.cleanup();
    }
  });
});

describe('Identity transaction durability', () => {
  it('attempts every initialized data-source cleanup after one cleanup fails', async () => {
    const sourceA: DestroyableDataSource = {
      destroy: jest.fn().mockRejectedValue(new Error('source A cleanup failed')),
      isInitialized: true,
    };
    const sourceB: DestroyableDataSource = {
      destroy: jest.fn().mockResolvedValue(undefined),
      isInitialized: true,
    };

    await expect(destroyInitializedDataSources([sourceA, sourceB])).rejects.toThrow(
      'source A cleanup failed',
    );
    expect(sourceA.destroy).toHaveBeenCalledTimes(1);
    expect(sourceB.destroy).toHaveBeenCalledTimes(1);
  });

  it('rolls back and commits all four participants across separate connections', async () => {
    const plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(
        randomBytes(32).toString('hex'),
        await selectLoopbackPort(),
      ),
    );
    const run = await startIsolatedPostgres(plan);
    try {
      await run.migrate({ createDataSource: createIdentityDataSource });
      const sourceA = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
      const sourceB = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
      try {
        await sourceA.initialize();
        await sourceB.initialize();
        const transaction = new TypeOrmIdentityTransactionAdapter(sourceA);
        await expect(
          transaction.run({
            execute: async (scope) => {
              await writeIdentityScope(scope, 'rollback@example.test');
              throw new Error('forced rollback');
            },
          }),
        ).rejects.toThrow('forced rollback');
        await expectIdentityCounts(sourceB, plan.schemaName, 0);

        const committed = await transaction.run({
          execute: async (scope) => writeIdentityScope(scope, 'commit@example.test'),
        });
        await expectIdentityCounts(sourceB, plan.schemaName, 1);
        const observed = await new TypeOrmIdentityTransactionAdapter(sourceB).run({
          execute: async (scope) => ({
            user: await scope.users.findByNormalizedEmail(committed.user.normalizedEmail),
            session: await scope.sessions.findById(committed.session.id),
            registrationThrottle: await scope.registrationThrottles.findByKeyAndWindow({
              keyHash: committed.registrationThrottle.keyHash,
              windowStartedAt: committed.registrationThrottle.windowStartedAt,
            }),
            loginThrottle: await scope.loginThrottles.findByKeyAndWindow({
              keyHash: committed.loginThrottle.keyHash,
              windowStartedAt: committed.loginThrottle.windowStartedAt,
            }),
          }),
        });
        expect(observed).toStrictEqual(committed);
      } finally {
        await destroyInitializedDataSources([sourceA, sourceB]);
      }
    } finally {
      await run.cleanup();
    }
  });
});

type DestroyableDataSource = Pick<DataSource, 'destroy' | 'isInitialized'>;

async function destroyInitializedDataSources(
  sources: readonly DestroyableDataSource[],
): Promise<void> {
  const results = await Promise.allSettled(
    sources.map(async (source) => {
      if (source.isInitialized) await source.destroy();
    }),
  );
  const failures = results.flatMap((result) =>
    result.status === 'rejected' ? [result.reason] : [],
  );
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, 'Data-source cleanup failed.');
}

function createOwnedResources(plan: IsolatedPostgresPlan): readonly IsolatedPostgresResource[] {
  return [
    createOwnedResource(plan, 'container'),
    createOwnedResource(plan, 'network'),
    createOwnedResource(plan, 'volume'),
  ];
}

function corruptContainerLabel(resource: IsolatedPostgresResource): IsolatedPostgresResource {
  if (resource.kind !== 'container') {
    return resource;
  }

  return {
    ...resource,
    labels: {
      ...resource.labels,
      'com.udemy.identity-test.run-id':
        'f0e1d2c3b4a5968778695a4b3c2d1e0ffedcba98765432100123456789abcdef',
    },
  };
}

function replaceEnvironment(
  environment: IsolatedPostgresEnvironment,
  changes: Partial<IsolatedPostgresEnvironment>,
): IsolatedPostgresEnvironment {
  return { ...environment, ...changes };
}

function createUserEntity(normalizedEmail: string): UserEntity {
  const now = new Date();
  const entity = new UserEntity();
  entity.id = randomUUID();
  entity.normalizedEmail = normalizedEmail;
  entity.passwordHash = 'test-only-hash';
  entity.createdAt = now;
  entity.updatedAt = now;
  return entity;
}

type SessionRow = {
  readonly id: string;
  readonly userId: string | null;
  readonly tokenHash: string;
  readonly csrfTokenHash: string;
  readonly state: string;
  readonly createdAt: Date;
  readonly lastSeenAt: Date;
  readonly absoluteExpiresAt: Date;
  readonly idleExpiresAt: Date;
  readonly revokedAt: Date | null;
};

type ThrottleRow = {
  readonly id: string;
  readonly keyHash: string;
  readonly windowStartedAt: Date;
  readonly expiresAt: Date;
  readonly count: number;
};

type CommittedIdentity = {
  readonly user: User;
  readonly session: Session;
  readonly registrationThrottle: RegistrationThrottle;
  readonly loginThrottle: LoginThrottle;
};

function createSessionRow(now: Date, expiresAt: Date): SessionRow {
  return {
    id: randomUUID(),
    userId: null,
    tokenHash: randomBytes(32).toString('hex'),
    csrfTokenHash: randomBytes(32).toString('hex'),
    state: 'pre_auth',
    createdAt: now,
    lastSeenAt: now,
    absoluteExpiresAt: expiresAt,
    idleExpiresAt: expiresAt,
    revokedAt: null,
  };
}

function createThrottleRow(
  now: Date,
  expiresAt: Date,
  keyHash: string,
  count: number,
): ThrottleRow {
  return { id: randomUUID(), keyHash, windowStartedAt: now, expiresAt, count };
}

async function insertUserRow(
  source: DataSource,
  schema: string,
  id: string,
  normalizedEmail: string,
  now: Date,
): Promise<void> {
  await source.query(
    `INSERT INTO "${schema}"."identity_users" (id, normalized_email, password_hash, created_at, updated_at) VALUES ($1, $2, $3, $4, $4)`,
    [id, normalizedEmail, 'test-only-hash', now],
  );
}

async function insertSessionRow(
  source: DataSource,
  schema: string,
  row: SessionRow,
): Promise<void> {
  await source.query(
    `INSERT INTO "${schema}"."identity_sessions" (id, user_id, token_hash, csrf_token_hash, state, created_at, last_seen_at, absolute_expires_at, idle_expires_at, revoked_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [
      row.id,
      row.userId,
      row.tokenHash,
      row.csrfTokenHash,
      row.state,
      row.createdAt,
      row.lastSeenAt,
      row.absoluteExpiresAt,
      row.idleExpiresAt,
      row.revokedAt,
    ],
  );
}

async function insertRegistrationThrottleRow(
  source: DataSource,
  schema: string,
  row: ThrottleRow,
): Promise<void> {
  await source.query(
    `INSERT INTO "${schema}"."identity_registration_throttles" (id, key_hash, window_started_at, expires_at, attempt_count) VALUES ($1, $2, $3, $4, $5)`,
    [row.id, row.keyHash, row.windowStartedAt, row.expiresAt, row.count],
  );
}

async function insertLoginThrottleRow(
  source: DataSource,
  schema: string,
  row: ThrottleRow,
): Promise<void> {
  await source.query(
    `INSERT INTO "${schema}"."identity_login_throttles" (id, key_hash, window_started_at, expires_at, failure_count) VALUES ($1, $2, $3, $4, $5)`,
    [row.id, row.keyHash, row.windowStartedAt, row.expiresAt, row.count],
  );
}

async function expectConstraintViolation(
  operation: () => Promise<void>,
  code: string,
  constraint: string,
): Promise<void> {
  await expect(operation()).rejects.toMatchObject({ code, constraint });
}

async function writeIdentityScope(
  scope: IdentityTransactionScope,
  normalizedEmail: string,
): Promise<CommittedIdentity> {
  const now = new Date();
  const userId = randomUUID();
  const sessionId = randomUUID();
  const hash = 'a'.repeat(64);
  const user: User = {
    id: userId,
    normalizedEmail,
    passwordHash: 'test-only-hash',
    createdAt: now,
    updatedAt: now,
  };
  const session: Session = {
    id: sessionId,
    userId,
    tokenHash: hash,
    csrfTokenHash: 'b'.repeat(64),
    state: 'authenticated',
    createdAt: now,
    lastSeenAt: now,
    absoluteExpiresAt: new Date(now.getTime() + 10_000),
    idleExpiresAt: new Date(now.getTime() + 5_000),
    revokedAt: null,
  };
  const registrationThrottle: RegistrationThrottle = {
    id: randomUUID(),
    keyHash: 'c'.repeat(64),
    windowStartedAt: now,
    expiresAt: new Date(now.getTime() + 10_000),
    attemptCount: 0,
  };
  const loginThrottle: LoginThrottle = {
    id: randomUUID(),
    keyHash: 'd'.repeat(64),
    windowStartedAt: now,
    expiresAt: new Date(now.getTime() + 10_000),
    failureCount: 0,
  };
  await scope.users.insert(user);
  await scope.sessions.insert(session);
  await scope.registrationThrottles.save(registrationThrottle);
  await scope.loginThrottles.save(loginThrottle);
  return { user, session, registrationThrottle, loginThrottle };
}

async function expectIdentityCounts(
  source: DataSource,
  schemaName: string,
  expected: number,
): Promise<void> {
  const tables = [
    'identity_users',
    'identity_sessions',
    'identity_registration_throttles',
    'identity_login_throttles',
  ];
  for (const table of tables) {
    const rows = await source.query(
      `SELECT COUNT(*)::int AS count FROM "${schemaName}"."${table}"`,
    );
    expect(rows[0]?.count).toBe(expected);
  }
}

function selectLoopbackPort(): Promise<number> {
  return new Promise((resolvePort, rejectPort) => {
    const server = createServer();
    server.once('error', rejectPort);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') {
        server.close(() => rejectPort(new Error('Unable to reserve an isolated PostgreSQL port.')));
        return;
      }
      server.close((error) => {
        if (error !== undefined) {
          rejectPort(error);
          return;
        }
        resolvePort(address.port);
      });
    });
  });
}

function readConstraintName(row: unknown): string {
  if (typeof row !== 'object' || row === null || Array.isArray(row)) {
    throw new Error('Unexpected PostgreSQL constraint result.');
  }
  const entry = Object.entries(row).find(([key]) => key === 'conname');
  const value = entry?.[1];
  if (typeof value !== 'string') {
    throw new Error('Unexpected PostgreSQL constraint name.');
  }
  return value;
}
