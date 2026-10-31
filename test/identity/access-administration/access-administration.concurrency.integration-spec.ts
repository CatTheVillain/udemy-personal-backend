import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';

import { DataSource, QueryRunner } from 'typeorm';

import {
  IdentityAccessAdministrationCredentialsConfig,
  OperatorCredentialPurpose,
} from '../../../src/modules/identity/application/access-administration-config';
import { IdentityAccessAdministrationService } from '../../../src/modules/identity/application/identity-access-administration.service';
import { ConfigOperatorCredentialVerifier } from '../../../src/modules/identity/application/operator-credential-verifier';
import {
  IdentityTransactionPort,
  IdentityTransactionScope,
  IdentityTransactionWork,
  UserRepositoryPort,
} from '../../../src/modules/identity/application/ports/identity.ports';
import { User } from '../../../src/modules/identity/domain/identity.types';
import { TypeOrmAccessAdministrationLockRepository } from '../../../src/modules/identity/infrastructure/persistence/repositories/typeorm-access-administration-lock.repository';
import { TypeOrmAccessCapabilityRepository } from '../../../src/modules/identity/infrastructure/persistence/repositories/typeorm-access-capability.repository';
import { TypeOrmAccessChangeRepository } from '../../../src/modules/identity/infrastructure/persistence/repositories/typeorm-access-change.repository';
import { TypeOrmAccessReceiptRepository } from '../../../src/modules/identity/infrastructure/persistence/repositories/typeorm-access-receipt.repository';
import { TypeOrmLoginThrottleRepository } from '../../../src/modules/identity/infrastructure/persistence/repositories/typeorm-login-throttle.repository';
import { TypeOrmRegistrationThrottleRepository } from '../../../src/modules/identity/infrastructure/persistence/repositories/typeorm-registration-throttle.repository';
import { TypeOrmSessionRepository } from '../../../src/modules/identity/infrastructure/persistence/repositories/typeorm-session.repository';
import { TypeOrmUserRepository } from '../../../src/modules/identity/infrastructure/persistence/repositories/typeorm-user.repository';
import { TypeOrmIdentityTransactionAdapter } from '../../../src/modules/identity/infrastructure/persistence/typeorm-identity-transaction.adapter';
import { createIdentityDataSource } from '../../../src/shared/database/identity-database-options';
import {
  createIsolatedPostgresDatabaseOptions,
  createIsolatedPostgresEnvironment,
  createIsolatedPostgresPlan,
  IsolatedPostgresPlan,
  startIsolatedPostgres,
} from '../../support/isolated-postgres-harness';

const ADMINISTRATION_LOCK_NAMESPACE = 734_111;
const ADMINISTRATION_LOCK_KEY = 5;
const REGISTRATION_LOCK_KEY = 734_111_003;

describe('Identity access-administration concurrency', () => {
  let first!: DataSource;
  let second!: DataSource;
  let plan!: IsolatedPostgresPlan;
  let cleanup: (() => Promise<void>) | undefined;

  beforeEach(async () => {
    plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(randomBytes(32).toString('hex'), await loopbackPort()),
    );
    const run = await startIsolatedPostgres(plan);
    cleanup = () => run.cleanup();
    first = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
    second = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
    await first.initialize();
    await first.query(`CREATE SCHEMA "${plan.schemaName}"`);
    await first.runMigrations();
    await second.initialize();
  });

  afterEach(async () => {
    const results = await Promise.allSettled([
      second?.isInitialized ? second.destroy() : Promise.resolve(),
      first?.isInitialized ? first.destroy() : Promise.resolve(),
      cleanup?.() ?? Promise.resolve(),
    ]);
    const failure = results.find((result) => result.status === 'rejected');
    if (failure?.status === 'rejected') throw failure.reason;
  });

  it('serializes bootstrap/recovery and rejects a later D1 invocation after exactly one commit', async () => {
    const firstTarget = await insertUser(first, plan, 'd1-bootstrap@example.test');
    const secondTarget = await insertUser(first, plan, 'd1-recovery@example.test');
    const bootstrap = randomBytes(32);
    const recovery = randomBytes(32);
    const latch = createLatch();
    const bootstrapService = service(
      first,
      bootstrap,
      recovery,
      new PausingIdentityTransactionAdapter(first, latch, 'administrator-count'),
    );
    const recoveryTransactions = new CountingIdentityTransactionAdapter(second);
    const recoveryService = service(second, bootstrap, recovery, recoveryTransactions);
    const firstOperation = bootstrapService.execute(operator(firstTarget, bootstrap, 'bootstrap'));
    try {
      await latch.reached;
      await expect(
        recoveryService.execute(operator(secondTarget, recovery, 'recovery')),
      ).resolves.toEqual({ code: 'access_administration_busy', retryAfterSeconds: 1 });
      expect(latch.pauseCount()).toBe(1);
      expect(recoveryTransactions.calls()).toBe(1);
      latch.release();
      await expect(firstOperation).resolves.toEqual({ code: 'access_administration_completed' });
      await expect(
        recoveryService.execute(operator(secondTarget, recovery, 'recovery')),
      ).resolves.toEqual({ code: 'access_administration_forbidden' });
      expect(await count(first, plan, 'identity_access_capabilities')).toBe(1);
      expect(await count(first, plan, 'identity_access_changes')).toBe(1);
      expect(await count(first, plan, 'identity_access_command_receipts')).toBe(1);
    } finally {
      latch.release();
      await firstOperation.catch(() => undefined);
    }
  });

  it('holds the membership lock for ordinary admin changes, preserves one final administrator, and has no retry', async () => {
    const administrator = await insertUser(first, plan, 'self-revoke-a@example.test');
    const survivor = await insertUser(first, plan, 'self-revoke-b@example.test');
    const bootstrap = randomBytes(32);
    const recovery = randomBytes(32);
    const adminService = service(first, bootstrap, recovery);
    const secondTransactions = new CountingIdentityTransactionAdapter(second);
    const secondService = service(second, bootstrap, recovery, secondTransactions);
    await adminService.execute(operator(administrator, bootstrap, 'bootstrap'));
    await first.query(
      `INSERT INTO "${plan.schemaName}".identity_access_capabilities (user_id, capability, active) VALUES ($1, 'administrator', true)`,
      [survivor],
    );
    const firstSession = await insertSession(first, plan, administrator);
    const secondSession = await insertSession(first, plan, survivor);
    const latch = createLatch();
    const pausedService = service(
      first,
      bootstrap,
      recovery,
      new PausingIdentityTransactionAdapter(first, latch, 'administrator-count'),
    );
    const firstOperation = pausedService.execute(ordinary(administrator, firstSession));
    try {
      await latch.reached;
      await expect(secondService.execute(ordinary(survivor, secondSession))).resolves.toEqual({
        code: 'access_administration_busy',
        retryAfterSeconds: 1,
      });
      expect(latch.pauseCount()).toBe(1);
      expect(secondTransactions.calls()).toBe(1);
      latch.release();
      await expect(firstOperation).resolves.toEqual({ code: 'access_administration_completed' });
      await expect(secondService.execute(ordinary(survivor, secondSession))).resolves.toEqual({
        code: 'access_administration_forbidden',
      });
      expect(await activeAdministrators(first, plan)).toEqual([survivor]);
    } finally {
      latch.release();
      await firstOperation.catch(() => undefined);
    }
  });

  it('keeps same-user incompatible capability races durable-safe while allowing distinct-user control', async () => {
    const administrator = await insertUser(first, plan, 'race-admin@example.test');
    const secondAdministrator = await insertUser(first, plan, 'race-second-admin@example.test');
    const target = await insertUser(first, plan, 'race-target@example.test');
    const independentInstructor = await insertUser(first, plan, 'race-instructor@example.test');
    const independentModerator = await insertUser(first, plan, 'race-moderator@example.test');
    const bootstrap = randomBytes(32);
    const recovery = randomBytes(32);
    const latch = createLatch();
    const left = service(
      first,
      bootstrap,
      recovery,
      new PausingIdentityTransactionAdapter(first, latch, 'user-locks'),
    );
    const right = service(second, bootstrap, recovery);
    const bootstrapService = service(first, bootstrap, recovery);
    await bootstrapService.execute(operator(administrator, bootstrap, 'bootstrap'));
    await first.query(
      `INSERT INTO "${plan.schemaName}".identity_access_capabilities (user_id, capability, active) VALUES ($1, 'administrator', true)`,
      [secondAdministrator],
    );
    const session = await insertSession(first, plan, administrator);
    const secondSession = await insertSession(first, plan, secondAdministrator);
    const leftOperation = left.execute(ordinary(administrator, session, target, 'instructor'));
    await latch.reached;
    const rightOperation = right.execute(
      ordinary(secondAdministrator, secondSession, target, 'content_moderator'),
    );
    try {
      await waitForUserLockWait(first, plan);
      latch.release();
      const [instructor, moderator] = await Promise.all([leftOperation, rightOperation]);
      expect([instructor.code, moderator.code]).toContain('access_administration_completed');
      expect(await activeCapabilities(first, plan, target)).toHaveLength(1);
      await expect(
        left.execute(ordinary(administrator, session, independentInstructor, 'instructor')),
      ).resolves.toEqual({ code: 'access_administration_completed' });
      await expect(
        right.execute(ordinary(administrator, session, independentModerator, 'content_moderator')),
      ).resolves.toEqual({ code: 'access_administration_completed' });
      expect(await activeCapabilities(first, plan, independentInstructor)).toEqual(['instructor']);
      expect(await activeCapabilities(first, plan, independentModerator)).toEqual([
        'content_moderator',
      ]);
    } finally {
      latch.release();
      await Promise.all([
        leftOperation.catch(() => undefined),
        rightOperation.catch(() => undefined),
      ]);
    }
  });

  it('proves the isolated unsafe control can expose the prohibited combination and lock namespaces do not contend', async () => {
    await first.query(
      `CREATE TABLE "${plan.schemaName}".unsafe_administrators (user_id uuid NOT NULL)`,
    );
    const latch = createLatch();
    const staleLeft = first.createQueryRunner();
    const staleRight = second.createQueryRunner();
    const leftOperation = unsafeStaleCountInsert(staleLeft, plan, latch);
    const rightOperation = unsafeStaleCountInsert(staleRight, plan, latch);
    try {
      await waitForPauseCount(latch, 2);
      latch.release();
      await Promise.all([leftOperation, rightOperation]);
      expect(await count(first, plan, 'unsafe_administrators')).toBe(2);
    } finally {
      latch.release();
      await Promise.all([
        leftOperation.catch(() => undefined),
        rightOperation.catch(() => undefined),
      ]);
    }

    const holder = await first.createQueryRunner();
    await holder.connect();
    await holder.startTransaction();
    try {
      await holder.query('SELECT pg_advisory_xact_lock($1)', [REGISTRATION_LOCK_KEY]);
      const result = await second.query('SELECT pg_try_advisory_xact_lock($1, $2) AS locked', [
        ADMINISTRATION_LOCK_NAMESPACE,
        ADMINISTRATION_LOCK_KEY,
      ]);
      expect(readLocked(result)).toBe(true);
    } finally {
      await release(holder);
    }
    const membershipHolder = await holdAdministrationLock(first);
    try {
      const result = await second.query('SELECT pg_try_advisory_xact_lock($1) AS locked', [
        REGISTRATION_LOCK_KEY,
      ]);
      expect(readLocked(result)).toBe(true);
    } finally {
      await release(membershipHolder);
    }
  });
});

type PausePoint = 'administrator-count' | 'user-locks';
type OrdinaryCapability = 'instructor' | 'content_moderator' | 'administrator';

interface AdministratorSession {
  readonly id: string;
  readonly tokenHash: string;
}

interface Latch {
  readonly reached: Promise<void>;
  release(): void;
  pauseCount(): number;
  wait(): Promise<void>;
}

class PausingIdentityTransactionAdapter implements IdentityTransactionPort {
  public constructor(
    private readonly source: DataSource,
    private readonly latch: Latch,
    private readonly pausePoint: PausePoint,
  ) {}

  public async run<Result>(work: IdentityTransactionWork<Result>): Promise<Result> {
    return this.source.transaction(async (manager) => {
      const capabilities = new TypeOrmAccessCapabilityRepository(manager);
      const users = new PausingUserRepository(
        new TypeOrmUserRepository(manager),
        this.latch,
        this.pausePoint,
      );
      const scope: IdentityTransactionScope = {
        users,
        sessions: new TypeOrmSessionRepository(manager),
        registrationThrottles: new TypeOrmRegistrationThrottleRepository(manager),
        loginThrottles: new TypeOrmLoginThrottleRepository(manager),
        accessAdministrationLocks: new TypeOrmAccessAdministrationLockRepository(manager),
        accessCapabilities: {
          findActiveProjectionForUser: (userId) => capabilities.findActiveProjectionForUser(userId),
          findActiveLocked: (userId, capability) =>
            capabilities.findActiveLocked(userId, capability),
          hasActiveLocked: (userId, capability) => capabilities.hasActiveLocked(userId, capability),
          lockActiveAdministratorsAndCount: async () => {
            const result = await capabilities.lockActiveAdministratorsAndCount();
            if (this.pausePoint === 'administrator-count') await this.latch.wait();
            return result;
          },
          applyTransition: (transition) => capabilities.applyTransition(transition),
        },
        accessChanges: new TypeOrmAccessChangeRepository(manager),
        accessReceipts: new TypeOrmAccessReceiptRepository(manager),
      };
      return work.execute(scope);
    });
  }
}

class CountingIdentityTransactionAdapter implements IdentityTransactionPort {
  private count = 0;
  private readonly delegate: TypeOrmIdentityTransactionAdapter;

  public constructor(source: DataSource) {
    this.delegate = new TypeOrmIdentityTransactionAdapter(source);
  }

  public calls(): number {
    return this.count;
  }

  public async run<Result>(work: IdentityTransactionWork<Result>): Promise<Result> {
    this.count += 1;
    return this.delegate.run(work);
  }
}

class PausingUserRepository implements UserRepositoryPort {
  public constructor(
    private readonly delegate: TypeOrmUserRepository,
    private readonly latch: Latch,
    private readonly pausePoint: PausePoint,
  ) {}

  public findByNormalizedEmail(normalizedEmail: string): Promise<User | null> {
    return this.delegate.findByNormalizedEmail(normalizedEmail);
  }

  public findById(id: string): Promise<User | null> {
    return this.delegate.findById(id);
  }

  public async findLockedByIds(ids: readonly string[]): Promise<readonly User[]> {
    const users = await this.delegate.findLockedByIds(ids);
    if (this.pausePoint === 'user-locks') await this.latch.wait();
    return users;
  }

  public insert(user: User): Promise<void> {
    return this.delegate.insert(user);
  }

  public insertIfAbsent(user: User): Promise<boolean> {
    return this.delegate.insertIfAbsent(user);
  }
}

function createLatch(): Latch {
  let pauseCount = 0;
  let releaseWait: () => void;
  let signalReached: () => void;
  const reached = new Promise<void>((resolve) => {
    signalReached = resolve;
  });
  const waiting = new Promise<void>((resolve) => {
    releaseWait = resolve;
  });
  return {
    reached,
    release: (): void => releaseWait(),
    pauseCount: (): number => pauseCount,
    wait: async (): Promise<void> => {
      pauseCount += 1;
      signalReached();
      await waiting;
    },
  };
}

function service(
  source: DataSource,
  bootstrap: Buffer,
  recovery: Buffer,
  transactions: IdentityTransactionPort = new TypeOrmIdentityTransactionAdapter(source),
): IdentityAccessAdministrationService {
  const config = IdentityAccessAdministrationCredentialsConfig.from({
    IDENTITY_ACCESS_BOOTSTRAP_CREDENTIAL: bootstrap.toString('base64url'),
    IDENTITY_ACCESS_RECOVERY_CREDENTIAL: recovery.toString('base64url'),
  });
  return new IdentityAccessAdministrationService(
    transactions,
    new ConfigOperatorCredentialVerifier(config),
  );
}

function operator(targetUserId: string, credential: Buffer, purpose: OperatorCredentialPurpose) {
  return {
    kind: 'operator' as const,
    purpose,
    credential,
    commandId: randomUUID(),
    targetUserId,
    action: 'grant' as const,
    capability: 'administrator' as const,
    reason: 'concurrency proof',
    reference: 'ACC04 independent proof',
  };
}

function ordinary(
  actorId: string,
  session: AdministratorSession,
  targetUserId = actorId,
  capability: OrdinaryCapability = 'administrator',
) {
  return {
    kind: 'administrator' as const,
    actorSessionId: session.id,
    actorTokenHash: session.tokenHash,
    commandId: randomUUID(),
    targetUserId,
    action: capability === 'administrator' ? ('revoke' as const) : ('grant' as const),
    capability,
    reason: 'concurrency proof',
    reference: 'ACC04 independent proof',
  };
}

async function insertUser(
  source: DataSource,
  plan: IsolatedPostgresPlan,
  email: string,
): Promise<string> {
  const id = randomUUID();
  await source.query(
    `INSERT INTO "${plan.schemaName}".identity_users (id, normalized_email, password_hash, created_at, updated_at) VALUES ($1, $2, 'synthetic-hash', clock_timestamp(), clock_timestamp())`,
    [id, email],
  );
  return id;
}

async function insertSession(
  source: DataSource,
  plan: IsolatedPostgresPlan,
  userId: string,
): Promise<{ id: string; tokenHash: string }> {
  const id = randomUUID();
  const tokenHash = randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 3_600_000);
  await source.query(
    `INSERT INTO "${plan.schemaName}".identity_sessions (id, user_id, token_hash, csrf_token_hash, state, created_at, last_seen_at, absolute_expires_at, idle_expires_at, revoked_at) VALUES ($1, $2, $3, $4, 'authenticated', clock_timestamp(), clock_timestamp(), $5, $5, NULL)`,
    [id, userId, tokenHash, randomBytes(32).toString('hex'), expiresAt],
  );
  return { id, tokenHash };
}

async function holdAdministrationLock(source: DataSource): Promise<QueryRunner> {
  const runner = source.createQueryRunner();
  await runner.connect();
  await runner.startTransaction();
  await runner.query('SELECT pg_advisory_xact_lock($1, $2)', [
    ADMINISTRATION_LOCK_NAMESPACE,
    ADMINISTRATION_LOCK_KEY,
  ]);
  return runner;
}
async function release(runner: QueryRunner): Promise<void> {
  try {
    await runner.rollbackTransaction();
  } finally {
    await runner.release();
  }
}
async function count(
  source: DataSource,
  plan: IsolatedPostgresPlan,
  table: string,
): Promise<number> {
  const rows = await source.query(
    `SELECT count(*)::int AS count FROM "${plan.schemaName}".${table}`,
  );
  return readNumber(rows, 'count');
}

async function countWithRunner(
  runner: QueryRunner,
  plan: IsolatedPostgresPlan,
  table: string,
): Promise<number> {
  const rows = await runner.query(
    `SELECT count(*)::int AS count FROM "${plan.schemaName}".${table}`,
  );
  return readNumber(rows, 'count');
}

async function unsafeStaleCountInsert(
  runner: QueryRunner,
  plan: IsolatedPostgresPlan,
  latch: Latch,
): Promise<void> {
  try {
    await runner.connect();
    await runner.startTransaction();
    expect(await countWithRunner(runner, plan, 'unsafe_administrators')).toBe(0);
    await latch.wait();
    await runner.query(`INSERT INTO "${plan.schemaName}".unsafe_administrators VALUES ($1)`, [
      randomUUID(),
    ]);
    await runner.commitTransaction();
  } finally {
    if (runner.isTransactionActive) await runner.rollbackTransaction();
    if (!runner.isReleased) await runner.release();
  }
}

async function waitForPauseCount(latch: Latch, expected: number): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    if (latch.pauseCount() >= expected) return;
    await new Promise<void>((resolveDelay) => setTimeout(resolveDelay, 10));
  }
  throw new Error('Unsafe stale-count control did not reach both intended reads.');
}
async function activeAdministrators(
  source: DataSource,
  plan: IsolatedPostgresPlan,
): Promise<readonly string[]> {
  const rows = await source.query(
    `SELECT user_id FROM "${plan.schemaName}".identity_access_capabilities WHERE active AND capability = 'administrator' ORDER BY user_id`,
  );
  return readStrings(rows, 'user_id');
}
async function activeCapabilities(
  source: DataSource,
  plan: IsolatedPostgresPlan,
  userId: string,
): Promise<readonly string[]> {
  const rows = await source.query(
    `SELECT capability FROM "${plan.schemaName}".identity_access_capabilities WHERE active AND user_id = $1 ORDER BY capability`,
    [userId],
  );
  return readStrings(rows, 'capability');
}

async function waitForUserLockWait(source: DataSource, plan: IsolatedPostgresPlan): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const rows = await source.query(
      `SELECT pid, pg_blocking_pids(pid) AS blockers
       FROM pg_stat_activity
       WHERE datname = $1 AND wait_event_type = 'Lock' AND query ILIKE $2`,
      [plan.databaseName, '%identity_users%'],
    );
    if (!Array.isArray(rows)) throw new Error('Unexpected PostgreSQL lock observer result.');
    const blocked = rows.some((row) => {
      if (typeof row !== 'object' || row === null || Array.isArray(row)) {
        throw new Error('Unexpected PostgreSQL lock observer row.');
      }
      const blockers = (row as Record<string, unknown>).blockers;
      return Array.isArray(blockers) && blockers.some((pid) => typeof pid === 'number');
    });
    if (blocked) return;
    await new Promise<void>((resolveDelay) => setTimeout(resolveDelay, 10));
  }
  throw new Error('Same-user capability race did not reach the expected user lock.');
}
function readLocked(rows: unknown): boolean {
  if (
    !Array.isArray(rows) ||
    rows.length !== 1 ||
    typeof rows[0] !== 'object' ||
    rows[0] === null ||
    Array.isArray(rows[0])
  )
    throw new Error('Unexpected advisory-lock result.');
  const value = (rows[0] as Record<string, unknown>).locked;
  if (typeof value !== 'boolean') throw new Error('Unexpected advisory-lock value.');
  return value;
}
function readNumber(rows: unknown, key: string): number {
  if (
    !Array.isArray(rows) ||
    rows.length !== 1 ||
    typeof rows[0] !== 'object' ||
    rows[0] === null ||
    Array.isArray(rows[0])
  )
    throw new Error('Unexpected count result.');
  const value = (rows[0] as Record<string, unknown>)[key];
  if (typeof value !== 'number') throw new Error('Unexpected count value.');
  return value;
}
function readStrings(rows: unknown, key: string): readonly string[] {
  if (!Array.isArray(rows)) throw new Error('Unexpected row set.');
  return rows.map((row) => {
    if (typeof row !== 'object' || row === null || Array.isArray(row))
      throw new Error('Unexpected row.');
    const value = (row as Record<string, unknown>)[key];
    if (typeof value !== 'string') throw new Error('Unexpected string value.');
    return value;
  });
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
