import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';

import { DataSource, QueryRunner } from 'typeorm';

import { TypeOrmSessionRepository } from '../../src/modules/identity/infrastructure/persistence/repositories/typeorm-session.repository';
import { SessionEntity } from '../../src/modules/identity/infrastructure/persistence/entities/session.entity';
import { createIdentityDataSource } from '../../src/shared/database/identity-database-options';
import {
  createIsolatedPostgresDatabaseOptions,
  createIsolatedPostgresEnvironment,
  createIsolatedPostgresPlan,
  IsolatedPostgresPlan,
  startIsolatedPostgres,
} from '../support/isolated-postgres-harness';

const CSRF_HASH = 'b'.repeat(64);
const BARRIER_LOCK_KEY = 917221;

type ContentionRow = {
  readonly databaseName: string;
  readonly pid: number;
  readonly query: string;
};
type Sources = {
  readonly coordinator: DataSource;
  readonly sourceA: DataSource;
  readonly sourceB: DataSource;
  readonly sourceC: DataSource;
};
type Runners = {
  readonly coordinator: QueryRunner;
  readonly sourceA: QueryRunner;
  readonly sourceB: QueryRunner;
};

describe('Identity guarded session transition', () => {
  it('allows exactly one concurrent real guarded revoke and preserves the full revoked record', async () => {
    const plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(
        randomBytes(32).toString('hex'),
        await selectLoopbackPort(),
      ),
    );
    const run = await startIsolatedPostgres(plan);
    try {
      await run.migrate({ createDataSource: createIdentityDataSource });
      const sources = createDataSources(plan);
      await initializeDataSources(sources);
      try {
        const session = createActivePreAuthSession();
        await sources.sourceC.getRepository(SessionEntity).insert(session);
        const runners = createQueryRunners(sources);
        await connectQueryRunners(runners);
        const pidA = await readBackendPid(runners.sourceA);
        const pidB = await readBackendPid(runners.sourceB);
        expect(pidA).not.toBe(pidB);
        const operations: Promise<{ affectedRows: number }>[] = [];
        let lockHeld = false;
        try {
          await installStatementBarrier(runners.coordinator, plan.schemaName);
          await runners.coordinator.query('SELECT pg_advisory_lock($1)', [BARRIER_LOCK_KEY]);
          lockHeld = true;
          const now = new Date();
          const operationA = new TypeOrmSessionRepository(
            runners.sourceA.manager,
          ).revokeActiveSession({ id: session.id, tokenHash: session.tokenHash, now });
          operations.push(operationA);
          await waitForContendedUpdates(
            runners.coordinator,
            [pidA],
            plan.databaseName,
            plan.schemaName,
          );
          const operationB = new TypeOrmSessionRepository(
            runners.sourceB.manager,
          ).revokeActiveSession({ id: session.id, tokenHash: session.tokenHash, now });
          operations.push(operationB);
          await waitForContendedUpdates(
            runners.coordinator,
            [pidA, pidB],
            plan.databaseName,
            plan.schemaName,
          );
          const results = await unlockAndSettle(runners.coordinator, [operationA, operationB]);
          lockHeld = false;
          expect(results.map((result) => result.affectedRows).sort()).toEqual([0, 1]);
          const stored = await sources.sourceC
            .getRepository(SessionEntity)
            .findOneByOrFail({ id: session.id });
          expect(stored).toMatchObject({
            id: session.id,
            userId: null,
            tokenHash: session.tokenHash,
            csrfTokenHash: session.csrfTokenHash,
            state: 'revoked',
            createdAt: session.createdAt,
            lastSeenAt: session.lastSeenAt,
            absoluteExpiresAt: session.absoluteExpiresAt,
            idleExpiresAt: session.idleExpiresAt,
          });
          expect(stored.revokedAt).toEqual(now);
        } finally {
          if (lockHeld) {
            await unlockAndSettle(runners.coordinator, operations);
          }
          await releaseQueryRunners(runners);
        }
      } finally {
        await destroyDataSources(sources);
      }
    } finally {
      await run.cleanup();
    }
  });

  it('proves the same two-connection barrier exposes prohibited double success for a test-only unguarded update', async () => {
    const plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(
        randomBytes(32).toString('hex'),
        await selectLoopbackPort(),
      ),
    );
    const run = await startIsolatedPostgres(plan);
    try {
      await run.migrate({ createDataSource: createIdentityDataSource });
      const sources = createDataSources(plan);
      await initializeDataSources(sources);
      try {
        const session = createActivePreAuthSession();
        await sources.sourceC.getRepository(SessionEntity).insert(session);
        const runners = createQueryRunners(sources);
        await connectQueryRunners(runners);
        const pidA = await readBackendPid(runners.sourceA);
        const pidB = await readBackendPid(runners.sourceB);
        expect(pidA).not.toBe(pidB);
        const operations: Promise<number>[] = [];
        let lockHeld = false;
        try {
          await installStatementBarrier(runners.coordinator, plan.schemaName);
          await runners.coordinator.query('SELECT pg_advisory_lock($1)', [BARRIER_LOCK_KEY]);
          lockHeld = true;
          const now = new Date();
          const operationA = unsafeUnguardedRevoke(
            runners.sourceA,
            plan.schemaName,
            session.id,
            session.tokenHash,
            now,
          );
          operations.push(operationA);
          await waitForContendedUpdates(
            runners.coordinator,
            [pidA],
            plan.databaseName,
            plan.schemaName,
          );
          const operationB = unsafeUnguardedRevoke(
            runners.sourceB,
            plan.schemaName,
            session.id,
            session.tokenHash,
            now,
          );
          operations.push(operationB);
          await waitForContendedUpdates(
            runners.coordinator,
            [pidA, pidB],
            plan.databaseName,
            plan.schemaName,
          );
          const results = await unlockAndSettle(runners.coordinator, [operationA, operationB]);
          lockHeld = false;
          expect(results).toEqual([1, 1]);
        } finally {
          if (lockHeld) {
            await unlockAndSettle(runners.coordinator, operations);
          }
          await releaseQueryRunners(runners);
        }
      } finally {
        await destroyDataSources(sources);
      }
    } finally {
      await run.cleanup();
    }
  });

  it('rejects wrong hash, expiry, and prior revocation while allowing pre-auth null-user revocation', async () => {
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
        const repository = new TypeOrmSessionRepository(source.manager);
        const now = new Date();
        const valid = createActivePreAuthSession(now);
        const expired = createExpiredPreAuthSession(now);
        const idleExpired = createIdleExpiredPreAuthSession(now);
        const revoked = createActivePreAuthSession(now);
        revoked.state = 'revoked';
        revoked.revokedAt = now;
        await source.getRepository(SessionEntity).insert([valid, expired, idleExpired, revoked]);
        await expectZeroAffected(repository, randomUUID(), valid.tokenHash, now);
        await expectZeroAffected(repository, valid.id, 'c'.repeat(64), now);
        await expectZeroAffected(repository, expired.id, expired.tokenHash, now);
        await expectZeroAffected(repository, idleExpired.id, idleExpired.tokenHash, now);
        await expectZeroAffected(repository, revoked.id, revoked.tokenHash, now);
        await expectOneAffected(repository, valid.id, valid.tokenHash, now);
      } finally {
        await source.destroy();
      }
    } finally {
      await run.cleanup();
    }
  });
});

function createDataSources(plan: IsolatedPostgresPlan): Sources {
  const options = createIsolatedPostgresDatabaseOptions(plan);
  return {
    coordinator: createIdentityDataSource(options),
    sourceA: createIdentityDataSource(options),
    sourceB: createIdentityDataSource(options),
    sourceC: createIdentityDataSource(options),
  };
}
async function initializeDataSources(sources: Sources): Promise<void> {
  await Promise.all([
    sources.coordinator.initialize(),
    sources.sourceA.initialize(),
    sources.sourceB.initialize(),
    sources.sourceC.initialize(),
  ]);
}
async function destroyDataSources(sources: Sources): Promise<void> {
  await Promise.all([
    sources.coordinator.destroy(),
    sources.sourceA.destroy(),
    sources.sourceB.destroy(),
    sources.sourceC.destroy(),
  ]);
}
function createQueryRunners(sources: Sources): Runners {
  return {
    coordinator: sources.coordinator.createQueryRunner(),
    sourceA: sources.sourceA.createQueryRunner(),
    sourceB: sources.sourceB.createQueryRunner(),
  };
}
async function connectQueryRunners(runners: Runners): Promise<void> {
  await Promise.all([
    runners.coordinator.connect(),
    runners.sourceA.connect(),
    runners.sourceB.connect(),
  ]);
}
async function releaseQueryRunners(runners: Runners): Promise<void> {
  await Promise.all([
    runners.coordinator.release(),
    runners.sourceA.release(),
    runners.sourceB.release(),
  ]);
}

function createActivePreAuthSession(referenceNow = new Date()): SessionEntity {
  return createPreAuthSession(
    new Date(referenceNow.getTime() - 2_000),
    new Date(referenceNow.getTime() - 1_000),
    new Date(referenceNow.getTime() + 60_000),
  );
}
function createExpiredPreAuthSession(referenceNow: Date): SessionEntity {
  return createPreAuthSession(
    new Date(referenceNow.getTime() - 30_000),
    new Date(referenceNow.getTime() - 20_000),
    new Date(referenceNow.getTime() - 10_000),
  );
}
function createIdleExpiredPreAuthSession(referenceNow: Date): SessionEntity {
  const entity = createActivePreAuthSession(referenceNow);
  entity.createdAt = new Date(referenceNow.getTime() - 30_000);
  entity.lastSeenAt = new Date(referenceNow.getTime() - 20_000);
  entity.idleExpiresAt = new Date(referenceNow.getTime() - 10_000);
  return entity;
}
function createPreAuthSession(createdAt: Date, lastSeenAt: Date, expiresAt: Date): SessionEntity {
  const entity = new SessionEntity();
  entity.id = randomUUID();
  entity.userId = null;
  entity.tokenHash = randomBytes(32).toString('hex');
  entity.csrfTokenHash = CSRF_HASH;
  entity.state = 'pre_auth';
  entity.createdAt = createdAt;
  entity.lastSeenAt = lastSeenAt;
  entity.absoluteExpiresAt = expiresAt;
  entity.idleExpiresAt = expiresAt;
  entity.revokedAt = null;
  return entity;
}
async function installStatementBarrier(runner: QueryRunner, schema: string): Promise<void> {
  await runner.query(
    `CREATE FUNCTION "${schema}".test_session_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(${BARRIER_LOCK_KEY}); RETURN NEW; END; $$; CREATE TRIGGER test_session_barrier BEFORE UPDATE ON "${schema}".identity_sessions FOR EACH STATEMENT EXECUTE FUNCTION "${schema}".test_session_barrier();`,
  );
}
async function readBackendPid(runner: QueryRunner): Promise<number> {
  return readInteger(await runner.query('SELECT pg_backend_pid()::int AS pid'), 'pid');
}
async function waitForContendedUpdates(
  coordinator: QueryRunner,
  pids: readonly number[],
  databaseName: string,
  schema: string,
): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const rows = await coordinator.query(
      `SELECT activity.datname AS "databaseName", activity.pid::int AS pid, activity.query FROM pg_locks AS locks INNER JOIN pg_stat_activity AS activity ON activity.pid = locks.pid WHERE locks.locktype = 'advisory' AND NOT locks.granted AND activity.pid = ANY($1::int[]) ORDER BY activity.pid`,
      [pids],
    );
    const contended = readContentionRows(rows);
    if (
      contended.length === pids.length &&
      contended.every(
        (row) =>
          pids.includes(row.pid) &&
          row.databaseName === databaseName &&
          row.query.includes(`UPDATE "${schema}"."identity_sessions"`),
      )
    )
      return;
    await waitForNextObservation();
  }
  throw new Error('Expected both specified connections to wait at the owned session UPDATE.');
}
async function unlockAndSettle<T>(
  coordinator: QueryRunner,
  operations: readonly Promise<T>[],
): Promise<T[]> {
  try {
    await coordinator.query('SELECT pg_advisory_unlock($1)', [BARRIER_LOCK_KEY]);
    const results = await Promise.allSettled(operations);
    const rejected = results.find((result) => result.status === 'rejected');
    if (rejected !== undefined && rejected.status === 'rejected') throw rejected.reason;
    return results.map((result) => {
      if (result.status === 'fulfilled') return result.value;
      throw new Error('Unexpected rejected concurrent operation.');
    });
  } catch (error) {
    await Promise.allSettled(operations);
    throw error;
  }
}
async function unsafeUnguardedRevoke(
  runner: QueryRunner,
  schema: string,
  id: string,
  tokenHash: string,
  now: Date,
): Promise<number> {
  const rows = await runner.query(
    `WITH updated AS (UPDATE "${schema}"."identity_sessions" SET state = 'revoked', revoked_at = $1 WHERE id = $2 AND token_hash = $3 RETURNING id) SELECT count(*)::int AS affected FROM updated`,
    [now, id, tokenHash],
  );
  return readInteger(rows, 'affected');
}
async function expectZeroAffected(
  repository: TypeOrmSessionRepository,
  id: string,
  tokenHash: string,
  now: Date,
): Promise<void> {
  expect((await repository.revokeActiveSession({ id, tokenHash, now })).affectedRows).toBe(0);
}
async function expectOneAffected(
  repository: TypeOrmSessionRepository,
  id: string,
  tokenHash: string,
  now: Date,
): Promise<void> {
  expect((await repository.revokeActiveSession({ id, tokenHash, now })).affectedRows).toBe(1);
}
function readInteger(rows: unknown, field: string): number {
  const row = readSingleRecord(rows);
  const value = row[field];
  if (typeof value !== 'number') throw new Error(`Expected numeric ${field} from PostgreSQL.`);
  return value;
}
function readContentionRows(rows: unknown): readonly ContentionRow[] {
  if (!Array.isArray(rows)) throw new Error('Unexpected PostgreSQL contention result.');
  return rows.map((row) => {
    if (typeof row !== 'object' || row === null || Array.isArray(row))
      throw new Error('Unexpected PostgreSQL contention row.');
    const entry = row as Record<string, unknown>;
    if (
      typeof entry.databaseName !== 'string' ||
      typeof entry.pid !== 'number' ||
      typeof entry.query !== 'string'
    )
      throw new Error('Unexpected PostgreSQL contention fields.');
    return { databaseName: entry.databaseName, pid: entry.pid, query: entry.query };
  });
}
function readSingleRecord(rows: unknown): Record<string, unknown> {
  if (!Array.isArray(rows) || rows.length !== 1)
    throw new Error('Expected one PostgreSQL result row.');
  const row = rows[0];
  if (typeof row !== 'object' || row === null || Array.isArray(row))
    throw new Error('Unexpected PostgreSQL result row.');
  return row as Record<string, unknown>;
}
function waitForNextObservation(): Promise<void> {
  return new Promise((resolveWait) => setTimeout(resolveWait, 25));
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
