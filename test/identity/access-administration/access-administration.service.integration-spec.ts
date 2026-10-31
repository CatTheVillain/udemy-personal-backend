import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';

import { DataSource, QueryRunner } from 'typeorm';

import { IdentityAccessAdministrationCredentialsConfig } from '../../../src/modules/identity/application/access-administration-config';
import { IdentityAccessAdministrationService } from '../../../src/modules/identity/application/identity-access-administration.service';
import {
  IdentityTransactionPort,
  IdentityTransactionScope,
  IdentityTransactionWork,
} from '../../../src/modules/identity/application/ports/identity.ports';
import { ConfigOperatorCredentialVerifier } from '../../../src/modules/identity/application/operator-credential-verifier';
import { TypeOrmIdentityTransactionAdapter } from '../../../src/modules/identity/infrastructure/persistence/typeorm-identity-transaction.adapter';
import { createIdentityDataSource } from '../../../src/shared/database/identity-database-options';
import {
  createIsolatedPostgresDatabaseOptions,
  createIsolatedPostgresEnvironment,
  createIsolatedPostgresPlan,
  IsolatedPostgresPlan,
  startIsolatedPostgres,
} from '../../support/isolated-postgres-harness';

type AdministrationAction = 'grant' | 'revoke';
type AdministrationCapability = 'instructor' | 'content_moderator' | 'administrator';

describe('Identity access-administration service', () => {
  let source: DataSource;
  let plan: IsolatedPostgresPlan;
  let cleanup: (() => Promise<void>) | undefined;

  beforeEach(async () => {
    plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(
        randomBytes(32).toString('hex'),
        await selectLoopbackPort(),
      ),
    );
    const run = await startIsolatedPostgres(plan);
    cleanup = () => run.cleanup();
    source = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
    await source.initialize();
    await source.query(`CREATE SCHEMA "${plan.schemaName}"`);
    await source.runMigrations();
  });

  afterEach(async () => {
    if (source.isInitialized) await source.destroy();
    await cleanup?.();
  });

  it('creates one bootstrap administrator atomically and exact replay does not duplicate it', async () => {
    const targetUserId = await insertUser(source, plan, 'bootstrap-target@example.test');
    const bootstrap = randomBytes(32);
    const recovery = randomBytes(32);
    const service = createService(source, bootstrap, recovery);
    const command = operatorCommand(targetUserId, bootstrap);

    await expect(service.execute(command)).resolves.toEqual({
      code: 'access_administration_completed',
    });
    await expect(service.execute(command)).resolves.toEqual({
      code: 'access_administration_completed',
    });

    expect(await countRows(source, plan, 'identity_access_capabilities')).toBe(1);
    expect(await countRows(source, plan, 'identity_access_changes')).toBe(1);
    expect(await countRows(source, plan, 'identity_access_command_receipts')).toBe(1);
    await expect(service.readReceipt({ command })).resolves.toEqual({
      code: 'access_administration_completed',
    });
  });

  it('enforces durable capability constraints and immutable journal rows', async () => {
    const firstUserId = await insertUser(source, plan, 'capability-first@example.test');
    const secondUserId = await insertUser(source, plan, 'capability-second@example.test');

    await source.query(
      `INSERT INTO "${plan.schemaName}".identity_access_capabilities (user_id, capability, active) VALUES ($1, 'instructor', true)`,
      [firstUserId],
    );
    await expect(
      source.query(
        `INSERT INTO "${plan.schemaName}".identity_access_capabilities (user_id, capability, active) VALUES ($1, 'instructor', true)`,
        [firstUserId],
      ),
    ).rejects.toMatchObject({
      driverError: {
        code: '23505',
        constraint: 'uq_identity_access_capability_active',
      },
    });
    await expect(
      source.query(
        `INSERT INTO "${plan.schemaName}".identity_access_capabilities (user_id, capability, active) VALUES ($1, 'instructor', false)`,
        [firstUserId],
      ),
    ).resolves.toBeDefined();
    expect(await activeCapabilities(source, plan, firstUserId)).toEqual(['instructor']);
    await expect(
      source.query(
        `INSERT INTO "${plan.schemaName}".identity_access_capabilities (user_id, capability, active) VALUES ($1, 'content_moderator', true)`,
        [firstUserId],
      ),
    ).rejects.toThrow('incompatible active capability combination');
    await expect(
      source.query(
        `INSERT INTO "${plan.schemaName}".identity_access_capabilities (user_id, capability, active) VALUES ($1, 'invalid', true)`,
        [secondUserId],
      ),
    ).rejects.toThrow();
    await expect(
      source.query(
        `INSERT INTO "${plan.schemaName}".identity_access_capabilities (user_id, capability, active) VALUES ($1, 'content_moderator', true), ($1, 'administrator', true)`,
        [secondUserId],
      ),
    ).resolves.toBeDefined();

    const commandId = randomUUID();
    await source.query(
      `INSERT INTO "${plan.schemaName}".identity_access_changes (command_id, target_user_id, principal_kind, principal_binding, action, capability, before_active, after_active, reason, reference) VALUES ($1, $2, 'bootstrap', 'trusted-server-bootstrap', 'grant', 'administrator', false, true, 'test', 'test')`,
      [commandId, firstUserId],
    );
    await expect(
      source.query(
        `UPDATE "${plan.schemaName}".identity_access_changes SET reason = 'changed' WHERE command_id = $1`,
        [commandId],
      ),
    ).rejects.toThrow('identity access changes are immutable');
  });

  it('denies valid ordinary sessions and preserves session state during access changes', async () => {
    const administratorId = await insertUser(source, plan, 'administrator@example.test');
    const ordinaryId = await insertUser(source, plan, 'ordinary@example.test');
    const targetId = await insertUser(source, plan, 'target@example.test');
    const bootstrap = randomBytes(32);
    const recovery = randomBytes(32);
    const service = createService(source, bootstrap, recovery);
    await service.execute(operatorCommand(administratorId, bootstrap));
    const tokenHash = randomBytes(32).toString('hex');
    const sessionId = randomUUID();
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
    await source.query(
      `INSERT INTO "${plan.schemaName}".identity_sessions (id, user_id, token_hash, csrf_token_hash, state, created_at, last_seen_at, absolute_expires_at, idle_expires_at, revoked_at) VALUES ($1, $2, $3, $4, 'authenticated', clock_timestamp(), clock_timestamp(), $5, $5, NULL)`,
      [sessionId, ordinaryId, tokenHash, randomBytes(32).toString('hex'), expiresAt],
    );

    await expect(
      service.execute({
        kind: 'administrator',
        actorSessionId: sessionId,
        actorTokenHash: tokenHash,
        commandId: randomUUID(),
        targetUserId: targetId,
        action: 'grant',
        capability: 'instructor',
        reason: 'ordinary request',
        reference: 'T4 independent proof',
      }),
    ).resolves.toEqual({ code: 'access_administration_forbidden' });

    const rows = await source.query(
      `SELECT state, revoked_at AS "revokedAt" FROM "${plan.schemaName}".identity_sessions WHERE id = $1`,
      [sessionId],
    );
    expect(rows).toEqual([{ state: 'authenticated', revokedAt: null }]);
    expect(await countRows(source, plan, 'identity_access_changes')).toBe(1);
  });

  it('allows a current administrator to grant and revoke, denies the last administrator, and leaves sessions untouched', async () => {
    const administratorId = await insertUser(source, plan, 'ordinary-administrator@example.test');
    const targetId = await insertUser(source, plan, 'ordinary-target@example.test');
    const bootstrap = randomBytes(32);
    const service = createService(source, bootstrap, randomBytes(32));
    await expect(service.execute(operatorCommand(administratorId, bootstrap))).resolves.toEqual({
      code: 'access_administration_completed',
    });
    const session = await insertAuthenticatedSession(source, plan, administratorId);
    const before = await sessionSnapshot(source, plan, session.id);

    await expect(
      service.execute(administratorCommand(session, targetId, 'grant', 'instructor')),
    ).resolves.toEqual({ code: 'access_administration_completed' });
    await expect(
      service.execute(administratorCommand(session, targetId, 'revoke', 'instructor')),
    ).resolves.toEqual({ code: 'access_administration_completed' });
    await expect(
      service.execute(administratorCommand(session, targetId, 'grant', 'administrator')),
    ).resolves.toEqual({ code: 'access_administration_completed' });
    expect(await activeCapabilities(source, plan, targetId)).toEqual(['administrator']);
    await expect(
      service.execute(administratorCommand(session, targetId, 'revoke', 'administrator')),
    ).resolves.toEqual({ code: 'access_administration_completed' });
    await expect(
      service.execute(administratorCommand(session, administratorId, 'revoke', 'administrator')),
    ).resolves.toEqual({ code: 'access_administration_forbidden' });

    expect(await sessionSnapshot(source, plan, session.id)).toEqual(before);
    expect(await activeCapabilities(source, plan, targetId)).toEqual([]);
    expect(await activeCapabilities(source, plan, administratorId)).toEqual(['administrator']);
  });

  it('binds completed receipts to the authenticated administrator and makes response-loss readback mutation-free', async () => {
    const primaryAdministratorId = await insertUser(source, plan, 'receipt-primary@example.test');
    const secondAdministratorId = await insertUser(source, plan, 'receipt-second@example.test');
    const targetId = await insertUser(source, plan, 'receipt-target@example.test');
    const bootstrap = randomBytes(32);
    const service = createService(source, bootstrap, randomBytes(32));
    await service.execute(operatorCommand(primaryAdministratorId, bootstrap));
    await grantAdministratorFixture(source, plan, secondAdministratorId);
    const primarySession = await insertAuthenticatedSession(source, plan, primaryAdministratorId);
    const secondSession = await insertAuthenticatedSession(source, plan, secondAdministratorId);
    const command = administratorCommand(primarySession, targetId, 'grant', 'instructor');

    await expect(service.execute(command)).resolves.toEqual({
      code: 'access_administration_completed',
    });
    const countsAfterCommit = await accessCounts(source, plan);
    await expect(service.readReceipt({ command })).resolves.toEqual({
      code: 'access_administration_completed',
    });
    await expect(
      service.execute({ ...command, reason: 'different semantic payload' }),
    ).resolves.toEqual({ code: 'access_administration_conflict' });
    await expect(
      service.execute({
        ...command,
        actorSessionId: secondSession.id,
        actorTokenHash: secondSession.tokenHash,
      }),
    ).resolves.toEqual({ code: 'access_administration_conflict' });

    expect(await accessCounts(source, plan)).toEqual(countsAfterCommit);
  });

  it('forbids a revoked administrator while retaining the valid session snapshot', async () => {
    const actingAdministratorId = await insertUser(source, plan, 'revoker@example.test');
    const revokedAdministratorId = await insertUser(
      source,
      plan,
      'revoked-administrator@example.test',
    );
    const targetId = await insertUser(source, plan, 'revoked-target@example.test');
    const bootstrap = randomBytes(32);
    const service = createService(source, bootstrap, randomBytes(32));
    await service.execute(operatorCommand(actingAdministratorId, bootstrap));
    await grantAdministratorFixture(source, plan, revokedAdministratorId);
    const actingSession = await insertAuthenticatedSession(source, plan, actingAdministratorId);
    const revokedSession = await insertAuthenticatedSession(source, plan, revokedAdministratorId);
    const before = await sessionSnapshot(source, plan, revokedSession.id);

    await expect(
      service.execute(
        administratorCommand(actingSession, revokedAdministratorId, 'revoke', 'administrator'),
      ),
    ).resolves.toEqual({ code: 'access_administration_completed' });
    await expect(
      service.execute(administratorCommand(revokedSession, targetId, 'grant', 'instructor')),
    ).resolves.toEqual({ code: 'access_administration_forbidden' });

    expect(await sessionSnapshot(source, plan, revokedSession.id)).toEqual(before);
    expect(await activeCapabilities(source, plan, revokedAdministratorId)).toEqual([]);
  });

  it('rejects both incompatible grants as conflicts without writes, while exact authorized replay wins over later state', async () => {
    const administratorId = await insertUser(source, plan, 'pair-administrator@example.test');
    const instructorTargetId = await insertUser(source, plan, 'pair-instructor@example.test');
    const moderatorTargetId = await insertUser(source, plan, 'pair-moderator@example.test');
    const ordinaryId = await insertUser(source, plan, 'pair-ordinary@example.test');
    const bootstrap = randomBytes(32);
    const service = createService(source, bootstrap, randomBytes(32));
    await service.execute(operatorCommand(administratorId, bootstrap));
    const administrator = await insertAuthenticatedSession(source, plan, administratorId);
    const ordinary = await insertAuthenticatedSession(source, plan, ordinaryId);
    await source.query(
      `INSERT INTO "${plan.schemaName}".identity_access_capabilities (user_id, capability, active) VALUES ($1, 'content_moderator', true), ($2, 'instructor', true)`,
      [instructorTargetId, moderatorTargetId],
    );

    const beforeConflicts = await accessCounts(source, plan);
    await expect(
      service.execute(
        administratorCommand(administrator, instructorTargetId, 'grant', 'instructor'),
      ),
    ).resolves.toEqual({ code: 'access_administration_conflict' });
    await expect(
      service.execute(
        administratorCommand(administrator, moderatorTargetId, 'grant', 'content_moderator'),
      ),
    ).resolves.toEqual({ code: 'access_administration_conflict' });
    expect(await accessCounts(source, plan)).toEqual(beforeConflicts);

    await expect(
      service.execute(administratorCommand(ordinary, instructorTargetId, 'grant', 'instructor')),
    ).resolves.toEqual({ code: 'access_administration_forbidden' });
    expect(await accessCounts(source, plan)).toEqual(beforeConflicts);

    const replayTargetId = await insertUser(source, plan, 'pair-replay@example.test');
    const completed = administratorCommand(administrator, replayTargetId, 'grant', 'instructor');
    await expect(service.execute(completed)).resolves.toEqual({
      code: 'access_administration_completed',
    });
    await expect(
      service.execute(administratorCommand(administrator, replayTargetId, 'revoke', 'instructor')),
    ).resolves.toEqual({ code: 'access_administration_completed' });
    await expect(
      service.execute(
        administratorCommand(administrator, replayTargetId, 'grant', 'content_moderator'),
      ),
    ).resolves.toEqual({ code: 'access_administration_completed' });
    const beforeReplay = await accessCounts(source, plan);
    await expect(service.execute(completed)).resolves.toEqual({
      code: 'access_administration_completed',
    });
    expect(await accessCounts(source, plan)).toEqual(beforeReplay);
  });

  it('rolls back the pending receipt, projection, and journal when the real receipt completion collaborator fails', async () => {
    const targetId = await insertUser(source, plan, 'rollback-target@example.test');
    const bootstrap = randomBytes(32);
    const service = new IdentityAccessAdministrationService(
      new FailingReceiptCompletionTransactions(new TypeOrmIdentityTransactionAdapter(source)),
      new ConfigOperatorCredentialVerifier(
        IdentityAccessAdministrationCredentialsConfig.from({
          IDENTITY_ACCESS_BOOTSTRAP_CREDENTIAL: bootstrap.toString('base64url'),
          IDENTITY_ACCESS_RECOVERY_CREDENTIAL: randomBytes(32).toString('base64url'),
        }),
      ),
    );

    await expect(service.execute(operatorCommand(targetId, bootstrap))).resolves.toEqual({
      code: 'access_administration_unavailable',
    });
    expect(await accessCounts(source, plan)).toEqual({ capabilities: 0, changes: 0, receipts: 0 });
  });

  it('enforces completed-receipt and journal immutability with a durable before-after link', async () => {
    const targetId = await insertUser(source, plan, 'immutable-target@example.test');
    const bootstrap = randomBytes(32);
    const service = createService(source, bootstrap, randomBytes(32));
    const command = operatorCommand(targetId, bootstrap);
    await service.execute(command);
    const receiptRows = await source.query(
      `SELECT change_id AS "changeId", state FROM "${plan.schemaName}".identity_access_command_receipts WHERE command_id = $1`,
      [command.commandId],
    );
    expect(receiptRows).toEqual([{ changeId: expect.any(String), state: 'completed' }]);
    await expect(
      source.query(
        `UPDATE "${plan.schemaName}".identity_access_command_receipts SET reference = 'changed' WHERE command_id = $1`,
        [command.commandId],
      ),
    ).rejects.toThrow('invalid identity access receipt transition');
    await expect(
      source.query(
        `DELETE FROM "${plan.schemaName}".identity_access_command_receipts WHERE command_id = $1`,
        [command.commandId],
      ),
    ).rejects.toThrow('identity access receipts are immutable');
    await expect(
      source.query(
        `DELETE FROM "${plan.schemaName}".identity_access_changes WHERE command_id = $1`,
        [command.commandId],
      ),
    ).rejects.toThrow('identity access changes are immutable');
  });

  it('records course and enrollment state as unavailable because the migrated product schema has neither table', async () => {
    const rows = await source.query(
      `SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_name IN ('courses', 'enrollments')`,
      [plan.schemaName],
    );
    expect(rows).toEqual([]);
  });

  it('rolls back an actual same-command receipt collision, then freshly reauthorizes before receipt-only reload', async () => {
    const firstAdministratorId = await insertUser(
      source,
      plan,
      'collision-first-admin@example.test',
    );
    const secondAdministratorId = await insertUser(
      source,
      plan,
      'collision-second-admin@example.test',
    );
    const firstTargetId = await insertUser(source, plan, 'collision-first-target@example.test');
    const secondTargetId = await insertUser(source, plan, 'collision-second-target@example.test');
    const bootstrap = randomBytes(32);
    const recovery = randomBytes(32);
    const bootstrapService = createService(source, bootstrap, recovery);
    await bootstrapService.execute(operatorCommand(firstAdministratorId, bootstrap));
    await grantAdministratorFixture(source, plan, secondAdministratorId);
    const firstSession = await insertAuthenticatedSession(source, plan, firstAdministratorId);
    const secondSession = await insertAuthenticatedSession(source, plan, secondAdministratorId);
    const other = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
    await other.initialize();
    const firstTransactions = new ObservingAuthorizationTransactions(
      new TypeOrmIdentityTransactionAdapter(source),
    );
    const secondTransactions = new ObservingAuthorizationTransactions(
      new TypeOrmIdentityTransactionAdapter(other),
    );
    const firstService = createServiceWithTransactions(firstTransactions, bootstrap, recovery);
    const secondService = createServiceWithTransactions(secondTransactions, bootstrap, recovery);
    const commandId = randomUUID();
    const holder = await holdReceiptInsertBarrier(source, plan);
    try {
      const first = firstService.execute({
        ...administratorCommand(firstSession, firstTargetId, 'grant', 'instructor'),
        commandId,
      });
      const second = secondService.execute({
        ...administratorCommand(secondSession, secondTargetId, 'grant', 'instructor'),
        commandId,
      });
      await waitForReceiptBarrierWaiters(source);
      await releaseTransaction(holder);
      const outcomes = await Promise.all([first, second]);

      expect(outcomes).toEqual(
        expect.arrayContaining([
          { code: 'access_administration_completed' },
          { code: 'access_administration_conflict' },
        ]),
      );
      expect(firstTransactions.authenticatedLookups + secondTransactions.authenticatedLookups).toBe(
        3,
      );
      expect(await accessCounts(source, plan)).toEqual({
        capabilities: 3,
        changes: 2,
        receipts: 2,
      });
      expect(
        (await activeCapabilities(source, plan, firstTargetId)).length +
          (await activeCapabilities(source, plan, secondTargetId)).length,
      ).toBe(1);
    } finally {
      if (holder.isReleased !== true) await releaseTransaction(holder);
      if (other.isInitialized) await other.destroy();
    }
  });
});

function createService(
  source: DataSource,
  bootstrap: Buffer,
  recovery: Buffer,
): IdentityAccessAdministrationService {
  const config = IdentityAccessAdministrationCredentialsConfig.from({
    IDENTITY_ACCESS_BOOTSTRAP_CREDENTIAL: bootstrap.toString('base64url'),
    IDENTITY_ACCESS_RECOVERY_CREDENTIAL: recovery.toString('base64url'),
  });
  return new IdentityAccessAdministrationService(
    new TypeOrmIdentityTransactionAdapter(source),
    new ConfigOperatorCredentialVerifier(config),
  );
}

function createServiceWithTransactions(
  transactions: IdentityTransactionPort,
  bootstrap: Buffer,
  recovery: Buffer,
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

function operatorCommand(targetUserId: string, credential: Buffer) {
  return {
    kind: 'operator' as const,
    purpose: 'bootstrap' as const,
    credential,
    commandId: randomUUID(),
    targetUserId,
    action: 'grant' as const,
    capability: 'administrator' as const,
    reason: 'initial bootstrap',
    reference: 'T3 independent proof',
  };
}

function administratorCommand(
  session: AuthenticatedSession,
  targetUserId: string,
  action: AdministrationAction,
  capability: AdministrationCapability,
) {
  return {
    kind: 'administrator' as const,
    actorSessionId: session.id,
    actorTokenHash: session.tokenHash,
    commandId: randomUUID(),
    targetUserId,
    action,
    capability,
    reason: 'independent service acceptance proof',
    reference: 'BE-BFI005-TE-SERVICE-COMPLETE-20261018-T1',
  };
}

async function insertUser(
  source: DataSource,
  plan: IsolatedPostgresPlan,
  email: string,
): Promise<string> {
  const id = randomUUID();
  await source.query(
    `INSERT INTO "${plan.schemaName}".identity_users (id, normalized_email, password_hash, created_at, updated_at) VALUES ($1, $2, $3, clock_timestamp(), clock_timestamp())`,
    [id, email, 'synthetic-test-password-hash'],
  );
  return id;
}

async function countRows(
  source: DataSource,
  plan: IsolatedPostgresPlan,
  table: string,
): Promise<number> {
  const rows = await source.query(
    `SELECT count(*)::int AS count FROM "${plan.schemaName}".${table}`,
  );
  const [row] = rows as readonly unknown[];
  if (typeof row !== 'object' || row === null || Array.isArray(row)) {
    throw new Error('Unexpected access-administration count row.');
  }
  const count = (row as Record<string, unknown>).count;
  if (typeof count !== 'number') throw new Error('Unexpected access-administration count.');
  return count;
}

interface AuthenticatedSession {
  readonly id: string;
  readonly tokenHash: string;
}

interface SessionSnapshot {
  readonly state: string;
  readonly revokedAt: Date | null;
  readonly lastSeenAt: Date;
  readonly idleExpiresAt: Date;
}

interface AccessCounts {
  readonly capabilities: number;
  readonly changes: number;
  readonly receipts: number;
}

class FailingReceiptCompletionTransactions implements IdentityTransactionPort {
  public constructor(private readonly transactions: IdentityTransactionPort) {}

  public async run<Result>(work: IdentityTransactionWork<Result>): Promise<Result> {
    return this.transactions.run({
      execute: async (scope) =>
        work.execute({
          ...scope,
          accessReceipts: {
            findByCommandId: (commandId) => scope.accessReceipts.findByCommandId(commandId),
            insertPending: (receipt) => scope.accessReceipts.insertPending(receipt),
            complete: async () => {
              throw new Error(
                'Injected receipt completion failure after real pending/projection/journal.',
              );
            },
          },
        }),
    });
  }
}

class ObservingAuthorizationTransactions implements IdentityTransactionPort {
  public authenticatedLookups = 0;

  public constructor(private readonly transactions: IdentityTransactionPort) {}

  public async run<Result>(work: IdentityTransactionWork<Result>): Promise<Result> {
    return this.transactions.run({
      execute: async (scope) => {
        const sessions = Object.create(scope.sessions) as typeof scope.sessions;
        sessions.findAccessAdministrationCurrentLockedAuthenticated = async (id, tokenHash) => {
          this.authenticatedLookups += 1;
          return scope.sessions.findAccessAdministrationCurrentLockedAuthenticated(id, tokenHash);
        };
        return work.execute({ ...scope, sessions });
      },
    });
  }
}

async function insertAuthenticatedSession(
  source: DataSource,
  plan: IsolatedPostgresPlan,
  userId: string,
): Promise<AuthenticatedSession> {
  const session: AuthenticatedSession = {
    id: randomUUID(),
    tokenHash: randomBytes(32).toString('hex'),
  };
  const expiresAt = new Date(Date.now() + 3_600_000);
  await source.query(
    `INSERT INTO "${plan.schemaName}".identity_sessions (id, user_id, token_hash, csrf_token_hash, state, created_at, last_seen_at, absolute_expires_at, idle_expires_at, revoked_at) VALUES ($1, $2, $3, $4, 'authenticated', clock_timestamp(), clock_timestamp(), $5, $5, NULL)`,
    [session.id, userId, session.tokenHash, randomBytes(32).toString('hex'), expiresAt],
  );
  return session;
}

async function grantAdministratorFixture(
  source: DataSource,
  plan: IsolatedPostgresPlan,
  userId: string,
): Promise<void> {
  await source.query(
    `INSERT INTO "${plan.schemaName}".identity_access_capabilities (user_id, capability, active) VALUES ($1, 'administrator', true)`,
    [userId],
  );
}

async function activeCapabilities(
  source: DataSource,
  plan: IsolatedPostgresPlan,
  userId: string,
): Promise<readonly string[]> {
  const rows = await source.query(
    `SELECT capability FROM "${plan.schemaName}".identity_access_capabilities WHERE user_id = $1 AND active ORDER BY capability`,
    [userId],
  );
  if (!Array.isArray(rows)) throw new Error('Unexpected capability rows.');
  return rows.map((row) => {
    if (typeof row !== 'object' || row === null || Array.isArray(row)) {
      throw new Error('Unexpected capability row.');
    }
    const capability = (row as Record<string, unknown>).capability;
    if (typeof capability !== 'string') throw new Error('Unexpected capability value.');
    return capability;
  });
}

async function accessCounts(source: DataSource, plan: IsolatedPostgresPlan): Promise<AccessCounts> {
  return {
    capabilities: await countRows(source, plan, 'identity_access_capabilities'),
    changes: await countRows(source, plan, 'identity_access_changes'),
    receipts: await countRows(source, plan, 'identity_access_command_receipts'),
  };
}

async function sessionSnapshot(
  source: DataSource,
  plan: IsolatedPostgresPlan,
  sessionId: string,
): Promise<SessionSnapshot> {
  const rows = await source.query(
    `SELECT state, revoked_at AS "revokedAt", last_seen_at AS "lastSeenAt", idle_expires_at AS "idleExpiresAt" FROM "${plan.schemaName}".identity_sessions WHERE id = $1`,
    [sessionId],
  );
  if (!Array.isArray(rows) || rows.length !== 1)
    throw new Error('Expected exactly one session snapshot.');
  const [row] = rows;
  if (typeof row !== 'object' || row === null || Array.isArray(row)) {
    throw new Error('Unexpected session snapshot row.');
  }
  const snapshot = row as Record<string, unknown>;
  if (
    typeof snapshot.state !== 'string' ||
    !(snapshot.lastSeenAt instanceof Date) ||
    !(snapshot.idleExpiresAt instanceof Date) ||
    (snapshot.revokedAt !== null && !(snapshot.revokedAt instanceof Date))
  ) {
    throw new Error('Unexpected session snapshot values.');
  }
  return {
    state: snapshot.state,
    revokedAt: snapshot.revokedAt,
    lastSeenAt: snapshot.lastSeenAt,
    idleExpiresAt: snapshot.idleExpiresAt,
  };
}

const RECEIPT_INSERT_BARRIER_KEY = 900_001;

async function holdReceiptInsertBarrier(
  source: DataSource,
  plan: IsolatedPostgresPlan,
): Promise<QueryRunner> {
  await source.query(
    `CREATE OR REPLACE FUNCTION "${plan.schemaName}".receipt_insert_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(${RECEIPT_INSERT_BARRIER_KEY}); RETURN NEW; END $$; CREATE TRIGGER receipt_insert_barrier BEFORE INSERT ON "${plan.schemaName}".identity_access_command_receipts FOR EACH ROW EXECUTE FUNCTION "${plan.schemaName}".receipt_insert_barrier()`,
  );
  const holder = source.createQueryRunner();
  await holder.connect();
  await holder.startTransaction();
  await holder.query('SELECT pg_advisory_xact_lock($1)', [RECEIPT_INSERT_BARRIER_KEY]);
  return holder;
}

async function waitForReceiptBarrierWaiters(source: DataSource): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const rows = await source.query(
      "SELECT count(*)::int AS count FROM pg_locks WHERE locktype = 'advisory' AND NOT granted",
    );
    if (readCount(rows) >= 2) return;
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('Both collision contenders did not reach the PostgreSQL receipt barrier.');
}

async function releaseTransaction(runner: QueryRunner): Promise<void> {
  try {
    if (runner.isTransactionActive) await runner.rollbackTransaction();
  } finally {
    if (!runner.isReleased) await runner.release();
  }
}

function readCount(rows: unknown): number {
  if (!Array.isArray(rows) || rows.length !== 1) throw new Error('Unexpected lock count rows.');
  const [row] = rows;
  if (typeof row !== 'object' || row === null || Array.isArray(row)) {
    throw new Error('Unexpected lock count row.');
  }
  const count = (row as Record<string, unknown>).count;
  if (typeof count !== 'number') throw new Error('Unexpected lock count value.');
  return count;
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
