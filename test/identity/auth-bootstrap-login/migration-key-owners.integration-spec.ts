import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';

import { DataSource, QueryRunner } from 'typeorm';

import { InitialIdentityPersistence1760194800000 } from '../../../src/migrations/1760194800000-initial-identity-persistence';
import { AddIdentityPersistenceInvariants1760194800001 } from '../../../src/migrations/1760194800001-add-identity-persistence-invariants';
import { AddIdentityThrottleKeyOwners1760270400000 } from '../../../src/migrations/1760270400000-add-identity-throttle-key-owners';
import { AddIdentityBootstrapRetentionIndex1760356800000 } from '../../../src/migrations/1760356800000-add-identity-bootstrap-retention-index';
import { AddIdentityThrottleRetentionIndexes1760443200000 } from '../../../src/migrations/1760443200000-add-identity-throttle-retention-indexes';
import {
  createIdentityDataSource,
  createIdentityDatabaseOptions,
} from '../../../src/shared/database/identity-database-options';
import {
  createIsolatedPostgresDatabaseOptions,
  createIsolatedPostgresEnvironment,
  createIsolatedPostgresPlan,
  IsolatedPostgresPlan,
  startIsolatedPostgres,
} from '../../support/isolated-postgres-harness';

describe('Identity throttle key-owner migration', () => {
  it('adds one durable owner per key when predecessors contain unique keys', async () => {
    await withLegacySchema(async (source, runner, plan) => {
      await seedThrottleRows(runner, plan, 'unique');
      await new AddIdentityThrottleKeyOwners1760270400000().up(runner);

      await expect(
        runner.query(
          `INSERT INTO ${plan.schemaName}.identity_login_throttles (id, key_hash, window_started_at, expires_at, failure_count) VALUES ($1, $2, NOW(), NOW() + INTERVAL '15 minutes', 0)`,
          [randomUUID(), key('c')],
        ),
      ).rejects.toThrow();
      expect(source.isInitialized).toBe(true);
    });
  });

  it('fails on legacy duplicate keys without delete, merge, rewrite, or partial constraint application', async () => {
    await withLegacySchema(async (_source, runner, plan) => {
      await seedThrottleRows(runner, plan, 'duplicate');
      const before = await readThrottlePreimage(runner, plan);

      await runner.startTransaction();
      try {
        await expect(new AddIdentityThrottleKeyOwners1760270400000().up(runner)).rejects.toThrow(
          'incompatible duplicate key ownership',
        );
      } finally {
        await runner.rollbackTransaction();
      }

      expect(await readThrottlePreimage(runner, plan)).toEqual(before);
      await expect(
        runner.query(
          `INSERT INTO ${plan.schemaName}.identity_registration_throttles (id, key_hash, window_started_at, expires_at, attempt_count) VALUES ($1, $2, NOW(), NOW() + INTERVAL '15 minutes', 0)`,
          [randomUUID(), key('d')],
        ),
      ).resolves.toBeDefined();
    });
  });

  it('registers forward-only immutable bootstrap retention indexes', async () => {
    await withLegacySchema(async (source, runner, plan) => {
      await new AddIdentityThrottleKeyOwners1760270400000().up(runner);
      await new AddIdentityBootstrapRetentionIndex1760356800000().up(runner);

      expect(source.migrations.map((migration) => migration.constructor)).toContain(
        AddIdentityBootstrapRetentionIndex1760356800000,
      );
      expect(await readSessionIndexes(runner, plan)).toEqual([
        expect.objectContaining({
          indexname: 'idx_identity_session_pre_auth_expiry',
          indexdef: expect.stringContaining("WHERE ((state)::text = 'pre_auth'::text)"),
        }),
        expect.objectContaining({
          indexname: 'idx_identity_session_revoked_pre_auth',
          indexdef: expect.stringContaining(
            "WHERE (((state)::text = 'revoked'::text) AND (user_id IS NULL))",
          ),
        }),
      ]);
      const definitions = (await readSessionIndexes(runner, plan)).map((index) => index.indexdef);
      expect(definitions.join('\n')).not.toContain('now()');
    });
  });

  it('discovers and applies the registered throttle-retention migration after preserved owner rows', async () => {
    const plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(
        randomBytes(32).toString('hex'),
        await selectLoopbackPort(),
      ),
    );
    const run = await startIsolatedPostgres(plan);
    const options = createIsolatedPostgresDatabaseOptions(plan);
    const registered = createIdentityDataSource(options);
    const legacy = new DataSource({
      ...createIdentityDatabaseOptions(options),
      migrations: [
        InitialIdentityPersistence1760194800000,
        AddIdentityPersistenceInvariants1760194800001,
        AddIdentityThrottleKeyOwners1760270400000,
        AddIdentityBootstrapRetentionIndex1760356800000,
      ],
    });
    let runner: QueryRunner | undefined;
    try {
      await legacy.initialize();
      await legacy.query(`CREATE SCHEMA "${plan.schemaName}"`);
      await legacy.runMigrations();
      runner = legacy.createQueryRunner();
      await runner.connect();
      await seedThrottleRows(runner, plan, 'unique');
      await runner.release();
      runner = undefined;
      await legacy.destroy();

      await registered.initialize();
      expect(registered.migrations.map((migration) => migration.constructor)).toEqual([
        InitialIdentityPersistence1760194800000,
        AddIdentityPersistenceInvariants1760194800001,
        AddIdentityThrottleKeyOwners1760270400000,
        AddIdentityBootstrapRetentionIndex1760356800000,
        AddIdentityThrottleRetentionIndexes1760443200000,
      ]);
      await registered.runMigrations();
      expect(await readThrottleRows(registered, plan)).toHaveLength(4);
      await expect(
        registered.query(
          `INSERT INTO "${plan.schemaName}".identity_registration_throttles (id, key_hash, window_started_at, expires_at, attempt_count) VALUES ($1, $2, NOW(), NOW() + INTERVAL '15 minutes', 0)`,
          [randomUUID(), key('a')],
        ),
      ).rejects.toThrow();
      await expect(
        registered.query(
          `INSERT INTO "${plan.schemaName}".identity_login_throttles (id, key_hash, window_started_at, expires_at, failure_count) VALUES ($1, $2, NOW(), NOW() + INTERVAL '15 minutes', 0)`,
          [randomUUID(), key('c')],
        ),
      ).rejects.toThrow();
      expect(await readThrottleIndexes(registered, plan)).toEqual([
        expect.objectContaining({
          indexname: 'idx_identity_login_throttle_expiry',
          indexdef: expect.stringContaining('(expires_at, id)'),
        }),
        expect.objectContaining({
          indexname: 'idx_identity_registration_throttle_expiry',
          indexdef: expect.stringContaining('(expires_at, id)'),
        }),
      ]);
    } finally {
      if (runner !== undefined) await runner.release();
      if (legacy.isInitialized) await legacy.destroy();
      if (registered.isInitialized) await registered.destroy();
      await run.cleanup();
    }
  });
});

type LegacyThrottleSeedMode = 'unique' | 'duplicate';

async function withLegacySchema(
  action: (source: DataSource, runner: QueryRunner, plan: IsolatedPostgresPlan) => Promise<void>,
): Promise<void> {
  const plan = createIsolatedPostgresPlan(
    createIsolatedPostgresEnvironment(randomBytes(32).toString('hex'), await selectLoopbackPort()),
  );
  const run = await startIsolatedPostgres(plan);
  const source = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
  let runner: QueryRunner | undefined;
  try {
    await source.initialize();
    runner = source.createQueryRunner();
    await runner.connect();
    await runner.query(`CREATE SCHEMA "${plan.schemaName}"`);
    await new InitialIdentityPersistence1760194800000().up(runner);
    await new AddIdentityPersistenceInvariants1760194800001().up(runner);
    await action(source, runner, plan);
  } finally {
    if (runner !== undefined) await runner.release();
    if (source.isInitialized) await source.destroy();
    await run.cleanup();
  }
}

async function seedThrottleRows(
  runner: QueryRunner,
  plan: IsolatedPostgresPlan,
  mode: LegacyThrottleSeedMode,
): Promise<void> {
  const registrationKeys = mode === 'duplicate' ? [key('a'), key('a')] : [key('a'), key('b')];
  const loginKeys = mode === 'duplicate' ? [key('c'), key('c')] : [key('c'), key('d')];
  for (const value of registrationKeys) {
    await runner.query(
      `INSERT INTO ${plan.schemaName}.identity_registration_throttles (id, key_hash, window_started_at, expires_at, attempt_count) VALUES ($1, $2, NOW(), NOW() + INTERVAL '15 minutes', 1)`,
      [randomUUID(), value],
    );
  }
  for (const value of loginKeys) {
    await runner.query(
      `INSERT INTO ${plan.schemaName}.identity_login_throttles (id, key_hash, window_started_at, expires_at, failure_count) VALUES ($1, $2, NOW(), NOW() + INTERVAL '15 minutes', 1)`,
      [randomUUID(), value],
    );
  }
}

async function readThrottlePreimage(
  runner: QueryRunner,
  plan: IsolatedPostgresPlan,
): Promise<readonly unknown[]> {
  return runner.query(
    `SELECT 'registration' AS table_name, key_hash, attempt_count AS count FROM ${plan.schemaName}.identity_registration_throttles UNION ALL SELECT 'login' AS table_name, key_hash, failure_count AS count FROM ${plan.schemaName}.identity_login_throttles ORDER BY table_name, key_hash, count`,
  );
}

async function readThrottleRows(
  source: DataSource,
  plan: IsolatedPostgresPlan,
): Promise<readonly unknown[]> {
  return source.query(
    `SELECT key_hash FROM "${plan.schemaName}".identity_registration_throttles UNION ALL SELECT key_hash FROM "${plan.schemaName}".identity_login_throttles`,
  );
}

type ThrottleIndex = { readonly indexname: string; readonly indexdef: string };

async function readThrottleIndexes(
  source: DataSource,
  plan: IsolatedPostgresPlan,
): Promise<readonly ThrottleIndex[]> {
  const rows = await source.query(
    `SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = $1 AND indexname IN ('idx_identity_login_throttle_expiry', 'idx_identity_registration_throttle_expiry') ORDER BY indexname`,
    [plan.schemaName],
  );
  if (!Array.isArray(rows)) throw new Error('Unexpected throttle index rows.');
  return rows.map((row) => {
    if (typeof row !== 'object' || row === null || Array.isArray(row)) {
      throw new Error('Unexpected throttle index row.');
    }
    const indexname = (row as Record<string, unknown>).indexname;
    const indexdef = (row as Record<string, unknown>).indexdef;
    if (typeof indexname !== 'string' || typeof indexdef !== 'string') {
      throw new Error('Unexpected throttle index values.');
    }
    return { indexname, indexdef };
  });
}

function key(character: string): string {
  return character.repeat(64);
}

type SessionIndex = { readonly indexname: string; readonly indexdef: string };

async function readSessionIndexes(
  runner: QueryRunner,
  plan: IsolatedPostgresPlan,
): Promise<readonly SessionIndex[]> {
  const rows = await runner.query(
    `SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = $1 AND tablename = 'identity_sessions' AND indexname IN ('idx_identity_session_pre_auth_expiry', 'idx_identity_session_revoked_pre_auth') ORDER BY indexname`,
    [plan.schemaName],
  );
  if (!Array.isArray(rows)) throw new Error('Unexpected identity session index rows.');
  return rows.map((row) => {
    if (typeof row !== 'object' || row === null || Array.isArray(row)) {
      throw new Error('Unexpected identity session index row.');
    }
    const indexname = (row as Record<string, unknown>).indexname;
    const indexdef = (row as Record<string, unknown>).indexdef;
    if (typeof indexname !== 'string' || typeof indexdef !== 'string') {
      throw new Error('Unexpected identity session index values.');
    }
    return { indexname, indexdef };
  });
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
