import { randomBytes } from 'node:crypto';
import { createServer } from 'node:net';

import { DataSource } from 'typeorm';

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

describe('Identity access-administration migration', () => {
  it('registers durable capability, journal, and command-receipt storage', async () => {
    const plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(
        randomBytes(32).toString('hex'),
        await selectLoopbackPort(),
      ),
    );
    const run = await startIsolatedPostgres(plan);
    const source = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));

    try {
      await source.initialize();
      await source.query(`CREATE SCHEMA "${plan.schemaName}"`);
      await source.runMigrations();

      expect(await accessAdministrationTables(source, plan)).toEqual([
        'identity_access_capabilities',
        'identity_access_changes',
        'identity_access_command_receipts',
      ]);
    } finally {
      if (source.isInitialized) await source.destroy();
      await run.cleanup();
    }
  });
});

async function accessAdministrationTables(
  source: DataSource,
  plan: IsolatedPostgresPlan,
): Promise<readonly string[]> {
  const rows = await source.query(
    `SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_name IN ('identity_access_capabilities', 'identity_access_changes', 'identity_access_command_receipts') ORDER BY table_name`,
    [plan.schemaName],
  );
  if (!Array.isArray(rows)) throw new Error('Unexpected access-administration table query result.');

  return rows.map((row) => {
    if (typeof row !== 'object' || row === null || Array.isArray(row)) {
      throw new Error('Unexpected access-administration table row.');
    }
    const tableName = (row as Record<string, unknown>).table_name;
    if (typeof tableName !== 'string')
      throw new Error('Unexpected access-administration table name.');
    return tableName;
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
