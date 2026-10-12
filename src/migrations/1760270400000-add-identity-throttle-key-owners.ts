import { MigrationInterface, QueryRunner } from 'typeorm';

import { identityMigrationSchema, qualifiedIdentityTable } from './identity-migration-schema';

export class AddIdentityThrottleKeyOwners1760270400000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const schema = identityMigrationSchema(queryRunner);
    await addKeyOwner(
      queryRunner,
      qualifiedIdentityTable(schema, 'identity_registration_throttles'),
      'uq_identity_registration_throttle_key',
    );
    await addKeyOwner(
      queryRunner,
      qualifiedIdentityTable(schema, 'identity_login_throttles'),
      'uq_identity_login_throttle_key',
    );
  }

  public async down(): Promise<void> {
    throw new Error('Identity migrations are forward-only.');
  }
}

async function addKeyOwner(
  queryRunner: QueryRunner,
  table: string,
  constraintName: string,
): Promise<void> {
  const duplicates = await queryRunner.query(
    `SELECT key_hash FROM ${table} GROUP BY key_hash HAVING COUNT(*) > 1 LIMIT 1`,
  );
  if (Array.isArray(duplicates) && duplicates.length > 0) {
    throw new Error('Identity throttle migration found incompatible duplicate key ownership.');
  }
  await queryRunner.query(
    `ALTER TABLE ${table} ADD CONSTRAINT ${constraintName} UNIQUE (key_hash)`,
  );
}
