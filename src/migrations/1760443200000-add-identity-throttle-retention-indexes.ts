import { MigrationInterface, QueryRunner } from 'typeorm';

import { identityMigrationSchema, qualifiedIdentityTable } from './identity-migration-schema';

export class AddIdentityThrottleRetentionIndexes1760443200000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const schema = identityMigrationSchema(queryRunner);
    await queryRunner.query(
      `CREATE INDEX idx_identity_registration_throttle_expiry
       ON ${qualifiedIdentityTable(schema, 'identity_registration_throttles')} (expires_at, id)`,
    );
    await queryRunner.query(
      `CREATE INDEX idx_identity_login_throttle_expiry
       ON ${qualifiedIdentityTable(schema, 'identity_login_throttles')} (expires_at, id)`,
    );
  }

  public async down(): Promise<void> {
    throw new Error('Identity migrations are forward-only.');
  }
}
