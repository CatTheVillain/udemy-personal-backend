import { MigrationInterface, QueryRunner } from 'typeorm';

import { identityMigrationSchema, qualifiedIdentityTable } from './identity-migration-schema';

export class AddIdentityBootstrapRetentionIndex1760356800000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const schema = identityMigrationSchema(queryRunner);
    const table = qualifiedIdentityTable(schema, 'identity_sessions');
    await queryRunner.query(
      `CREATE INDEX idx_identity_session_pre_auth_expiry
       ON ${table} (absolute_expires_at, id)
       WHERE state = 'pre_auth'`,
    );
    await queryRunner.query(
      `CREATE INDEX idx_identity_session_revoked_pre_auth
       ON ${table} (revoked_at, id)
       WHERE state = 'revoked' AND user_id IS NULL`,
    );
  }

  public async down(): Promise<void> {
    throw new Error('Identity migrations are forward-only.');
  }
}
