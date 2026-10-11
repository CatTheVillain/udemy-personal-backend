import { MigrationInterface, QueryRunner, Table } from 'typeorm';

import { identityMigrationSchema } from './identity-migration-schema';

export class InitialIdentityPersistence1760194800000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const schema = identityMigrationSchema(queryRunner);

    await queryRunner.createTable(
      new Table({
        name: 'identity_users',
        schema,
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true },
          { name: 'normalized_email', type: 'varchar', length: '254' },
          { name: 'password_hash', type: 'varchar', length: '255' },
          { name: 'created_at', type: 'timestamptz' },
          { name: 'updated_at', type: 'timestamptz' },
        ],
      }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'identity_sessions',
        schema,
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true },
          { name: 'user_id', type: 'uuid', isNullable: true },
          { name: 'token_hash', type: 'char', length: '64' },
          { name: 'csrf_token_hash', type: 'char', length: '64' },
          { name: 'state', type: 'varchar', length: '32' },
          { name: 'created_at', type: 'timestamptz' },
          { name: 'last_seen_at', type: 'timestamptz' },
          { name: 'absolute_expires_at', type: 'timestamptz' },
          { name: 'idle_expires_at', type: 'timestamptz' },
          { name: 'revoked_at', type: 'timestamptz', isNullable: true },
        ],
      }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'identity_registration_throttles',
        schema,
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true },
          { name: 'key_hash', type: 'char', length: '64' },
          { name: 'window_started_at', type: 'timestamptz' },
          { name: 'expires_at', type: 'timestamptz' },
          { name: 'attempt_count', type: 'integer' },
        ],
      }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'identity_login_throttles',
        schema,
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true },
          { name: 'key_hash', type: 'char', length: '64' },
          { name: 'window_started_at', type: 'timestamptz' },
          { name: 'expires_at', type: 'timestamptz' },
          { name: 'failure_count', type: 'integer' },
        ],
      }),
    );
  }

  public async down(): Promise<void> {
    throw new Error('Identity migrations are forward-only.');
  }
}
